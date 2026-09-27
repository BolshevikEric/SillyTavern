import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { promisify } from 'node:util';

import mime from 'mime-types';
import { init as initModuleLexer, parse as parseModule } from 'es-module-lexer';

const brotliCompress = promisify(zlib.brotliCompress);

/** Extensions that are worth compressing (already-compressed formats like woff2/png are skipped). */
const COMPRESSIBLE_EXTENSIONS = new Set(['.js', '.mjs', '.css', '.html', '.json', '.svg', '.txt', '.xml', '.map', '.md']);

/** Files smaller than this are not worth the compression overhead. */
const MIN_COMPRESS_BYTES = 1024;

/**
 * Brotli quality for the background warmup. Quality 11 is worth its CPU cost because it is paid
 * once per process, off the request path, and it is ~10% smaller than quality 9.
 */
const WARMUP_BROTLI_QUALITY = 11;

/** Brotli quality for on-demand compression: ~26x faster than quality 11 for ~10% more bytes. */
const ON_DEMAND_BROTLI_QUALITY = 9;

/** Upper bound for the in-memory representation cache. */
const MAX_CACHE_BYTES = 64 * 1024 * 1024;

/** Fingerprinted URLs never change content, so they can be cached forever. */
const CACHE_CONTROL_IMMUTABLE = 'public, max-age=31536000, immutable';

/** Unversioned URLs (fonts, images, urls built at runtime) are revalidated in the background. */
const CACHE_CONTROL_DEFAULT = 'public, max-age=86400, stale-while-revalidate=604800';

/** Bodies that do not match the requested version must not be cached under that URL. */
const CACHE_CONTROL_NO_CACHE = 'no-cache';

/** HTML must always be revalidated: it carries the current asset version. */
const CACHE_CONTROL_HTML = 'no-cache, must-revalidate';

/** Extensions that may contain ES module imports and therefore need versioning. */
const MODULE_EXTENSIONS = new Set(['.js', '.mjs']);

/**
 * @typedef {object} AssetEntry
 * @property {number} mtimeMs Source modification time, used to invalidate the cache.
 * @property {number} size Source size, used to invalidate the cache.
 * @property {number} quality Brotli quality the representation was built with.
 * @property {string} contentType Response content type.
 * @property {Buffer} body Uncompressed (and, for modules, versioned) bytes.
 * @property {string} etag Entity tag for the identity representation.
 * @property {Buffer|null} br Brotli representation, if the file is worth compressing.
 * @property {string|null} brEtag Entity tag for the brotli representation.
 */

/** @type {Map<string, AssetEntry>} Absolute file path -> cached representation. */
const entries = new Map();

/** @type {Map<string, Promise<AssetEntry|null>>} In-flight builds, to avoid duplicate work. */
const pendingEntries = new Map();

let cacheBytes = 0;
let assetVersion = 'dev';
let lexerReady = null;

/**
 * Sets the version that is appended to module specifiers and asset URLs.
 * @param {string} version Version string (usually the short git revision).
 */
export function setAssetVersion(version) {
    assetVersion = String(version || 'dev');
}

/**
 * Gets the current asset version.
 * @returns {string} Version string.
 */
export function getAssetVersion() {
    return assetVersion;
}

/**
 * Collects the files that take part in versioning: everything under the given roots that can be
 * requested by a browser.
 * @param {string} root Directory to walk.
 * @param {Set<string>} extensions File extensions to collect.
 * @returns {string[]} Absolute file paths.
 */
export function collectAssetFiles(root, extensions = COMPRESSIBLE_EXTENSIONS) {
    const collected = [];
    const walk = directory => {
        let dirents;
        try {
            dirents = fs.readdirSync(directory, { withFileTypes: true });
        } catch {
            return;
        }
        for (const dirent of dirents) {
            const fullPath = path.join(directory, dirent.name);
            if (dirent.isDirectory()) {
                walk(fullPath);
            } else if (dirent.isFile() && extensions.has(path.extname(fullPath).toLowerCase())) {
                collected.push(fullPath);
            }
        }
    };
    walk(path.resolve(root));
    return collected;
}

/**
 * Computes the asset version from the content of every file a browser can request.
 * Content hashing (instead of the git revision) means an edit to any asset — including a patch
 * applied directly on the server without a commit — invalidates the cached URLs, while a deploy
 * that does not touch the frontend keeps the existing caches valid.
 * @param {object} param Parameters
 * @param {string[]} [param.roots] Directories to include.
 * @param {string[]} [param.extraFiles] Additional files to include.
 * @returns {string} Short version string.
 */
export function computeAssetVersion({ roots = [], extraFiles = [] } = {}) {
    const files = [...extraFiles];
    for (const root of roots) {
        files.push(...collectAssetFiles(root));
    }

    const hash = crypto.createHash('sha256');
    for (const file of [...new Set(files)].sort()) {
        try {
            const stat = fs.statSync(file);
            if (!stat.isFile()) {
                continue;
            }
            hash.update(`${file}\0${stat.size}\0`);
            hash.update(fs.readFileSync(file));
        } catch {
            // Unreadable files simply do not contribute to the version.
        }
    }

    return hash.digest('hex').slice(0, 12);
}

/**
 * Appends the asset version to relative asset references (scripts and stylesheets) in an HTML document.
 * @param {string} html HTML source.
 * @param {string} [version] Version to append, defaults to the current asset version.
 * @returns {string} HTML with versioned asset references.
 */
export function fingerprintHtml(html, version = assetVersion) {
    return html.replace(/(\s(?:src|href)=")([^"]+\.(?:js|mjs|css))(")/gi, (match, prefix, url, suffix) => {
        if (/^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(url) || url.startsWith('data:')) {
            return match;
        }
        return `${prefix}${url}?v=${version}${suffix}`;
    });
}

/**
 * Parses an Accept-Encoding header and reports whether brotli can be used.
 * @param {string|undefined} header Accept-Encoding header value.
 * @returns {boolean} Whether brotli is acceptable.
 */
function acceptsBrotli(header) {
    if (typeof header !== 'string' || header.length === 0) {
        return false;
    }
    for (const part of header.split(',')) {
        const [name, ...params] = part.trim().split(';');
        if (name.trim().toLowerCase() !== 'br') {
            continue;
        }
        const quality = params.map(p => p.trim()).find(p => p.startsWith('q='));
        if (quality && Number.parseFloat(quality.slice(2)) === 0) {
            return false;
        }
        return true;
    }
    return false;
}

/**
 * Resolves a request path to a file inside the served root, or to one of the virtual assets.
 * @param {string} root Resolved root directory.
 * @param {string} requestPath Decoded request path.
 * @param {Map<string, string>} virtualFiles Map of request paths to absolute file paths.
 * @returns {string|null} Absolute file path, or null when the request is not a static asset.
 */
function resolveRequestPath(root, requestPath, virtualFiles) {
    const virtual = virtualFiles.get(requestPath);
    if (virtual) {
        return virtual;
    }

    const resolved = path.resolve(root, `.${path.posix.normalize(requestPath)}`);
    if (resolved !== root && !resolved.startsWith(root + path.sep)) {
        return null;
    }
    return resolved;
}

/**
 * Creates a strong entity tag for a response body.
 * @param {Buffer} body Response body.
 * @param {string} [prefix] Representation prefix, so encodings get distinct tags.
 * @returns {string} Entity tag.
 */
function makeEtag(body, prefix = '') {
    const digest = crypto.createHash('sha1').update(body).digest('base64url');
    return `"${prefix}${digest}"`;
}

/**
 * Rewrites relative module specifiers so that they carry the current asset version.
 * Only specifiers that resolve to an existing file are touched, which keeps strings that
 * merely look like paths intact.
 *
 * Versioning is required for correctness as well: the same file reached through a versioned and
 * an unversioned URL would be instantiated twice by the browser, duplicating its module state.
 *
 * @param {string} source Module source.
 * @param {string} filePath Absolute path of the module.
 * @param {string} root Root directory that is served as static assets.
 * @param {Map<string, string>} virtualFiles Map of request paths to absolute file paths.
 * @returns {{source: string, rewritten: number}} Rewritten source and the number of specifiers changed.
 */
function rewriteModuleSpecifiers(source, filePath, root, virtualFiles) {
    const [imports] = parseModule(source);
    if (imports.length === 0) {
        return { source, rewritten: 0 };
    }

    const dir = path.dirname(filePath);
    let result = '';
    let cursor = 0;
    let rewritten = 0;

    for (const imported of imports) {
        let start = imported.s;
        let end = imported.e;

        // Dynamic imports report the whole expression; only plain string literals can be versioned.
        if (imported.d >= 0) {
            const quote = source[start];
            if ((quote !== '\'' && quote !== '"') || source[end - 1] !== quote) {
                continue;
            }
            start += 1;
            end -= 1;
        }

        const specifier = source.slice(start, end);
        if (specifier.includes('?v=') || specifier.length === 0) {
            continue;
        }

        let target;
        if (specifier.startsWith('/')) {
            // Root-relative specifiers are resolved against the served root, like the browser does.
            target = virtualFiles.get(specifier) ?? path.resolve(root, `.${path.posix.normalize(specifier)}`);
        } else if (specifier.startsWith('./') || specifier.startsWith('../')) {
            target = path.resolve(dir, specifier);
        } else {
            // Bare specifiers are resolved by the browser through an import map, if any.
            continue;
        }

        if (!fs.existsSync(target)) {
            continue;
        }

        result += source.slice(cursor, end) + `?v=${assetVersion}`;
        cursor = end;
        rewritten++;
    }

    if (rewritten === 0) {
        return { source, rewritten: 0 };
    }

    return { source: result + source.slice(cursor), rewritten };
}

/**
 * Drops cached representations until the cache fits into its budget.
 */
function trimCache() {
    while (cacheBytes > MAX_CACHE_BYTES) {
        const oldest = entries.keys().next();
        if (oldest.done) {
            break;
        }
        const entry = entries.get(oldest.value);
        cacheBytes -= entry.body.length + (entry.br?.length ?? 0);
        entries.delete(oldest.value);
    }
}

/**
 * Builds (or returns a cached) representation of a static asset.
 * @param {string} filePath Absolute file path.
 * @param {object} options Options
 * @param {string} options.root Root directory that is served as static assets.
 * @param {boolean} options.fingerprint Whether module specifiers should be versioned.
 * @param {boolean} options.brotli Whether a brotli representation should be built.
 * @param {number} options.quality Brotli quality to use.
 * @param {Map<string, string>} options.virtualFiles Map of request paths to absolute file paths.
 * @returns {Promise<AssetEntry|null>} The cached representation, or null if the file is not servable.
 */
async function buildEntry(filePath, { root, fingerprint, brotli, quality, virtualFiles }) {
    let stat;
    try {
        stat = await fs.promises.stat(filePath);
    } catch {
        return null;
    }
    if (!stat.isFile()) {
        return null;
    }

    const cached = entries.get(filePath);
    const isUpToDate = cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size;
    if (isUpToDate && cached.quality >= quality) {
        // Refresh the recency of the entry in the insertion-ordered map.
        entries.delete(filePath);
        entries.set(filePath, cached);
        return cached;
    }

    const extension = path.extname(filePath).toLowerCase();
    let body = await fs.promises.readFile(filePath);

    if (fingerprint && MODULE_EXTENSIONS.has(extension)) {
        await ensureModuleLexer();
        const rewritten = rewriteModuleSpecifiers(body.toString('utf8'), filePath, root, virtualFiles);
        if (rewritten.rewritten > 0) {
            body = Buffer.from(rewritten.source);
        }
    } else if (fingerprint && extension === '.html') {
        body = Buffer.from(fingerprintHtml(body.toString('utf8')));
    }

    let compressed = null;
    if (brotli && COMPRESSIBLE_EXTENSIONS.has(extension) && body.length >= MIN_COMPRESS_BYTES) {
        compressed = await brotliCompress(body, {
            params: {
                [zlib.constants.BROTLI_PARAM_QUALITY]: quality,
                [zlib.constants.BROTLI_PARAM_SIZE_HINT]: body.length,
            },
        });
    }

    /** @type {AssetEntry} */
    const entry = {
        mtimeMs: stat.mtimeMs,
        size: stat.size,
        quality,
        contentType: mime.lookup(filePath) || 'application/octet-stream',
        body,
        etag: makeEtag(body),
        br: compressed,
        brEtag: compressed ? makeEtag(compressed, 'br-') : null,
    };

    const previous = entries.get(filePath);
    if (previous) {
        cacheBytes -= previous.body.length + (previous.br?.length ?? 0);
    }
    entries.set(filePath, entry);
    cacheBytes += entry.body.length + (entry.br?.length ?? 0);
    trimCache();

    return entry;
}

/**
 * Waits for the module lexer to be ready.
 * @returns {Promise<void>} Resolves when the lexer can be used.
 */
async function ensureModuleLexer() {
    if (!lexerReady) {
        lexerReady = Promise.resolve(initModuleLexer);
    }
    await lexerReady;
}

/**
 * Returns the cached representation of an asset, building it on demand.
 * @param {string} filePath Absolute file path.
 * @param {object} options Build options.
 * @returns {Promise<AssetEntry|null>} The representation, or null when it cannot be built.
 */
function getEntry(filePath, options) {
    const inflight = pendingEntries.get(filePath);
    if (inflight) {
        return inflight;
    }

    const promise = buildEntry(filePath, options).finally(() => pendingEntries.delete(filePath));
    pendingEntries.set(filePath, promise);
    return promise;
}

/**
 * Sends a response body with the appropriate validators, honouring conditional requests.
 * @param {import('express').Request} request Express request.
 * @param {import('express').Response} response Express response.
 * @param {Buffer} body Response body.
 * @param {AssetEntry} entry Asset entry.
 * @param {string|null} encoding Content encoding of the body, or null for identity.
 */
function sendBody(request, response, body, entry, encoding) {
    response.setHeader('Content-Type', entry.contentType);
    response.setHeader('ETag', encoding === 'br' ? entry.brEtag : entry.etag);
    response.setHeader('Last-Modified', new Date(entry.mtimeMs).toUTCString());
    if (encoding) {
        response.setHeader('Content-Encoding', encoding);
    }

    if (request.fresh) {
        response.removeHeader('Content-Type');
        response.removeHeader('Content-Encoding');
        response.removeHeader('Content-Length');
        response.status(304).end();
        return;
    }

    response.setHeader('Content-Length', String(body.length));

    if (request.method === 'HEAD') {
        response.end();
        return;
    }

    response.write(body);
    response.end();
}

/**
 * Express middleware that serves static assets with brotli compression, immutable caching for
 * versioned URLs and versioned ES module specifiers.
 * @param {object} options Options
 * @param {string} options.root Directory that is served as static assets.
 * @param {Map<string, string>} [options.virtualFiles] Map of request paths to absolute file paths served by other middlewares.
 * @param {boolean} [options.fingerprint] Whether module specifiers should be versioned.
 * @param {boolean} [options.brotli] Whether brotli representations should be served.
 * @returns {import('express').RequestHandler} Middleware function.
 */
export function getAssetOptimizerMiddleware({ root, virtualFiles = new Map(), fingerprint = true, brotli = true }) {
    const resolvedRoot = path.resolve(root);

    return async function assetOptimizerMiddleware(request, response, next) {
        try {
            if (request.method !== 'GET' && request.method !== 'HEAD') {
                return next();
            }

            if (request.headers.range) {
                // Ranged requests are rare for compressible assets; let express.static deal with them.
                return next();
            }

            let requestPath;
            try {
                requestPath = decodeURIComponent(request.path);
            } catch {
                return next();
            }

            const filePath = resolveRequestPath(resolvedRoot, requestPath, virtualFiles);
            if (!filePath) {
                return next();
            }

            const extension = path.extname(filePath).toLowerCase();
            const isModule = MODULE_EXTENSIONS.has(extension);
            const requestedVersion = typeof request.query?.v === 'string' && request.query.v.length > 0 ? request.query.v : null;

            // Every representation varies by encoding, and the brotli one may be served for any of them.
            response.setHeader('Vary', 'Accept-Encoding');

            const entry = await getEntry(filePath, { root: resolvedRoot, fingerprint, brotli, quality: ON_DEMAND_BROTLI_QUALITY, virtualFiles });
            if (!entry) {
                // Not a servable file: let express.static respond with the usual 404.
                return next();
            }

            // A module body carries versioned import specifiers, so it may only ever be served under
            // the URL of the version it was built for. Requests for another version - including
            // unversioned ones, such as the entry points of user-installed extensions - are resolved
            // to the current version instead. Serving the file as-is would either embed a stale
            // version in a long-lived cached body or give the browser two URLs for one file, which
            // makes it instantiate the module twice and breaks circular imports.
            if (fingerprint && isModule && requestedVersion !== assetVersion) {
                response.setHeader('Cache-Control', 'no-store');
                return response.redirect(302, `${request.path}?v=${encodeURIComponent(assetVersion)}`);
            }

            const isStaleVersion = requestedVersion !== null && requestedVersion !== assetVersion;

            if (extension === '.html') {
                response.setHeader('Cache-Control', CACHE_CONTROL_HTML);
            } else if (requestedVersion !== null && !isStaleVersion) {
                response.setHeader('Cache-Control', CACHE_CONTROL_IMMUTABLE);
            } else if (isStaleVersion) {
                // Do not let a client cache the current body under a version it does not belong to.
                response.setHeader('Cache-Control', CACHE_CONTROL_NO_CACHE);
            } else {
                response.setHeader('Cache-Control', CACHE_CONTROL_DEFAULT);
            }

            if (brotli && entry.br && acceptsBrotli(request.headers['accept-encoding'])) {
                return sendBody(request, response, entry.br, entry, 'br');
            }

            // Modules have to be served from here even without brotli: their body carries the
            // versioned specifiers, and serving the original file would break the module graph.
            if (isModule) {
                return sendBody(request, response, entry.body, entry, null);
            }

            return next();
        } catch (error) {
            console.error('[Assets] Failed to serve static asset:', error.message);
            return next();
        }
    };
}

/**
 * Pre-compresses static assets in the background so that the first visitor does not pay for it.
 * @param {object} options Options
 * @param {string} options.root Directory that is served as static assets.
 * @param {Map<string, string>} [options.virtualFiles] Map of request paths to absolute file paths served by other middlewares.
 * @param {boolean} [options.fingerprint] Whether module specifiers should be versioned.
 * @param {boolean} [options.brotli] Whether brotli representations should be built.
 * @returns {Promise<{files: number, bytes: number}>} Warmup statistics.
 */
export async function warmupAssets({ root, virtualFiles = new Map(), fingerprint = true, brotli = true }) {
    const resolvedRoot = path.resolve(root);
    const targets = [...virtualFiles.values()];

    const walk = directory => {
        for (const dirent of fs.readdirSync(directory, { withFileTypes: true })) {
            const fullPath = path.join(directory, dirent.name);
            if (dirent.isDirectory()) {
                walk(fullPath);
            } else if (dirent.isFile() && COMPRESSIBLE_EXTENSIONS.has(path.extname(fullPath).toLowerCase())) {
                targets.push(fullPath);
            }
        }
    };

    try {
        walk(resolvedRoot);
    } catch (error) {
        console.error('[Assets] Failed to enumerate static assets:', error.message);
        return { files: 0, bytes: 0 };
    }

    const startedAt = Date.now();
    let files = 0;
    let bytes = 0;

    for (const filePath of targets) {
        try {
            const stat = await fs.promises.stat(filePath);
            if (!stat.isFile() || stat.size < MIN_COMPRESS_BYTES) {
                continue;
            }
            const entry = await getEntry(filePath, { root: resolvedRoot, fingerprint, brotli, quality: WARMUP_BROTLI_QUALITY, virtualFiles });
            if (entry) {
                files++;
                bytes += entry.br?.length ?? entry.body.length;
            }
        } catch {
            // A file may disappear while the warmup runs; skip it.
        }
        // Yield to the event loop between files to keep request handling responsive.
        await new Promise(resolve => setImmediate(resolve));
    }

    const elapsed = Date.now() - startedAt;
    console.log(`Asset cache warmed up: ${files} files, ${(bytes / 1024 / 1024).toFixed(2)} MB in ${elapsed} ms`);

    return { files, bytes };
}
