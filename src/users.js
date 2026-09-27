// Native Node Modules
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import process from 'node:process';

// Express and other dependencies
import storage from 'node-persist';
import express from 'express';
import _ from 'lodash';
import { sync as writeFileAtomicSync } from 'write-file-atomic';

import { USER_DIRECTORY_TEMPLATE, DEFAULT_USER, PUBLIC_DIRECTORIES, UPLOADS_DIRECTORY } from './constants.js';
import { getConfigValue, color, delay, invalidateFirefoxCache, isPathUnderParent, setPermissionsSync } from './util.js';
import { readSecret, writeSecret } from './endpoints/secrets.js';
import { getContentOfType } from './endpoints/content-manager.js';
import { serverDirectory } from './server-directory.js';
import { extensionsEnabledFeatureGuard } from './endpoints/extensions.js';

export const KEY_PREFIX = 'user:';
const ANON_CSRF_SECRET = crypto.randomBytes(64).toString('base64');

/**
 * Cache for user directories.
 * @type {Map<string, UserDirectoryList>}
 */
const DIRECTORIES_CACHE = new Map();
const COOKIE_SECRET_PATH = 'cookie-secret.txt';

const STORAGE_KEYS = {
    csrfSecret: 'csrfSecret',
    /**
     * @deprecated Read from COOKIE_SECRET_PATH in DATA_ROOT instead.
     */
    cookieSecret: 'cookieSecret',
};

/**
 * @typedef {Object} User
 * @property {string} handle - The user's short handle. Used for directories and other references
 * @property {string} name - The user's name. Displayed in the UI
 * @property {number} created - The timestamp when the user was created
 * @property {string} password - Scrypt hash of the user's password
 * @property {string} salt - Salt used for hashing the password
 * @property {boolean} enabled - Whether the user is enabled
 * @property {boolean} admin - Whether the user is an admin (can manage other users)
 */

/**
 * @typedef {Object} UserViewModel
 * @property {string} handle - The user's short handle. Used for directories and other references
 * @property {string} name - The user's name. Displayed in the UI
 * @property {string} avatar - The user's avatar image
 * @property {boolean} [admin] - Whether the user is an admin (can manage other users)
 * @property {boolean} password - Whether the user is password protected
 * @property {boolean} [enabled] - Whether the user is enabled
 * @property {number} [created] - The timestamp when the user was created
 */

/**
 * @typedef {Object} UserDirectoryList
 * @property {string} root - The root directory for the user
 * @property {string} thumbnails - The directory where the thumbnails are stored
 * @property {string} thumbnailsBg - The directory where the background thumbnails are stored
 * @property {string} thumbnailsAvatar - The directory where the avatar thumbnails are stored
 * @property {string} thumbnailsPersona - The directory where the persona thumbnails are stored
 * @property {string} worlds - The directory where the WI are stored
 * @property {string} user - The directory where the user's public data is stored
 * @property {string} avatars - The directory where the avatars are stored
 * @property {string} userImages - The directory where the images are stored
 * @property {string} groups - The directory where the groups are stored
 * @property {string} groupChats - The directory where the group chats are stored
 * @property {string} chats - The directory where the chats are stored
 * @property {string} characters - The directory where the characters are stored
 * @property {string} backgrounds - The directory where the backgrounds are stored
 * @property {string} novelAI_Settings - The directory where the NovelAI settings are stored
 * @property {string} koboldAI_Settings - The directory where the KoboldAI settings are stored
 * @property {string} openAI_Settings - The directory where the OpenAI settings are stored
 * @property {string} textGen_Settings - The directory where the TextGen settings are stored
 * @property {string} themes - The directory where the themes are stored
 * @property {string} movingUI - The directory where the moving UI data is stored
 * @property {string} extensions - The directory where the extensions are stored
 * @property {string} instruct - The directory where the instruct templates is stored
 * @property {string} context - The directory where the context templates is stored
 * @property {string} quickreplies - The directory where the quick replies are stored
 * @property {string} assets - The directory where the assets are stored
 * @property {string} comfyWorkflows - The directory where the ComfyUI workflows are stored
 * @property {string} files - The directory where the uploaded files are stored
 * @property {string} vectors - The directory where the vectors are stored
 * @property {string} backups - The directory where the backups are stored
 * @property {string} sysprompt - The directory where the system prompt data is stored
 * @property {string} reasoning - The directory where the reasoning templates are stored
 */

/**
 * Ensures that the content directories exist.
 * @returns {Promise<import('./users.js').UserDirectoryList[]>} - The list of user directories
 */
export async function ensurePublicDirectoriesExist() {
    for (const dir of Object.values(PUBLIC_DIRECTORIES)) {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    }

    const userHandles = await getAllUserHandles();
    const directoriesList = userHandles.map(handle => getUserDirectories(handle));
    for (const userDirectories of directoriesList) {
        for (const dir of Object.values(userDirectories)) {
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
        }
    }
    return directoriesList;
}

/**
 * Verifies the security settings and prints warnings if necessary.
 *
 * There is no authentication in this build, so listening on a non-localhost address
 * without an IP whitelist exposes the data directory to everyone who can reach the port.
 * @returns {Promise<void>}
 */
export async function verifySecuritySettings() {
    const { listen, whitelistMode } = globalThis.COMMAND_LINE_ARGS;

    // Skip all security checks as listen is set to false
    if (!listen) {
        return;
    }

    if (whitelistMode) {
        return;
    }

    if (getConfigValue('securityOverride', false, 'boolean')) {
        console.warn(color.red('Security has been overridden. If it\'s not a trusted network, change the settings.'));
        return;
    }

    console.error(color.red('Your current SillyTavern configuration is insecure (listening to non-localhost). Enable whitelisting or set "securityOverride" in the config if you know what you are doing.'));
    process.exit(1);
}

export function cleanUploads() {
    try {
        const uploadsPath = path.join(globalThis.DATA_ROOT, UPLOADS_DIRECTORY);
        if (fs.existsSync(uploadsPath)) {
            const uploads = fs.readdirSync(uploadsPath);

            if (!uploads.length) {
                return;
            }

            console.debug(`Cleaning uploads folder (${uploads.length} files)`);
            uploads.forEach(file => {
                const pathToFile = path.join(uploadsPath, file);
                fs.unlinkSync(pathToFile);
            });
        }
    } catch (err) {
        console.error(err);
    }
}

/**
 * Gets a list of all user directories.
 * @returns {Promise<import('./users.js').UserDirectoryList[]>} - The list of user directories
 */
export async function getUserDirectoriesList() {
    const userHandles = await getAllUserHandles();
    const directoriesList = userHandles.map(handle => getUserDirectories(handle));
    return directoriesList;
}

/**
 * Perform migration from the old user data format to the new one.
 */
export async function migrateUserData() {
    const publicDirectory = path.join(process.cwd(), 'public');

    // No need to migrate if the characters directory doesn't exists
    if (!fs.existsSync(path.join(publicDirectory, 'characters'))) {
        return;
    }

    const TIMEOUT = 10;

    console.log();
    console.log(color.magenta('Preparing to migrate user data...'));
    console.log(`All public data will be moved to the ${globalThis.DATA_ROOT} directory.`);
    console.log('This process may take a while depending on the amount of data to move.');
    console.log(`Backups will be placed in the ${PUBLIC_DIRECTORIES.backups} directory.`);
    console.log(`The process will start in ${TIMEOUT} seconds. Press Ctrl+C to cancel.`);

    for (let i = TIMEOUT; i > 0; i--) {
        console.log(`${i}...`);
        await delay(1000);
    }

    console.log(color.magenta('Starting migration... Do not interrupt the process!'));

    const userDirectories = getUserDirectories(DEFAULT_USER.handle);

    const dataMigrationMap = [
        {
            old: path.join(publicDirectory, 'assets'),
            new: userDirectories.assets,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'backgrounds'),
            new: userDirectories.backgrounds,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'characters'),
            new: userDirectories.characters,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'chats'),
            new: userDirectories.chats,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'context'),
            new: userDirectories.context,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'group chats'),
            new: userDirectories.groupChats,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'groups'),
            new: userDirectories.groups,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'instruct'),
            new: userDirectories.instruct,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'KoboldAI Settings'),
            new: userDirectories.koboldAI_Settings,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'movingUI'),
            new: userDirectories.movingUI,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'NovelAI Settings'),
            new: userDirectories.novelAI_Settings,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'OpenAI Settings'),
            new: userDirectories.openAI_Settings,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'QuickReplies'),
            new: userDirectories.quickreplies,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'TextGen Settings'),
            new: userDirectories.textGen_Settings,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'themes'),
            new: userDirectories.themes,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'user'),
            new: userDirectories.user,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'User Avatars'),
            new: userDirectories.avatars,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'worlds'),
            new: userDirectories.worlds,
            file: false,
        },
        {
            old: path.join(publicDirectory, 'scripts/extensions/third-party'),
            new: userDirectories.extensions,
            file: false,
        },
        {
            old: path.join(process.cwd(), 'thumbnails'),
            new: userDirectories.thumbnails,
            file: false,
        },
        {
            old: path.join(process.cwd(), 'vectors'),
            new: userDirectories.vectors,
            file: false,
        },
        {
            old: path.join(process.cwd(), 'secrets.json'),
            new: path.join(userDirectories.root, 'secrets.json'),
            file: true,
        },
        {
            old: path.join(publicDirectory, 'settings.json'),
            new: path.join(userDirectories.root, 'settings.json'),
            file: true,
        },
        {
            old: path.join(publicDirectory, 'stats.json'),
            new: path.join(userDirectories.root, 'stats.json'),
            file: true,
        },
    ];

    const currentDate = new Date().toISOString().split('T')[0];
    const backupDirectory = path.join(process.cwd(), PUBLIC_DIRECTORIES.backups, '_migration', currentDate);

    if (!fs.existsSync(backupDirectory)) {
        fs.mkdirSync(backupDirectory, { recursive: true });
    }

    const errors = [];

    for (const migration of dataMigrationMap) {
        console.log(`Migrating ${migration.old} to ${migration.new}...`);

        try {
            if (!fs.existsSync(migration.old)) {
                console.log(color.yellow(`Skipping migration of ${migration.old} as it does not exist.`));
                continue;
            }

            if (migration.file) {
                // Copy the file to the new location
                fs.cpSync(migration.old, migration.new, { force: true });
                // Move the file to the backup location
                fs.cpSync(
                    migration.old,
                    path.join(backupDirectory, path.basename(migration.old)),
                    { recursive: true, force: true },
                );
                fs.rmSync(migration.old, { recursive: true, force: true });
            } else {
                // Copy the directory to the new location
                fs.cpSync(migration.old, migration.new, { recursive: true, force: true });
                // Move the directory to the backup location
                fs.cpSync(
                    migration.old,
                    path.join(backupDirectory, path.basename(migration.old)),
                    { recursive: true, force: true },
                );
                fs.rmSync(migration.old, { recursive: true, force: true });
            }
        } catch (error) {
            console.error(color.red(`Error migrating ${migration.old} to ${migration.new}:`), error.message);
            errors.push(migration.old);
        }
    }

    if (errors.length > 0) {
        console.log(color.red('Migration completed with errors. Move the following files manually:'));
        errors.forEach(error => console.error(error));
    }

    console.log(color.green('Migration completed!'));
}

export async function migrateSystemPrompts() {
    /**
     * Gets the default system prompts.
     * @returns {Promise<any[]>} - The list of default system prompts
     */
    async function getDefaultSystemPrompts() {
        try {
            return getContentOfType('sysprompt', 'json');
        } catch {
            return [];
        }
    }

    const directories = await getUserDirectoriesList();
    for (const directory of directories) {
        try {
            const migrateMarker = path.join(directory.sysprompt, '.migrated');
            if (fs.existsSync(migrateMarker)) {
                continue;
            }
            const backupsPath = path.join(directory.backups, '_sysprompt');
            fs.mkdirSync(backupsPath, { recursive: true });
            const defaultPrompts = await getDefaultSystemPrompts();
            const instucts = fs.readdirSync(directory.instruct);
            let migratedPrompts = [];
            for (const instruct of instucts) {
                const instructPath = path.join(directory.instruct, instruct);
                const sysPromptPath = path.join(directory.sysprompt, instruct);
                if (path.extname(instruct) === '.json' && !fs.existsSync(sysPromptPath)) {
                    const instructData = JSON.parse(fs.readFileSync(instructPath, 'utf8'));
                    if ('system_prompt' in instructData && 'name' in instructData) {
                        const backupPath = path.join(backupsPath, `${instructData.name}.json`);
                        fs.cpSync(instructPath, backupPath, { force: true });
                        const syspromptData = { name: instructData.name, content: instructData.system_prompt };
                        migratedPrompts.push(syspromptData);
                        delete instructData.system_prompt;
                        writeFileAtomicSync(instructPath, JSON.stringify(instructData, null, 4));
                    }
                }
            }
            // Only leave unique contents
            migratedPrompts = _.uniqBy(migratedPrompts, 'content');
            // Only leave contents that are not in the default prompts
            migratedPrompts = migratedPrompts.filter(x => !defaultPrompts.some(y => y.content === x.content));
            for (const sysPromptData of migratedPrompts) {
                sysPromptData.name = `[Migrated] ${sysPromptData.name}`;
                const syspromptPath = path.join(directory.sysprompt, `${sysPromptData.name}.json`);
                writeFileAtomicSync(syspromptPath, JSON.stringify(sysPromptData, null, 4));
                console.log(`Migrated system prompt ${sysPromptData.name} for ${directory.root.split(path.sep).pop()}`);
            }
            writeFileAtomicSync(migrateMarker, '');
        } catch (error) {
            console.error('Error migrating system prompts:', error);
        }
    }
}

export async function migratePublicOverrides() {
    const migrationMap = [
        {
            oldPath: path.join(serverDirectory, 'public', 'error', 'forbidden-by-whitelist.html'),
            newPath: path.join(globalThis.DATA_ROOT, '_errors', 'forbidden-by-whitelist.html'),
        },
        {
            oldPath: path.join(serverDirectory, 'public', 'error', 'host-not-allowed.html'),
            newPath: path.join(globalThis.DATA_ROOT, '_errors', 'host-not-allowed.html'),
        },
        {
            oldPath: path.join(serverDirectory, 'public', 'error', 'unauthorized.html'),
            newPath: path.join(globalThis.DATA_ROOT, '_errors', 'unauthorized.html'),
        },
        {
            oldPath: path.join(serverDirectory, 'public', 'error', 'url-not-found.html'),
            newPath: path.join(globalThis.DATA_ROOT, '_errors', 'url-not-found.html'),
        },
        {
            oldPath: path.join(serverDirectory, 'public', 'css', 'user.css'),
            newPath: path.join(globalThis.DATA_ROOT, '_css', 'user.css'),
        },
    ];

    for (const { oldPath, newPath } of migrationMap) {
        try {
            if (fs.existsSync(newPath)) {
                continue;
            }
            if (fs.existsSync(oldPath)) {
                fs.mkdirSync(path.dirname(newPath), { recursive: true });
                fs.cpSync(oldPath, newPath, { force: true });
                fs.unlinkSync(oldPath);
                setPermissionsSync(newPath);
                console.log(`Migrated ${path.basename(oldPath)} to data root.`);
            }
        } catch (error) {
            console.error(`Error migrating ${oldPath} to ${newPath}:`, error);
        }
    }
}

/**
 * Converts a user handle to a storage key.
 * @param {string} handle User handle
 * @returns {string} The key for the user storage
 */
export function toKey(handle) {
    return `${KEY_PREFIX}${handle}`;
}

/**
 * Initializes the user storage.
 * @param {string} dataRoot The root directory for user data
 * @returns {Promise<void>}
 */
export async function initUserStorage(dataRoot) {
    console.log('Using data root:', color.green(dataRoot));
    await storage.init({
        dir: path.join(dataRoot, '_storage'),
        ttl: false, // Never expire
        expiredInterval: 0,
    });

    const keys = await getAllUserHandles();

    // If there are no users, create the default user
    if (keys.length === 0) {
        await storage.setItem(toKey(DEFAULT_USER.handle), DEFAULT_USER);
    }
}

/**
 * Get the cookie secret from the config. If it doesn't exist, generate a new one.
 * @param {string} dataRoot The root directory for user data
 * @returns {string} The cookie secret
 */
export function getCookieSecret(dataRoot) {
    const cookieSecretPath = path.join(dataRoot, COOKIE_SECRET_PATH);

    if (fs.existsSync(cookieSecretPath)) {
        const stat = fs.statSync(cookieSecretPath);
        if (stat.size > 0) {
            return fs.readFileSync(cookieSecretPath, 'utf8');
        }
    }

    const oldSecret = getConfigValue(STORAGE_KEYS.cookieSecret);
    if (oldSecret) {
        console.log('Migrating cookie secret from config.yaml...');
        writeFileAtomicSync(cookieSecretPath, oldSecret, { encoding: 'utf8' });
        return oldSecret;
    }

    console.warn(color.yellow('Cookie secret is missing from data root. Generating a new one...'));
    const secret = crypto.randomBytes(64).toString('base64');
    writeFileAtomicSync(cookieSecretPath, secret, { encoding: 'utf8' });
    return secret;
}

/**
 * Get the session name for the current server.
 * @returns {string} The session name
 */
export function getCookieSessionName() {
    // Get server hostname and hash it to generate a session suffix
    const hostname = os.hostname() || 'localhost';
    const suffix = crypto.createHash('sha256').update(hostname).digest('hex').slice(0, 8);
    return `session-${suffix}`;
}

export function getSessionCookieAge() {
    // Defaults to "no expiration" if not set
    const configValue = getConfigValue('sessionTimeout', -1, 'number');

    // Convert to milliseconds
    if (configValue > 0) {
        return configValue * 1000;
    }

    // "No expiration" is just 400 days as per RFC 6265
    if (configValue < 0) {
        return 400 * 24 * 60 * 60 * 1000;
    }

    // 0 means session cookie is deleted when the browser session ends
    // (depends on the implementation of the browser)
    return undefined;
}

/**
 * Get the CSRF secret from the storage.
 * @param {import('express').Request} [request] HTTP request object
 * @returns {string} The CSRF secret
 */
export function getCsrfSecret(request) {
    if (!request || !request.user) {
        return ANON_CSRF_SECRET;
    }

    let csrfSecret = readSecret(request.user.directories, STORAGE_KEYS.csrfSecret);

    if (!csrfSecret) {
        csrfSecret = crypto.randomBytes(64).toString('base64');
        writeSecret(request.user.directories, STORAGE_KEYS.csrfSecret, csrfSecret);
    }

    return csrfSecret;
}

/**
 * Gets a list of all user handles.
 * @returns {Promise<string[]>} - The list of user handles
 */
export async function getAllUserHandles() {
    const keys = await storage.keys(x => x.key.startsWith(KEY_PREFIX));
    const handles = keys.map(x => x.replace(KEY_PREFIX, ''));
    return handles;
}

/**
 * Gets the directories listing for the provided user.
 * @param {string} handle User handle
 * @returns {UserDirectoryList} User directories
 */
export function getUserDirectories(handle) {
    if (DIRECTORIES_CACHE.has(handle)) {
        const cache = DIRECTORIES_CACHE.get(handle);
        if (cache) {
            return cache;
        }
    }

    const directories = structuredClone(USER_DIRECTORY_TEMPLATE);
    for (const key in directories) {
        directories[key] = path.join(globalThis.DATA_ROOT, handle, USER_DIRECTORY_TEMPLATE[key]);
    }
    DIRECTORIES_CACHE.set(handle, directories);
    return directories;
}

/**
 * Middleware to add user data to the request object.
 * Every request is served as the built-in single user.
 * @param {import('express').Request} request Request object
 * @param {import('express').Response} response Response object
 * @param {import('express').NextFunction} next Next function
 */
export async function setUserDataMiddleware(request, response, next) {
    const handle = DEFAULT_USER.handle;
    request.user = {
        profile: DEFAULT_USER,
        directories: getUserDirectories(handle),
    };

    return next();
}

/**
 * Creates a route handler for serving files from a specific directory.
 * @param {(req: import('express').Request) => string} directoryFn A function that returns the directory path to serve files from
 * @returns {import('express').RequestHandler}
 */
function createRouteHandler(directoryFn) {
    return async (req, res) => {
        try {
            const directory = directoryFn(req);
            const filePath = decodeURIComponent(req.params[0]);
            const fullPath = path.join(directory, filePath);
            if (!isPathUnderParent(directory, path.resolve(fullPath))) {
                return res.sendStatus(403);
            }
            const exists = fs.existsSync(fullPath);
            if (!exists) {
                return res.sendStatus(404);
            }

            invalidateFirefoxCache(filePath, req, res);
            return res.sendFile(filePath, { root: directory });
        } catch (error) {
            return res.sendStatus(500);
        }
    };
}

/**
 * Creates a route handler for serving extensions.
 * @param {(req: import('express').Request) => string} directoryFn A function that returns the directory path to serve files from
 * @returns {import('express').RequestHandler}
 */
function createExtensionsRouteHandler(directoryFn) {
    return async (req, res) => {
        try {
            const directory = directoryFn(req);
            const filePath = decodeURIComponent(req.params[0]);
            const localPath = path.join(directory, filePath);
            if (!isPathUnderParent(directory, path.resolve(localPath))) {
                return res.sendStatus(403);
            }
            const existsLocal = fs.existsSync(localPath);
            if (existsLocal) {
                return res.sendFile(filePath, { root: directory });
            }

            const globalPath = path.join(PUBLIC_DIRECTORIES.globalExtensions, filePath);
            if (!isPathUnderParent(PUBLIC_DIRECTORIES.globalExtensions, path.resolve(globalPath))) {
                return res.sendStatus(403);
            }
            const existsGlobal = fs.existsSync(globalPath);
            if (existsGlobal) {
                return res.sendFile(filePath, { root: PUBLIC_DIRECTORIES.globalExtensions });
            }

            return res.sendStatus(404);
        } catch (error) {
            return res.sendStatus(500);
        }
    };
}

/**
 * Express router for serving files from the user's directories.
 */
export const router = express.Router();
router.use('/backgrounds/*', createRouteHandler(req => req.user.directories.backgrounds));
router.use('/characters/*', createRouteHandler(req => req.user.directories.characters));
router.use('/User%20Avatars/*', createRouteHandler(req => req.user.directories.avatars));
router.use('/assets/*', createRouteHandler(req => req.user.directories.assets));
router.use('/user/images/*', createRouteHandler(req => req.user.directories.userImages));
router.use('/user/files/*', createRouteHandler(req => req.user.directories.files));
router.use('/scripts/extensions/third-party/*', extensionsEnabledFeatureGuard, createExtensionsRouteHandler(req => req.user.directories.extensions));
