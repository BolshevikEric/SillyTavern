/**
 * User accounts are not part of this build: every session runs as the built-in single user,
 * so there is nothing to log in as and nothing to load from the server.
 */

/**
 * The current user profile. Always null, matching the behavior of a single-user deployment
 * where no account is ever loaded.
 * @type {{ handle: string, name: string, admin: boolean, enabled: boolean }|null}
 */
export let currentUser = null;

/**
 * Checks if the current user is an admin.
 * A single-user deployment always has full permissions.
 * @returns {boolean} Always true
 */
export function isAdmin() {
    return true;
}

/**
 * Gets the handle string of the current user.
 * @returns {string} User handle
 */
export function getCurrentUserHandle() {
    return 'default-user';
}
