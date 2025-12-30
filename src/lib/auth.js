import { encodeBase32LowerCaseNoPadding, encodeHexLowerCase } from "@oslojs/encoding";
import { sha256 } from "@oslojs/crypto/sha2";

/**
 * Generate a random session token
 * @returns {string} A 32-character base32 encoded token
 */
export function generateSessionToken() {
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    return encodeBase32LowerCaseNoPadding(bytes);
}

/**
 * Create a new session for a user
 * @param {string} token - The session token
 * @param {string} userId - The user's ID
 * @param {object} context - The request context
 * @returns {Promise<object>} The created session object
 */
export async function createSession(token, userId, context) {
    const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
    const expiresAt = Date.now() + 1000 * 60 * 60 * 24 * 15; // 15 days

    const session = {
        id: sessionId,
        userId,
        expiresAt,
    };

    const DB = context.locals.runtime.env.DB;
    await DB.prepare(
        "INSERT INTO session (id, user_id, expires_at) VALUES (?, ?, ?)"
    )
        .bind(session.id, session.userId, Math.floor(session.expiresAt / 1000))
        .run();

    return session;
}

/**
 * Validate a session token
 * @param {string} token - The session token to validate
 * @param {object} context - The request context
 * @returns {Promise<{session: object|null, user: object|null}>}
 */
export async function validateSessionToken(token, context) {
    const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
    const DB = context.locals.runtime.env.DB;

    const result = await DB.prepare(
        "SELECT * FROM session WHERE id = ?"
    )
        .bind(sessionId)
        .run();

    if (result.results.length === 0) {
        return { session: null, user: null };
    }

    const session = result.results[0];
    const currentTime = Math.floor(Date.now() / 1000);

    if (currentTime >= session.expires_at) {
        await DB.prepare("DELETE FROM session WHERE id = ?").bind(sessionId).run();
        return { session: null, user: null };
    }

    const userResult = await DB.prepare(
        "SELECT id, display_name, email, username, locked, role FROM user WHERE id = ?"
    )
        .bind(session.user_id)
        .run();

    if (userResult.results.length === 0) {
        return { session: null, user: null };
    }

    return { session, user: userResult.results[0] };
}

/**
 * Invalidate a session
 * @param {string} sessionId - The session ID to invalidate
 * @param {object} context - The request context
 */
export async function invalidateSession(sessionId, context) {
    const DB = context.locals.runtime.env.DB;
    await DB.prepare("DELETE FROM session WHERE id = ?").bind(sessionId).run();
}

/**
 * Set a session cookie
 * @param {object} context - The request context
 * @param {string} token - The session token
 * @param {number} expiresAt - Expiration timestamp
 */
export function setSessionCookie(context, token, expiresAt) {
    context.cookies.set("session", token, {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        expires: new Date(expiresAt),
        secure: import.meta.env.PROD,
    });
}

/**
 * Delete the session cookie
 * @param {object} context - The request context
 */
export function deleteSessionCookie(context) {
    context.cookies.set("session", "", {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: import.meta.env.PROD,
        maxAge: 0,
    });
}
