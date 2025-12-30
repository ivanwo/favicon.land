/**
 * Hash a password using PBKDF2 with SHA-256
 * @param {string} password - The password to hash
 * @param {Uint8Array} [providedSalt] - Optional salt (generates random if not provided)
 * @returns {Promise<string>} The hashed password in format "hexsalt:hexhash"
 */
export async function hashPassword(password, providedSalt) {
    const encoder = new TextEncoder();
    const salt = providedSalt || crypto.getRandomValues(new Uint8Array(16));

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    const exportedKey = await crypto.subtle.exportKey("raw", key);
    const hashHex = Array.from(new Uint8Array(exportedKey))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    const saltHex = Array.from(salt)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

    return `${saltHex}:${hashHex}`;
}

/**
 * Verify a password against a stored hash
 * @param {string} storedHash - The stored hash in format "hexsalt:hexhash"
 * @param {string} passwordAttempt - The password attempt to verify
 * @returns {Promise<boolean>} True if password matches
 */
export async function verifyPassword(storedHash, passwordAttempt) {
    const [saltHex, originalHash] = storedHash.split(":");
    const salt = new Uint8Array(
        saltHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
    );
    const attemptHashWithSalt = await hashPassword(passwordAttempt, salt);
    const [, attemptHash] = attemptHashWithSalt.split(":");
    return attemptHash === originalHash;
}
