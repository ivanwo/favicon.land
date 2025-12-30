// logup.js
import { hashPassword } from "../../lib/utils";
import { generateSessionToken, createSession, setSessionCookie } from "../../lib/auth";
import { encodeBase32UpperCaseNoPadding } from "@oslojs/encoding";

export async function POST(context) {
    try {
        const data = await context.request.json();
        const { email, username, password, password2 } = data;

        // Validation
        if (!username || typeof username !== "string") {
            return new Response(
                JSON.stringify({ error: "Invalid username" }),
                { status: 400 }
            );
        }

        if (username.length < 3 || username.length > 16) {
            return new Response(
                JSON.stringify({ error: "Username must be 3-16 characters" }),
                { status: 400 }
            );
        }

        if (!/^[a-zA-Z0-9]+$/.test(username)) {
            return new Response(
                JSON.stringify({ error: "Username must be alphanumeric" }),
                { status: 400 }
            );
        }

        if (!email || typeof email !== "string" || email.length < 3 || email.length > 255) {
            return new Response(
                JSON.stringify({ error: "Invalid email" }),
                { status: 400 }
            );
        }

        if (!password || typeof password !== "string" || password.length < 6 || password.length > 255) {
            return new Response(
                JSON.stringify({ error: "Password must be 6-255 characters" }),
                { status: 400 }
            );
        }

        if (password !== password2) {
            return new Response(
                JSON.stringify({ error: "Passwords do not match" }),
                { status: 400 }
            );
        }

        const DB = context.locals.runtime.env.DB;

        // Check if email exists
        const emailCheck = await DB.prepare(
            "SELECT id FROM user WHERE email = ?"
        ).bind(email).run();

        if (emailCheck.results.length > 0) {
            return new Response(
                JSON.stringify({ error: "Email already in use" }),
                { status: 400 }
            );
        }

        // Check if username exists
        const usernameCheck = await DB.prepare(
            "SELECT id FROM user WHERE username = ?"
        ).bind(username).run();

        if (usernameCheck.results.length > 0) {
            return new Response(
                JSON.stringify({ error: "Username already taken" }),
                { status: 400 }
            );
        }

        // Generate user ID
        const userIdBytes = new Uint8Array(20);
        crypto.getRandomValues(userIdBytes);
        const userId = encodeBase32UpperCaseNoPadding(userIdBytes);

        // Hash password
        const hashedPassword = await hashPassword(password);

        // Create user
        await DB.prepare(
            "INSERT INTO user (id, email, username, hashed_password, display_name) VALUES (?, ?, ?, ?, ?)"
        ).bind(userId, email, username, hashedPassword, username).run();

        // Create session
        const sessionToken = generateSessionToken();
        const session = await createSession(sessionToken, userId, context);
        setSessionCookie(context, sessionToken, session.expiresAt);

        return new Response(
            JSON.stringify({
                message: "Account created successfully!",
                user: { id: userId, username, email }
            }),
            { status: 201 }
        );
    } catch (error) {
        console.error("Registration error:", error);
        return new Response(
            JSON.stringify({ error: "An error occurred during registration" }),
            { status: 500 }
        );
    }
}
