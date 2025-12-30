// login.js
import { verifyPassword } from "../../../lib/utils";
import { generateSessionToken, createSession, setSessionCookie } from "../../../lib/auth";

export async function POST(context) {
    try {
        const data = await context.request.json();
        const { username, password } = data;

        // Validation
        if (!username || typeof username !== "string") {
            return new Response(
                JSON.stringify({ error: "Invalid username" }),
                { status: 400 }
            );
        }

        if (!password || typeof password !== "string" || password.length < 6 || password.length > 255) {
            return new Response(
                JSON.stringify({ error: "Invalid password" }),
                { status: 400 }
            );
        }

        const DB = context.locals.runtime.env.DB;

        // Get user
        const userResult = await DB.prepare(
            "SELECT id, username, hashed_password, locked, role FROM user WHERE username = ?"
        ).bind(username).run();

        if (userResult.results.length === 0) {
            return new Response(
                JSON.stringify({ error: "Incorrect username or password" }),
                { status: 401 }
            );
        }

        const user = userResult.results[0];

        // Check if account is locked
        if (user.locked) {
            return new Response(
                JSON.stringify({ error: "Account is locked. Please contact support." }),
                { status: 403 }
            );
        }

        // Verify password
        const validPassword = await verifyPassword(user.hashed_password, password);

        if (!validPassword) {
            return new Response(
                JSON.stringify({ error: "Incorrect username or password" }),
                { status: 401 }
            );
        }

        // Create session
        const sessionToken = generateSessionToken();
        const session = await createSession(sessionToken, user.id, context);
        setSessionCookie(context, sessionToken, session.expiresAt);

        return new Response(
            JSON.stringify({
                message: "Login successful",
                user: { id: user.id, username: user.username, role: user.role }
            }),
            { status: 200 }
        );
    } catch (error) {
        console.error("Login error:", error);
        return new Response(
            JSON.stringify({ error: "An error occurred during login" }),
            { status: 500 }
        );
    }
}
