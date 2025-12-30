// logout.js
import { invalidateSession, deleteSessionCookie } from "../../lib/auth";

export async function POST(context) {
    if (context.locals.session === null) {
        return new Response(null, {
            status: 401
        });
    }

    await invalidateSession(context.locals.session.id, context);
    deleteSessionCookie(context);

    return new Response(null, {
        status: 200
    });
}
