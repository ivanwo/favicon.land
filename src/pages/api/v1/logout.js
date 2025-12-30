// logout.js
import { invalidateSession, deleteSessionCookie } from "../../../lib/auth";

export async function POST(context) {
    try {
        if (context.locals.session === null) {
            return new Response(null, {
                status: 401
            });
        }

        await invalidateSession(context.locals.session.id, context);
        deleteSessionCookie(context);

        return context.redirect("/", 302);
    } catch (error) {
        console.error(error);
        return new Response(null, {
            status: 500
        });
    }
}

// export async function GET(context) {
//     if (context.locals.session === null) {
//         return new Response(null, {
//             status: 401
//         });
//     }

//     await invalidateSession(context.locals.session.id, context);
//     deleteSessionCookie(context);

//     return new Response(null, {
//         status: 200
//     });
// }

