import { defineMiddleware } from "astro:middleware";
import {
    deleteSessionCookie,
    setSessionCookie,
    validateSessionToken,
} from "./lib/auth";

export const onRequest = defineMiddleware(async (context, next) => {
    const token = context.cookies.get("session")?.value ?? null;

    if (token === null) {
        context.locals.user = null;
        context.locals.session = null;
        return next();
    }

    const { session, user } = await validateSessionToken(token, context);

    if (session !== null && session !== undefined) {
        // Extend session by 15 days on valid access
        setSessionCookie(
            context,
            token,
            new Date().getTime() + 1000 * 60 * 60 * 24 * 15
        );
    } else {
        deleteSessionCookie(context);
    }

    context.locals.user = user;
    context.locals.session = session;
    return next();
});
