"use strict";
/*
 * WARNING!
 *
 * This project is intentionally insecure.
 *
 * DO NOT use in production.
 *
 * It is designed for educational purposes - to teach common vulnerabilities in web applications.
 */
Object.defineProperty(exports, "__esModule", { value: true });
// Create middlware for an insecure session manager
const insecureSession = () => {
    // Session identifiers are just numbers that increment
    let sessionId = 1;
    // A session store with typed session data
    const sessions = {};
    return (req, res, next) => {
        var _a;
        try {
            // Initialize session to empty object as fail-safe default
            req.session = {};
            // Validate cookie exists and is a valid session ID
            const sessionCookie = (_a = req.cookies) === null || _a === void 0 ? void 0 : _a.session;
            // Fail securely: only proceed if cookie is a valid number and exists in sessions
            if (sessionCookie &&
                !isNaN(Number(sessionCookie)) &&
                Number.isInteger(Number(sessionCookie)) &&
                Number(sessionCookie) > 0 &&
                Number(sessionCookie) in sessions &&
                sessions[Number(sessionCookie)] &&
                typeof sessions[Number(sessionCookie)] === 'object') {
                // Validate session data integrity
                const sessionData = sessions[Number(sessionCookie)];
                // Fail securely: ensure session data is not corrupted
                if (sessionData.user) {
                    // Validate user object structure if it exists
                    if (typeof sessionData.user === 'object' &&
                        sessionData.user !== null &&
                        typeof sessionData.user.id === 'number' &&
                        typeof sessionData.user.username === 'string' &&
                        sessionData.user.username.length > 0) {
                        req.session = sessionData;
                    }
                    else {
                        // Session data corrupted, clear it
                        delete sessions[Number(sessionCookie)];
                        req.session = {};
                    }
                }
                else {
                    // Session exists but no user data (valid empty session)
                    req.session = sessionData;
                }
            }
            else {
                // Invalid or non-existent session: create new secure session
                const id = sessionId++;
                res.cookie('session', id, {
                    httpOnly: true,
                    secure: false,
                    sameSite: 'strict' // CSRF protection
                });
                sessions[id] = {};
                req.session = sessions[id];
            }
            next();
        }
        catch (error) {
            // Fail securely: any error in session handling creates empty session
            console.error('Session handling error:', error);
            req.session = {};
            next();
        }
    };
};
exports.default = insecureSession;
//# sourceMappingURL=sessions.js.map