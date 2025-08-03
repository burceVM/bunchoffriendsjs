"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.allowRoles = exports.requireAuth = void 0;
function requireAuth(req, res, next) {
    try {
        // Fail securely: deny access if session is undefined, null, or malformed
        if (!req.session ||
            req.session === null ||
            typeof req.session !== 'object' ||
            !req.session.user ||
            req.session.user === null ||
            typeof req.session.user !== 'object') {
            res.redirect(303, '/');
            return;
        }
        // Additional validation: ensure user object has required properties
        if (!req.session.user.id ||
            !req.session.user.username ||
            typeof req.session.user.id !== 'number' ||
            typeof req.session.user.username !== 'string') {
            // Session appears corrupted or invalid, clear it and redirect
            req.session.user = undefined;
            res.redirect(303, '/');
            return;
        }
        next();
    }
    catch (error) {
        // Fail securely: any exception in authentication check denies access
        console.error('Authentication error:', error);
        res.redirect(303, '/');
        return;
    }
}
exports.requireAuth = requireAuth;
function allowRoles(...allowedRoles) {
    return function (req, res, next) {
        try {
            // Fail securely: deny access if no roles specified
            if (!allowedRoles || allowedRoles.length === 0) {
                res.status(403).send('Forbidden');
                return;
            }
            // Fail securely: comprehensive session and user validation
            if (!req.session ||
                req.session === null ||
                typeof req.session !== 'object' ||
                !req.session.user ||
                req.session.user === null ||
                typeof req.session.user !== 'object') {
                res.status(403).send('Forbidden');
                return;
            }
            // Fail securely: validate user role property exists and is valid
            if (!req.session.user.role ||
                typeof req.session.user.role !== 'string' ||
                req.session.user.role.trim() === '') {
                res.status(403).send('Forbidden');
                return;
            }
            // Normalize role comparison (trim whitespace, case insensitive)
            const userRole = req.session.user.role.trim().toLowerCase();
            const normalizedAllowedRoles = allowedRoles.map(role => typeof role === 'string' ? role.trim().toLowerCase() : '').filter(role => role !== '');
            // Fail securely: deny if no valid roles after normalization
            if (normalizedAllowedRoles.length === 0) {
                res.status(403).send('Forbidden');
                return;
            }
            // Check if user role is in allowed roles
            if (!normalizedAllowedRoles.includes(userRole)) {
                res.status(403).send('Forbidden');
                return;
            }
            next();
        }
        catch (error) {
            // Fail securely: any exception in role check denies access
            console.error('Role authorization error:', error);
            res.status(403).send('Forbidden');
            return;
        }
    };
}
exports.allowRoles = allowRoles;
//# sourceMappingURL=auth.js.map