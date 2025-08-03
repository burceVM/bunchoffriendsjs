"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.optionalAuth = exports.moderatorOrAdmin = exports.adminOnly = exports.requireResourceAccess = exports.requirePermission = exports.allowRoles = exports.requireAuth = void 0;
const authorizationService_1 = require("../services/authorizationService");
const accessDenialLog_1 = __importDefault(require("../orm/accessDenialLog"));
/**
 * Enhanced middleware using centralized authorization service
 */
/**
 * Require authentication - redirects to home if not authenticated
 */
function requireAuth(req, res, next) {
    var _a, _b, _c, _d, _e;
    try {
        // Strict validation: session must exist and be properly structured
        if (!req.session || typeof req.session !== 'object') {
            throw new Error('Invalid session object');
        }
        // Strict validation: user must exist in session
        if (!req.session.user || typeof req.session.user !== 'object') {
            throw new Error('No valid user in session');
        }
        // Validate user properties
        const userId = req.session.user.id;
        const username = req.session.user.username;
        // Validate user ID range
        if (typeof userId !== 'number' || userId < 1 || userId > 2147483647) {
            throw new Error('Invalid session data');
        }
        // Validate username length and character range
        if (typeof username !== 'string' || username.length < 1 || username.length > 50) {
            throw new Error('Invalid session data');
        }
        // Validate username character range (alphanumeric, underscore, dash, dot)
        if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
            throw new Error('Invalid session data');
        }
        next();
    }
    catch (error) {
        // Simple logging without validation
        try {
            // Validate input data before logging
            const userId = (_b = (_a = req.session) === null || _a === void 0 ? void 0 : _a.user) === null || _b === void 0 ? void 0 : _b.id;
            const username = (_d = (_c = req.session) === null || _c === void 0 ? void 0 : _c.user) === null || _d === void 0 ? void 0 : _d.username;
            const path = req.originalUrl;
            const ip = req.ip || ((_e = req.socket) === null || _e === void 0 ? void 0 : _e.remoteAddress) || 'unknown';
            const message = error instanceof Error ? 'Authentication failed' : 'Authentication check failed';
            // Validate and sanitize path (remove control characters, limit length)
            const safePath = path && typeof path === 'string' ?
                path.replace(/[^\x20-\x7E]/g, '').substring(0, 2048) : '/';
            // Validate message length
            const truncatedMessage = message.length > 500 ? message.substring(0, 500) : message;
            const log = new accessDenialLog_1.default(userId || null, username || null, truncatedMessage, safePath, ip);
            log.create();
        }
        catch (validationError) {
            console.error('Failed to log access denial due to validation error:', validationError);
            // Create minimal log with safe defaults
            const log = new accessDenialLog_1.default(null, null, 'Authentication failed', '/error', 'unknown');
            log.create();
        }
        res.redirect(303, '/?auth=required');
        return;
    }
}
exports.requireAuth = requireAuth;
/**
 * Require specific roles - returns 403 if unauthorized
 */
function allowRoles(...allowedRoles) {
    return function (req, res, next) {
        var _a, _b, _c, _d, _e;
        try {
            // Validate allowed roles input
            if (!Array.isArray(allowedRoles) || allowedRoles.length === 0) {
                throw new Error('Invalid allowed roles: must be non-empty array');
            }
            // Validate each role string
            for (const role of allowedRoles) {
                if (typeof role !== 'string' || role.length < 1 || role.length > 20) {
                    throw new Error('Invalid role configuration');
                }
                // Validate role character range (letters and underscores only)
                if (!/^[a-zA-Z_]+$/.test(role)) {
                    throw new Error('Invalid role configuration');
                }
            }
            // Convert string roles to UserRole enum with strict validation
            const roles = allowedRoles.map(role => {
                const lowerRole = role.toLowerCase();
                switch (lowerRole) {
                    case 'admin':
                        return authorizationService_1.UserRole.ADMIN;
                    case 'moderator':
                        return authorizationService_1.UserRole.MODERATOR;
                    case 'normie':
                    case 'user': // Support legacy 'user' role
                        return authorizationService_1.UserRole.NORMIE;
                    default:
                        throw new Error('Access denied');
                }
            });
            authorizationService_1.AuthorizationService.requireRole(req, roles);
            next();
        }
        catch (error) {
            // Log access denial
            const log = new accessDenialLog_1.default(((_b = (_a = req.session) === null || _a === void 0 ? void 0 : _a.user) === null || _b === void 0 ? void 0 : _b.id) || null, ((_d = (_c = req.session) === null || _c === void 0 ? void 0 : _c.user) === null || _d === void 0 ? void 0 : _d.username) || null, `Role authorization failed: ${error instanceof Error ? error.message : String(error)}`, req.originalUrl, req.ip || ((_e = req.socket) === null || _e === void 0 ? void 0 : _e.remoteAddress) || 'unknown');
            log.create();
            res.status(403).render('error', Object.assign(Object.assign({}, req.session), { view: 'error', error: 'You do not have permission to access this page.' }));
            return;
        }
    };
}
exports.allowRoles = allowRoles;
/**
 * Require specific permission - returns 403 if unauthorized
 */
function requirePermission(permission) {
    return function (req, res, next) {
        var _a, _b, _c, _d, _e;
        try {
            // Validate permission input
            if (!permission || typeof permission !== 'string') {
                throw new Error('Access denied');
            }
            // Validate permission length and character range
            if (permission.length < 1 || permission.length > 50) {
                throw new Error('Access denied');
            }
            // Validate permission character range (lowercase letters and underscores only)
            if (!/^[a-z_]+$/.test(permission)) {
                throw new Error('Access denied');
            }
            authorizationService_1.AuthorizationService.requirePermission(req, permission);
            next();
        }
        catch (error) {
            // Log access denial
            const log = new accessDenialLog_1.default(((_b = (_a = req.session) === null || _a === void 0 ? void 0 : _a.user) === null || _b === void 0 ? void 0 : _b.id) || null, ((_d = (_c = req.session) === null || _c === void 0 ? void 0 : _c.user) === null || _d === void 0 ? void 0 : _d.username) || null, `Permission denied: ${permission}`, req.originalUrl, req.ip || ((_e = req.socket) === null || _e === void 0 ? void 0 : _e.remoteAddress) || 'unknown');
            log.create();
            res.status(403).render('error', Object.assign(Object.assign({}, req.session), { view: 'error', error: 'You do not have permission to access this page.' }));
            return;
        }
    };
}
exports.requirePermission = requirePermission;
/**
 * Require resource ownership or elevated permissions
 */
function requireResourceAccess(getResourceOwnerId) {
    return function (req, res, next) {
        var _a, _b, _c, _d, _e;
        try {
            // Validate callback function
            if (typeof getResourceOwnerId !== 'function') {
                throw new Error('System configuration error');
            }
            const resourceOwnerId = getResourceOwnerId(req);
            // Validate resource owner ID if provided
            if (resourceOwnerId !== undefined) {
                if (typeof resourceOwnerId !== 'number' || resourceOwnerId < 1) {
                    throw new Error('Access denied');
                }
            }
            if (!authorizationService_1.AuthorizationService.canAccessResource(req, resourceOwnerId)) {
                throw new Error('Access denied');
            }
            next();
        }
        catch (error) {
            // Validate input data before logging
            try {
                const userId = (_b = (_a = req.session) === null || _a === void 0 ? void 0 : _a.user) === null || _b === void 0 ? void 0 : _b.id;
                const username = (_d = (_c = req.session) === null || _c === void 0 ? void 0 : _c.user) === null || _d === void 0 ? void 0 : _d.username;
                const path = req.originalUrl;
                const ip = req.ip || ((_e = req.socket) === null || _e === void 0 ? void 0 : _e.remoteAddress) || 'unknown';
                const message = error instanceof Error ? 'Access denied' : 'Resource access check failed';
                // Validate and sanitize path (remove control characters, limit length)
                const safePath = path && typeof path === 'string' ?
                    path.replace(/[^\x20-\x7E]/g, '').substring(0, 2048) : '/';
                // Validate message length
                const truncatedMessage = message.length > 500 ? message.substring(0, 500) : message;
                const log = new accessDenialLog_1.default(userId || null, username || null, truncatedMessage, safePath, ip);
                log.create();
                res.status(403).render('error', Object.assign(Object.assign({}, req.session), { view: 'error', error: 'You do not have permission to access this page.' }));
                return;
            }
            catch (logError) {
                // If logging fails, still deny access
                console.error('Failed to log access denial:', logError);
                res.status(403).render('error', Object.assign(Object.assign({}, req.session), { view: 'error', error: 'You do not have permission to access this page.' }));
                return;
            }
        }
    };
}
exports.requireResourceAccess = requireResourceAccess;
/**
 * Admin only access
 */
function adminOnly(req, res, next) {
    var _a, _b, _c, _d, _e;
    try {
        authorizationService_1.AuthorizationService.requireRole(req, authorizationService_1.UserRole.ADMIN);
        next();
    }
    catch (error) {
        // Log access denial
        const log = new accessDenialLog_1.default(((_b = (_a = req.session) === null || _a === void 0 ? void 0 : _a.user) === null || _b === void 0 ? void 0 : _b.id) || null, ((_d = (_c = req.session) === null || _c === void 0 ? void 0 : _c.user) === null || _d === void 0 ? void 0 : _d.username) || null, 'Admin authorization failed', req.originalUrl, req.ip || ((_e = req.socket) === null || _e === void 0 ? void 0 : _e.remoteAddress) || 'unknown');
        log.create();
        res.status(403).render('error', Object.assign(Object.assign({}, req.session), { view: 'error', error: 'You do not have permission to access this page.' }));
        return;
    }
}
exports.adminOnly = adminOnly;
/**
 * Moderator or admin access
 */
function moderatorOrAdmin(req, res, next) {
    var _a, _b, _c, _d, _e;
    try {
        authorizationService_1.AuthorizationService.requireRole(req, [authorizationService_1.UserRole.MODERATOR, authorizationService_1.UserRole.ADMIN]);
        next();
    }
    catch (error) {
        // Log access denial
        const log = new accessDenialLog_1.default(((_b = (_a = req.session) === null || _a === void 0 ? void 0 : _a.user) === null || _b === void 0 ? void 0 : _b.id) || null, ((_d = (_c = req.session) === null || _c === void 0 ? void 0 : _c.user) === null || _d === void 0 ? void 0 : _d.username) || null, 'Moderator authorization failed', req.originalUrl, req.ip || ((_e = req.socket) === null || _e === void 0 ? void 0 : _e.remoteAddress) || 'unknown');
        log.create();
        res.status(403).render('error', Object.assign(Object.assign({}, req.session), { view: 'error', error: 'You do not have permission to access this page.' }));
        return;
    }
}
exports.moderatorOrAdmin = moderatorOrAdmin;
/**
 * Optional authentication - doesn't fail if not authenticated, but provides auth context
 */
function optionalAuth(req, _res, next) {
    try {
        // Validate session structure if it exists
        if (req.session && typeof req.session === 'object') {
            if (req.session.user && typeof req.session.user === 'object') {
                // Validate user data if present
                const userId = req.session.user.id;
                const username = req.session.user.username;
                // Validate user ID range
                if (typeof userId !== 'number' || userId < 1 || userId > 2147483647) {
                    throw new Error('Invalid session data');
                }
                // Validate username length and character range
                if (typeof username !== 'string' || username.length < 1 || username.length > 50) {
                    throw new Error('Invalid session data');
                }
                // Validate username character range (alphanumeric, underscore, dash, dot)
                if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
                    throw new Error('Invalid session data');
                }
            }
        }
        // Attach auth context to request for use in routes
        req.auth = authorizationService_1.AuthorizationService.authorize(req);
        next();
    }
    catch (error) {
        console.error('Optional auth error:', error);
        // Provide guest context on error with strict validation
        try {
            req.auth = {
                isAuthenticated: false,
                role: authorizationService_1.UserRole.GUEST,
                hasPermission: () => false,
                hasRole: () => false,
                canAccessResource: () => false
            };
        }
        catch (fallbackError) {
            console.error('Failed to create fallback auth context:', fallbackError);
            // If even fallback fails, create minimal safe context
            req.auth = {
                isAuthenticated: false,
                role: authorizationService_1.UserRole.GUEST,
                hasPermission: () => false,
                hasRole: () => false,
                canAccessResource: () => false
            };
        }
        next();
    }
}
exports.optionalAuth = optionalAuth;
//# sourceMappingURL=auth.js.map