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
    var _a, _b, _c, _d, _e, _f;
    try {
        if (!req.session || !req.session.user) {
            // Log access denial
            const log = new accessDenialLog_1.default(null, null, 'No valid session/user', req.originalUrl, req.ip || ((_a = req.socket) === null || _a === void 0 ? void 0 : _a.remoteAddress) || 'unknown');
            log.create();
            res.redirect(303, '/');
            return;
        }
        next();
    }
    catch (error) {
        // Log access denial
        const log = new accessDenialLog_1.default(((_c = (_b = req.session) === null || _b === void 0 ? void 0 : _b.user) === null || _c === void 0 ? void 0 : _c.id) || null, ((_e = (_d = req.session) === null || _d === void 0 ? void 0 : _d.user) === null || _e === void 0 ? void 0 : _e.username) || null, 'Exception in authentication check', req.originalUrl, req.ip || ((_f = req.socket) === null || _f === void 0 ? void 0 : _f.remoteAddress) || 'unknown');
        log.create();
        res.redirect(303, '/');
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
            // Convert string roles to UserRole enum
            const roles = allowedRoles.map(role => {
                switch (role.toLowerCase()) {
                    case 'admin':
                        return authorizationService_1.UserRole.ADMIN;
                    case 'moderator':
                        return authorizationService_1.UserRole.MODERATOR;
                    case 'normie':
                    case 'user': // Support legacy 'user' role
                        return authorizationService_1.UserRole.NORMIE;
                    default:
                        return authorizationService_1.UserRole.NORMIE;
                }
            });
            authorizationService_1.AuthorizationService.requireRole(req, roles);
            next();
        }
        catch (error) {
            // Log access denial
            const log = new accessDenialLog_1.default(((_b = (_a = req.session) === null || _a === void 0 ? void 0 : _a.user) === null || _b === void 0 ? void 0 : _b.id) || null, ((_d = (_c = req.session) === null || _c === void 0 ? void 0 : _c.user) === null || _d === void 0 ? void 0 : _d.username) || null, `Role authorization failed: ${error instanceof Error ? error.message : String(error)}`, req.originalUrl, req.ip || ((_e = req.socket) === null || _e === void 0 ? void 0 : _e.remoteAddress) || 'unknown');
            log.create();
            res.status(403).send('Forbidden');
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
            authorizationService_1.AuthorizationService.requirePermission(req, permission);
            next();
        }
        catch (error) {
            // Log access denial
            const log = new accessDenialLog_1.default(((_b = (_a = req.session) === null || _a === void 0 ? void 0 : _a.user) === null || _b === void 0 ? void 0 : _b.id) || null, ((_d = (_c = req.session) === null || _c === void 0 ? void 0 : _c.user) === null || _d === void 0 ? void 0 : _d.username) || null, `Permission denied: ${permission}`, req.originalUrl, req.ip || ((_e = req.socket) === null || _e === void 0 ? void 0 : _e.remoteAddress) || 'unknown');
            log.create();
            res.status(403).send('Forbidden');
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
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k;
        try {
            const resourceOwnerId = getResourceOwnerId(req);
            if (!authorizationService_1.AuthorizationService.canAccessResource(req, resourceOwnerId)) {
                // Log access denial
                const log = new accessDenialLog_1.default(((_b = (_a = req.session) === null || _a === void 0 ? void 0 : _a.user) === null || _b === void 0 ? void 0 : _b.id) || null, ((_d = (_c = req.session) === null || _c === void 0 ? void 0 : _c.user) === null || _d === void 0 ? void 0 : _d.username) || null, 'Resource access denied', req.originalUrl, req.ip || ((_e = req.socket) === null || _e === void 0 ? void 0 : _e.remoteAddress) || 'unknown');
                log.create();
                res.status(403).send('Forbidden');
                return;
            }
            next();
        }
        catch (error) {
            // Log access denial
            const log = new accessDenialLog_1.default(((_g = (_f = req.session) === null || _f === void 0 ? void 0 : _f.user) === null || _g === void 0 ? void 0 : _g.id) || null, ((_j = (_h = req.session) === null || _h === void 0 ? void 0 : _h.user) === null || _j === void 0 ? void 0 : _j.username) || null, 'Exception in resource access check', req.originalUrl, req.ip || ((_k = req.socket) === null || _k === void 0 ? void 0 : _k.remoteAddress) || 'unknown');
            log.create();
            res.status(403).send('Forbidden');
            return;
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
        res.status(403).send('Forbidden');
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
        res.status(403).send('Forbidden');
        return;
    }
}
exports.moderatorOrAdmin = moderatorOrAdmin;
/**
 * Optional authentication - doesn't fail if not authenticated, but provides auth context
 */
function optionalAuth(req, _res, next) {
    try {
        // Attach auth context to request for use in routes
        req.auth = authorizationService_1.AuthorizationService.authorize(req);
        next();
    }
    catch (error) {
        console.error('Optional auth error:', error);
        // Provide guest context on error
        req.auth = {
            isAuthenticated: false,
            role: authorizationService_1.UserRole.GUEST,
            hasPermission: () => false,
            hasRole: () => false,
            canAccessResource: () => false
        };
        next();
    }
}
exports.optionalAuth = optionalAuth;
//# sourceMappingURL=auth.js.map