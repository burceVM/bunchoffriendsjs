"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.optionalAuth = exports.moderatorOrAdmin = exports.adminOnly = exports.requireResourceAccess = exports.requirePermission = exports.allowRoles = exports.requireAuth = void 0;
const authorizationService_1 = require("../services/authorizationService");
/**
 * Enhanced middleware using centralized authorization service
 */
/**
 * Require authentication - redirects to home if not authenticated
 */
function requireAuth(req, res, next) {
    try {
        authorizationService_1.AuthorizationService.requireAuth(req);
        next();
    }
    catch (error) {
        console.error('Authentication required:', error);
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
            console.error('Role authorization failed:', error);
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
        try {
            authorizationService_1.AuthorizationService.requirePermission(req, permission);
            next();
        }
        catch (error) {
            console.error('Permission authorization failed:', error);
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
        try {
            const resourceOwnerId = getResourceOwnerId(req);
            if (!authorizationService_1.AuthorizationService.canAccessResource(req, resourceOwnerId)) {
                res.status(403).send('Forbidden');
                return;
            }
            next();
        }
        catch (error) {
            console.error('Resource access authorization failed:', error);
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
    try {
        authorizationService_1.AuthorizationService.requireRole(req, authorizationService_1.UserRole.ADMIN);
        next();
    }
    catch (error) {
        console.error('Admin authorization failed:', error);
        res.status(403).send('Forbidden');
        return;
    }
}
exports.adminOnly = adminOnly;
/**
 * Moderator or admin access
 */
function moderatorOrAdmin(req, res, next) {
    try {
        authorizationService_1.AuthorizationService.requireRole(req, [authorizationService_1.UserRole.MODERATOR, authorizationService_1.UserRole.ADMIN]);
        next();
    }
    catch (error) {
        console.error('Moderator authorization failed:', error);
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