import { Request, Response, NextFunction } from 'express';
import { AuthorizationService, UserRole, Permission, AuthResult } from '../services/authorizationService';
import AccessDenialLog from '../orm/accessDenialLog';

/**
 * Extended Request interface to include auth context
 */
export interface AuthenticatedRequest extends Request {
    auth: AuthResult;
}

/**
 * Enhanced middleware using centralized authorization service
 */

/**
 * Require authentication - redirects to home if not authenticated
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
    try {
        if (!req.session || !req.session.user) {
            // Log access denial
            const log = new AccessDenialLog(
                null,
                null,
                'No valid session/user',
                req.originalUrl,
                req.ip || req.socket?.remoteAddress || 'unknown'
            );
            log.create();
            res.redirect(303, '/');
            return;
        }
        next();
    } catch (error) {
        // Log access denial
        const log = new AccessDenialLog(
            req.session?.user?.id || null,
            req.session?.user?.username || null,
            'Exception in authentication check',
            req.originalUrl,
            req.ip || req.socket?.remoteAddress || 'unknown'
        );
        log.create();
        res.redirect(303, '/');
        return;
    }
}

/**
 * Require specific roles - returns 403 if unauthorized
 */
export function allowRoles(...allowedRoles: string[]): (req: Request, res: Response, next: NextFunction) => void {
    return function (req: Request, res: Response, next: NextFunction): void {
        try {
            // Convert string roles to UserRole enum
            const roles = allowedRoles.map(role => {
                switch (role.toLowerCase()) {
                case 'admin':
                    return UserRole.ADMIN;
                case 'moderator':
                    return UserRole.MODERATOR;
                case 'normie':
                case 'user': // Support legacy 'user' role
                    return UserRole.NORMIE;
                default:
                    return UserRole.NORMIE;
                }
            });

            AuthorizationService.requireRole(req, roles);
            next();
        } catch (error) {
            // Log access denial
            const log = new AccessDenialLog(
                req.session?.user?.id || null,
                req.session?.user?.username || null,
                `Role authorization failed: ${error instanceof Error ? error.message : String(error)}`,
                req.originalUrl,
                req.ip || req.socket?.remoteAddress || 'unknown'
            );
            log.create();
            res.status(403).send('Forbidden');
            return;
        }
    };
}

/**
 * Require specific permission - returns 403 if unauthorized
 */
export function requirePermission(permission: Permission): (req: Request, res: Response, next: NextFunction) => void {
    return function (req: Request, res: Response, next: NextFunction): void {
        try {
            AuthorizationService.requirePermission(req, permission);
            next();
        } catch (error) {
            // Log access denial
            const log = new AccessDenialLog(
                req.session?.user?.id || null,
                req.session?.user?.username || null,
                `Permission denied: ${permission}`,
                req.originalUrl,
                req.ip || req.socket?.remoteAddress || 'unknown'
            );
            log.create();
            res.status(403).send('Forbidden');
            return;
        }
    };
}

/**
 * Require resource ownership or elevated permissions
 */
export function requireResourceAccess(getResourceOwnerId: (req: Request) => number | undefined): (req: Request, res: Response, next: NextFunction) => void {
    return function (req: Request, res: Response, next: NextFunction): void {
        try {
            const resourceOwnerId = getResourceOwnerId(req);
            if (!AuthorizationService.canAccessResource(req, resourceOwnerId)) {
                // Log access denial
                const log = new AccessDenialLog(
                    req.session?.user?.id || null,
                    req.session?.user?.username || null,
                    'Resource access denied',
                    req.originalUrl,
                    req.ip || req.socket?.remoteAddress || 'unknown'
                );
                log.create();
                res.status(403).send('Forbidden');
                return;
            }
            next();
        } catch (error) {
            // Log access denial
            const log = new AccessDenialLog(
                req.session?.user?.id || null,
                req.session?.user?.username || null,
                'Exception in resource access check',
                req.originalUrl,
                req.ip || req.socket?.remoteAddress || 'unknown'
            );
            log.create();
            res.status(403).send('Forbidden');
            return;
        }
    };
}

/**
 * Admin only access
 */
export function adminOnly(req: Request, res: Response, next: NextFunction): void {
    try {
        AuthorizationService.requireRole(req, UserRole.ADMIN);
        next();
    } catch (error) {
        // Log access denial
        const log = new AccessDenialLog(
            req.session?.user?.id || null,
            req.session?.user?.username || null,
            'Admin authorization failed',
            req.originalUrl,
            req.ip || req.socket?.remoteAddress || 'unknown'
        );
        log.create();
        res.status(403).send('Forbidden');
        return;
    }
}

/**
 * Moderator or admin access
 */
export function moderatorOrAdmin(req: Request, res: Response, next: NextFunction): void {
    try {
        AuthorizationService.requireRole(req, [UserRole.MODERATOR, UserRole.ADMIN]);
        next();
    } catch (error) {
        // Log access denial
        const log = new AccessDenialLog(
            req.session?.user?.id || null,
            req.session?.user?.username || null,
            'Moderator authorization failed',
            req.originalUrl,
            req.ip || req.socket?.remoteAddress || 'unknown'
        );
        log.create();
        res.status(403).send('Forbidden');
        return;
    }
}

/**
 * Optional authentication - doesn't fail if not authenticated, but provides auth context
 */
export function optionalAuth(req: Request, _res: Response, next: NextFunction): void {
    try {
        // Attach auth context to request for use in routes
        (req as AuthenticatedRequest).auth = AuthorizationService.authorize(req);
        next();
    } catch (error) {
        console.error('Optional auth error:', error);
        // Provide guest context on error
        (req as AuthenticatedRequest).auth = {
            isAuthenticated: false,
            role: UserRole.GUEST,
            hasPermission: () => false,
            hasRole: () => false,
            canAccessResource: () => false
        };
        next();
    }
}
