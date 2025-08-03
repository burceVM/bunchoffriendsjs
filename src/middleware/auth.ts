import { Request, Response, NextFunction } from 'express';
import { AuthorizationService, UserRole, Permission, AuthResult } from '../services/authorizationService';

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
        AuthorizationService.requireAuth(req);
        next();
    } catch (error) {
        console.error('Authentication required:', error);
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
            console.error('Role authorization failed:', error);
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
            console.error('Permission authorization failed:', error);
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
                res.status(403).send('Forbidden');
                return;
            }
            
            next();
        } catch (error) {
            console.error('Resource access authorization failed:', error);
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
        console.error('Admin authorization failed:', error);
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
        console.error('Moderator authorization failed:', error);
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
