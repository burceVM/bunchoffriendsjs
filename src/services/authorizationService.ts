/*
 * Centralized Authorization Service
 * Single source of truth for all access control decisions across the application
 */

import { Request } from 'express';
import User from '../orm/user';

/**
 * User roles in order of privilege (lowest to highest)
 */
export enum UserRole {
    GUEST = 'guest',
    NORMIE = 'normie',
    MODERATOR = 'moderator',
    ADMIN = 'admin'
}

/**
 * System permissions that can be granted to users
 */
export enum Permission {
    // Basic user permissions
    VIEW_OWN_PROFILE = 'view_own_profile',
    EDIT_OWN_PROFILE = 'edit_own_profile',
    VIEW_OWN_POSTS = 'view_own_posts',
    CREATE_POST = 'create_post',
    EDIT_OWN_POST = 'edit_own_post',
    DELETE_OWN_POST = 'delete_own_post',
    
    // Friend system permissions
    VIEW_FRIEND_POSTS = 'view_friend_posts',
    ADD_FRIEND = 'add_friend',
    REMOVE_FRIEND = 'remove_friend',
    VIEW_FRIEND_LIST = 'view_friend_list',
    
    // Interaction permissions
    LIKE_POST = 'like_post',
    UNLIKE_POST = 'unlike_post',
    
    // Security permissions
    CHANGE_PASSWORD = 'change_password',
    VIEW_LOGIN_HISTORY = 'view_login_history',
    
    // Moderator permissions
    VIEW_ALL_POSTS = 'view_all_posts',
    DELETE_ANY_POST = 'delete_any_post',
    VIEW_USER_LIST = 'view_user_list',
    
    // Admin permissions
    ADMIN_PANEL = 'admin_panel',
    EXECUTE_SQL = 'execute_sql',
    VIEW_ALL_USERS = 'view_all_users',
    MANAGE_USERS = 'manage_users',
    VIEW_SYSTEM_LOGS = 'view_system_logs',
    MANAGE_SECURITY = 'manage_security'
}

/**
 * Role-based permission mapping
 * Defined after Permission enum to avoid usage before declaration
 */
function createRolePermissions(): Record<UserRole, Permission[]> {
    return {
        [UserRole.GUEST]: [],
        
        [UserRole.NORMIE]: [
            Permission.VIEW_OWN_PROFILE,
            Permission.EDIT_OWN_PROFILE,
            Permission.VIEW_OWN_POSTS,
            Permission.CREATE_POST,
            Permission.EDIT_OWN_POST,
            Permission.DELETE_OWN_POST,
            Permission.VIEW_FRIEND_POSTS,
            Permission.ADD_FRIEND,
            Permission.REMOVE_FRIEND,
            Permission.VIEW_FRIEND_LIST,
            Permission.LIKE_POST,
            Permission.UNLIKE_POST,
            Permission.CHANGE_PASSWORD,
            Permission.VIEW_LOGIN_HISTORY
        ],
        
        [UserRole.MODERATOR]: [
            // Inherit all normie permissions
            Permission.VIEW_OWN_PROFILE,
            Permission.EDIT_OWN_PROFILE,
            Permission.VIEW_OWN_POSTS,
            Permission.CREATE_POST,
            Permission.EDIT_OWN_POST,
            Permission.DELETE_OWN_POST,
            Permission.VIEW_FRIEND_POSTS,
            Permission.ADD_FRIEND,
            Permission.REMOVE_FRIEND,
            Permission.VIEW_FRIEND_LIST,
            Permission.LIKE_POST,
            Permission.UNLIKE_POST,
            Permission.CHANGE_PASSWORD,
            Permission.VIEW_LOGIN_HISTORY,
            // Add moderator-specific permissions
            Permission.VIEW_ALL_POSTS,
            Permission.DELETE_ANY_POST,
            Permission.VIEW_USER_LIST
        ],
        
        [UserRole.ADMIN]: [
            // Inherit all moderator permissions
            Permission.VIEW_OWN_PROFILE,
            Permission.EDIT_OWN_PROFILE,
            Permission.VIEW_OWN_POSTS,
            Permission.CREATE_POST,
            Permission.EDIT_OWN_POST,
            Permission.DELETE_OWN_POST,
            Permission.VIEW_FRIEND_POSTS,
            Permission.ADD_FRIEND,
            Permission.REMOVE_FRIEND,
            Permission.VIEW_FRIEND_LIST,
            Permission.LIKE_POST,
            Permission.UNLIKE_POST,
            Permission.CHANGE_PASSWORD,
            Permission.VIEW_LOGIN_HISTORY,
            Permission.VIEW_ALL_POSTS,
            Permission.DELETE_ANY_POST,
            Permission.VIEW_USER_LIST,
            // Add admin-specific permissions
            Permission.ADMIN_PANEL,
            Permission.EXECUTE_SQL,
            Permission.VIEW_ALL_USERS,
            Permission.MANAGE_USERS,
            Permission.VIEW_SYSTEM_LOGS,
            Permission.MANAGE_SECURITY
        ]
    };
}

const ROLE_PERMISSIONS = createRolePermissions();

/**
 * Authentication and authorization result
 */
export interface AuthResult {
    isAuthenticated: boolean;
    user?: User;
    role: UserRole;
    hasPermission: (permission: Permission) => boolean;
    hasRole: (role: UserRole | UserRole[]) => boolean;
    canAccessResource: (resourceOwnerId?: number) => boolean;
}

/**
 * Centralized Authorization Service
 * Provides a single interface for all authentication and authorization decisions
 */
export class AuthorizationService {
    
    /**
     * Main authorization method - returns comprehensive auth information
     */
    static authorize(req: Request): AuthResult {
        try {
            // Check if user is authenticated
            const authCheck = this.isAuthenticated(req);
            
            if (!authCheck.isAuthenticated || !authCheck.user) {
                return this.createGuestAuthResult();
            }

            const user = authCheck.user;
            const role = this.getUserRole(user);
            const permissions = this.getRolePermissions(role);

            return {
                isAuthenticated: true,
                user,
                role,
                hasPermission: (permission: Permission) => permissions.includes(permission),
                hasRole: (roleOrRoles: UserRole | UserRole[]) => {
                    const rolesToCheck = Array.isArray(roleOrRoles) ? roleOrRoles : [roleOrRoles];
                    return rolesToCheck.includes(role);
                },
                canAccessResource: (resourceOwnerId?: number) => {
                    // User can always access their own resources
                    if (resourceOwnerId && user.id === resourceOwnerId) {
                        return true;
                    }
                    // Admins and moderators can access any resource
                    if (role === UserRole.ADMIN || role === UserRole.MODERATOR) {
                        return true;
                    }
                    // For other cases, check specific permissions
                    return false;
                }
            };

        } catch (error) {
            console.error('Authorization error:', error);
            return this.createGuestAuthResult();
        }
    }

    /**
     * Quick authentication check
     */
    static isAuthenticated(req: Request): { isAuthenticated: boolean; user?: User } {
        try {
            // Comprehensive session validation
            if (!req.session || 
                req.session === null || 
                typeof req.session !== 'object' || 
                !req.session.user || 
                req.session.user === null ||
                typeof req.session.user !== 'object') {
                return { isAuthenticated: false };
            }

            const user = req.session.user;

            // Validate user object structure
            if (!user.id || 
                !user.username || 
                typeof user.id !== 'number' ||
                typeof user.username !== 'string' ||
                user.username.trim() === '') {
                return { isAuthenticated: false };
            }

            return { isAuthenticated: true, user };

        } catch (error) {
            console.error('Authentication check error:', error);
            return { isAuthenticated: false };
        }
    }

    /**
     * Check if user has specific permission
     */
    static hasPermission(req: Request, permission: Permission): boolean {
        const auth = this.authorize(req);
        return auth.hasPermission(permission);
    }

    /**
     * Check if user has specific role(s)
     */
    static hasRole(req: Request, roleOrRoles: UserRole | UserRole[]): boolean {
        const auth = this.authorize(req);
        return auth.hasRole(roleOrRoles);
    }

    /**
     * Check if user can access a specific resource
     */
    static canAccessResource(req: Request, resourceOwnerId?: number): boolean {
        const auth = this.authorize(req);
        return auth.canAccessResource(resourceOwnerId);
    }

    /**
     * Check if user is admin
     */
    static isAdmin(req: Request): boolean {
        return this.hasRole(req, UserRole.ADMIN);
    }

    /**
     * Check if user is moderator or admin
     */
    static isModerator(req: Request): boolean {
        return this.hasRole(req, [UserRole.MODERATOR, UserRole.ADMIN]);
    }

    /**
     * Require authentication - throws error if not authenticated
     */
    static requireAuth(req: Request): User {
        const auth = this.isAuthenticated(req);
        if (!auth.isAuthenticated || !auth.user) {
            throw new Error('Authentication required');
        }
        return auth.user;
    }

    /**
     * Require specific permission - throws error if not authorized
     */
    static requirePermission(req: Request, permission: Permission): User {
        const user = this.requireAuth(req);
        if (!this.hasPermission(req, permission)) {
            throw new Error(`Permission required: ${permission}`);
        }
        return user;
    }

    /**
     * Require specific role - throws error if not authorized
     */
    static requireRole(req: Request, roleOrRoles: UserRole | UserRole[]): User {
        const user = this.requireAuth(req);
        if (!this.hasRole(req, roleOrRoles)) {
            const roles = Array.isArray(roleOrRoles) ? roleOrRoles.join(', ') : roleOrRoles;
            throw new Error(`Role required: ${roles}`);
        }
        return user;
    }

    /**
     * Get user role from user object
     */
    private static getUserRole(user: User): UserRole {
        if (!user.role || typeof user.role !== 'string') {
            return UserRole.NORMIE; // Default role
        }

        const role = user.role.trim().toLowerCase();
        
        // Map string roles to enum values
        switch (role) {
        case 'admin':
            return UserRole.ADMIN;
        case 'moderator':
            return UserRole.MODERATOR;
        case 'normie':
        case 'user': // Support legacy 'user' role
            return UserRole.NORMIE;
        default:
            return UserRole.NORMIE; // Default role for unknown roles
        }
    }

    /**
     * Get permissions for a role
     */
    private static getRolePermissions(role: UserRole): Permission[] {
        return ROLE_PERMISSIONS[role] || [];
    }

    /**
     * Create a guest (unauthenticated) auth result
     */
    private static createGuestAuthResult(): AuthResult {
        return {
            isAuthenticated: false,
            role: UserRole.GUEST,
            hasPermission: () => false,
            hasRole: () => false,
            canAccessResource: () => false
        };
    }

    /**
     * Get all permissions for a user (for debugging/admin purposes)
     */
    static getUserPermissions(req: Request): Permission[] {
        const auth = this.authorize(req);
        return this.getRolePermissions(auth.role);
    }

    /**
     * Check if a role has higher privilege than another
     */
    static hasHigherPrivilege(role1: UserRole, role2: UserRole): boolean {
        const roleOrder = [UserRole.GUEST, UserRole.NORMIE, UserRole.MODERATOR, UserRole.ADMIN];
        return roleOrder.indexOf(role1) > roleOrder.indexOf(role2);
    }

    /**
     * Validate that a user can perform an action on another user
     * (e.g., admin can manage any user, moderator can manage users but not admins)
     */
    static canManageUser(req: Request, targetUser: User): boolean {
        const auth = this.authorize(req);
        
        if (!auth.isAuthenticated) {
            return false;
        }

        // Users can manage themselves
        if (auth.user && auth.user.id === targetUser.id) {
            return true;
        }

        // Admins can manage anyone
        if (auth.role === UserRole.ADMIN) {
            return true;
        }

        // Moderators can manage users but not other moderators or admins
        if (auth.role === UserRole.MODERATOR) {
            const targetRole = this.getUserRole(targetUser);
            return targetRole === UserRole.NORMIE;
        }

        return false;
    }
}
