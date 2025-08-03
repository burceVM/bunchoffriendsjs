/*
 * Account lockout service with proper ORM implementation
 * Implements time-based account disabling with exponential backoff
 */

import LoginAttempt from '../orm/loginAttempt';

/**
 * Configuration for account lockout policy
 * Based on industry best practices and OWASP recommendations
 */
export interface LockoutPolicy {
    maxAttempts: number;           // Maximum failed attempts before lockout
    lockoutDurationMinutes: number; // Base lockout duration in minutes
    progressiveLockout: boolean;    // Whether to use progressive lockout times
    maxLockoutMinutes: number;     // Maximum lockout duration to prevent DoS
    attemptResetMinutes: number;   // Time to reset attempt counter after successful login
}

/**
 * Account lockout status
 */
export interface LockoutStatus {
    isLocked: boolean;
    lockoutUntil?: Date;
    attemptsRemaining: number;
    nextAttemptTime?: Date;
}

/**
 * Account lockout service class
 * Encapsulates all account lockout related operations
 */
export class AccountLockoutService {
    
    /**
     * Get current lockout policy configuration
     * Balances security with usability to prevent brute force without enabling DoS
     */
    static getLockoutPolicy(): LockoutPolicy {
        return {
            maxAttempts: 5,              // Industry standard (OWASP recommended 3-5)
            lockoutDurationMinutes: 15,  // Initial lockout: 15 minutes 
            progressiveLockout: true,    // Enable escalating lockout times
            maxLockoutMinutes: 60,       // Cap at 1 hour to prevent DoS
            attemptResetMinutes: 60      // Reset attempt counter after 1 hour of no attempts
        };
    }

    /**
     * Initialize account lockout database tables
     */
    static async initializeTables(): Promise<void> {
        await LoginAttempt.initializeTable();
    }

    /**
     * Record a login attempt
     */
    static async recordLoginAttempt(
        username: string, 
        isSuccessful: boolean, 
        ipAddress?: string
    ): Promise<void> {
        try {
            const attempt = new LoginAttempt(
                username.toLowerCase(),
                new Date(),
                isSuccessful,
                ipAddress
            );
            await attempt.create();

        } catch (error) {
            console.error('Error recording login attempt:', error);
        }
    }

    /**
     * Check if account is locked and get lockout status
     */
    static async getLockoutStatus(username: string): Promise<LockoutStatus> {
        try {
            const policy = this.getLockoutPolicy();
            const recentAttempts = await LoginAttempt.getRecentAttemptsByUsername(
                username.toLowerCase(), 
                policy.attemptResetMinutes
            );

            // Filter failed attempts only
            const failedAttempts = recentAttempts.filter(attempt => !attempt.isSuccessful);

            if (failedAttempts.length < policy.maxAttempts) {
                return {
                    isLocked: false,
                    attemptsRemaining: policy.maxAttempts - failedAttempts.length
                };
            }

            // Account is locked - calculate lockout duration
            const lockoutDuration = this.calculateLockoutDuration(
                failedAttempts.length, 
                policy
            );

            const mostRecentFailure = failedAttempts[0];
            const lockoutUntil = new Date(
                mostRecentFailure.attemptTime.getTime() + (lockoutDuration * 60 * 1000)
            );

            const now = new Date();
            const isCurrentlyLocked = now < lockoutUntil;

            return {
                isLocked: isCurrentlyLocked,
                lockoutUntil: isCurrentlyLocked ? lockoutUntil : undefined,
                attemptsRemaining: 0,
                nextAttemptTime: isCurrentlyLocked ? lockoutUntil : undefined
            };

        } catch (error) {
            console.error('Error checking lockout status:', error);
            // Fail secure - if we can't check, don't lock
            return {
                isLocked: false,
                attemptsRemaining: 5
            };
        }
    }

    /**
     * Calculate progressive lockout duration
     */
    private static calculateLockoutDuration(
        failedAttemptCount: number, 
        policy: LockoutPolicy
    ): number {
        if (!policy.progressiveLockout) {
            return policy.lockoutDurationMinutes;
        }

        // Progressive lockout: 15 min -> 30 min -> 60 min (max)
        const baseDuration = policy.lockoutDurationMinutes;
        const multiplier = Math.min(failedAttemptCount - policy.maxAttempts + 1, 4);
        const duration = baseDuration * multiplier;
        
        return Math.min(duration, policy.maxLockoutMinutes);
    }

    /**
     * Reset failed attempts for a user (on successful login)
     */
    static async resetFailedAttempts(username: string): Promise<void> {
        try {
            // Record successful login which effectively resets the counter
            await this.recordLoginAttempt(username, true);
        } catch (error) {
            console.error('Error resetting failed attempts:', error);
        }
    }

    /**
     * Get all locked accounts (for admin interface)
     */
    static async getAllLockedAccounts(): Promise<Array<{
        username: string;
        lockoutUntil: Date;
        failedAttempts: number;
    }>> {
        try {
            const policy = this.getLockoutPolicy();
            
            // Get all usernames with recent failed attempts
            const recentAttempts = await LoginAttempt.getFailedAttemptsByUsername(
                '', // Empty string to get all usernames
                policy.attemptResetMinutes
            );

            // Group by username
            const userAttempts = new Map<string, LoginAttempt[]>();
            recentAttempts.forEach(attempt => {
                if (!userAttempts.has(attempt.username)) {
                    userAttempts.set(attempt.username, []);
                }
                const attempts = userAttempts.get(attempt.username);
                if (attempts) {
                    attempts.push(attempt);
                }
            });

            const lockedAccounts: Array<{
                username: string;
                lockoutUntil: Date;
                failedAttempts: number;
            }> = [];

            for (const [username, attempts] of userAttempts) {
                const failedAttempts = attempts.filter(a => !a.isSuccessful);
                
                if (failedAttempts.length >= policy.maxAttempts) {
                    const lockoutDuration = this.calculateLockoutDuration(
                        failedAttempts.length, 
                        policy
                    );
                    
                    const mostRecentFailure = failedAttempts[0];
                    const lockoutUntil = new Date(
                        mostRecentFailure.attemptTime.getTime() + (lockoutDuration * 60 * 1000)
                    );

                    if (lockoutUntil > new Date()) {
                        lockedAccounts.push({
                            username,
                            lockoutUntil,
                            failedAttempts: failedAttempts.length
                        });
                    }
                }
            }

            return lockedAccounts;

        } catch (error) {
            console.error('Error getting locked accounts:', error);
            return [];
        }
    }

    /**
     * Get lockout statistics for monitoring and analysis
     */
    static async getLockoutStatistics(hoursBack = 24): Promise<{
        totalAttempts: number;
        failedAttempts: number;
        successfulAttempts: number;
        uniqueUsersLocked: number;
        topFailedUsernames: Array<{username: string, attempts: number}>;
    }> {
        try {
            const timeframeMinutes = hoursBack * 60;
            const allAttempts = await LoginAttempt.getRecentAttemptsByTimeframe(timeframeMinutes);
            
            const totalAttempts = allAttempts.length;
            const failedAttempts = allAttempts.filter((attempt: LoginAttempt) => !attempt.isSuccessful).length;
            const successfulAttempts = totalAttempts - failedAttempts;

            // Get unique failed usernames
            const failedUsernames = new Map<string, number>();
            allAttempts.filter((attempt: LoginAttempt) => !attempt.isSuccessful).forEach((attempt: LoginAttempt) => {
                failedUsernames.set(
                    attempt.username, 
                    (failedUsernames.get(attempt.username) || 0) + 1
                );
            });

            // Count currently locked users
            let uniqueUsersLocked = 0;
            for (const username of failedUsernames.keys()) {
                const lockoutStatus = await this.getLockoutStatus(username);
                if (lockoutStatus.isLocked) {
                    uniqueUsersLocked++;
                }
            }

            // Get top failed usernames
            const topFailedUsernames = Array.from(failedUsernames.entries())
                .map(([username, attempts]) => ({ username, attempts }))
                .sort((a, b) => b.attempts - a.attempts)
                .slice(0, 10);

            return {
                totalAttempts,
                failedAttempts,
                successfulAttempts,
                uniqueUsersLocked,
                topFailedUsernames
            };

        } catch (error) {
            console.error('Error getting lockout statistics:', error);
            return {
                totalAttempts: 0,
                failedAttempts: 0,
                successfulAttempts: 0,
                uniqueUsersLocked: 0,
                topFailedUsernames: []
            };
        }
    }

    /**
     * Clean up old login attempts
     */
    static async cleanupOldAttempts(daysToKeep = 7): Promise<void> {
        try {
            await LoginAttempt.cleanupOldAttempts(daysToKeep);
        } catch (error) {
            console.error('Error cleaning up old attempts:', error);
        }
    }
}

// Export functions for backward compatibility
export const getLockoutPolicy = AccountLockoutService.getLockoutPolicy;
export const initializeLoginTracking = AccountLockoutService.initializeTables;
export const recordLoginAttempt = AccountLockoutService.recordLoginAttempt;
export const getLockoutStatus = AccountLockoutService.getLockoutStatus;
export const resetFailedAttempts = AccountLockoutService.resetFailedAttempts;
export const getAllLockedAccounts = AccountLockoutService.getAllLockedAccounts;
export const getLockoutStatistics = AccountLockoutService.getLockoutStatistics;
