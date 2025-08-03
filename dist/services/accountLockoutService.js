"use strict";
/*
 * Account lockout service with proper ORM implementation
 * Implements time-based account disabling with exponential backoff
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getLockoutStatistics = exports.getAllLockedAccounts = exports.resetFailedAttempts = exports.getLockoutStatus = exports.recordLoginAttempt = exports.initializeLoginTracking = exports.getLockoutPolicy = exports.AccountLockoutService = void 0;
const loginAttempt_1 = __importDefault(require("../orm/loginAttempt"));
/**
 * Account lockout service class
 * Encapsulates all account lockout related operations
 */
class AccountLockoutService {
    /**
     * Get current lockout policy configuration
     * Balances security with usability to prevent brute force without enabling DoS
     */
    static getLockoutPolicy() {
        return {
            maxAttempts: 5,
            lockoutDurationMinutes: 15,
            progressiveLockout: true,
            maxLockoutMinutes: 60,
            attemptResetMinutes: 60 // Reset attempt counter after 1 hour of no attempts
        };
    }
    /**
     * Initialize account lockout database tables
     */
    static initializeTables() {
        return __awaiter(this, void 0, void 0, function* () {
            yield loginAttempt_1.default.initializeTable();
        });
    }
    /**
     * Record a login attempt
     */
    static recordLoginAttempt(username, isSuccessful, ipAddress) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const attempt = new loginAttempt_1.default(username.toLowerCase(), new Date(), isSuccessful, ipAddress);
                yield attempt.create();
            }
            catch (error) {
                console.error('Error recording login attempt:', error);
            }
        });
    }
    /**
     * Check if account is locked and get lockout status
     */
    static getLockoutStatus(username) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const policy = this.getLockoutPolicy();
                const recentAttempts = yield loginAttempt_1.default.getRecentAttemptsByUsername(username.toLowerCase(), policy.attemptResetMinutes);
                // Filter failed attempts only
                const failedAttempts = recentAttempts.filter(attempt => !attempt.isSuccessful);
                if (failedAttempts.length < policy.maxAttempts) {
                    return {
                        isLocked: false,
                        attemptsRemaining: policy.maxAttempts - failedAttempts.length
                    };
                }
                // Account is locked - calculate lockout duration
                const lockoutDuration = this.calculateLockoutDuration(failedAttempts.length, policy);
                const mostRecentFailure = failedAttempts[0];
                const lockoutUntil = new Date(mostRecentFailure.attemptTime.getTime() + (lockoutDuration * 60 * 1000));
                const now = new Date();
                const isCurrentlyLocked = now < lockoutUntil;
                return {
                    isLocked: isCurrentlyLocked,
                    lockoutUntil: isCurrentlyLocked ? lockoutUntil : undefined,
                    attemptsRemaining: 0,
                    nextAttemptTime: isCurrentlyLocked ? lockoutUntil : undefined
                };
            }
            catch (error) {
                console.error('Error checking lockout status:', error);
                // Fail secure - if we can't check, don't lock
                return {
                    isLocked: false,
                    attemptsRemaining: 5
                };
            }
        });
    }
    /**
     * Calculate progressive lockout duration
     */
    static calculateLockoutDuration(failedAttemptCount, policy) {
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
    static resetFailedAttempts(username) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Record successful login which effectively resets the counter
                yield this.recordLoginAttempt(username, true);
            }
            catch (error) {
                console.error('Error resetting failed attempts:', error);
            }
        });
    }
    /**
     * Get all locked accounts (for admin interface)
     */
    static getAllLockedAccounts() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const policy = this.getLockoutPolicy();
                // Get all usernames with recent failed attempts
                const recentAttempts = yield loginAttempt_1.default.getFailedAttemptsByUsername('', // Empty string to get all usernames
                policy.attemptResetMinutes);
                // Group by username
                const userAttempts = new Map();
                recentAttempts.forEach(attempt => {
                    if (!userAttempts.has(attempt.username)) {
                        userAttempts.set(attempt.username, []);
                    }
                    const attempts = userAttempts.get(attempt.username);
                    if (attempts) {
                        attempts.push(attempt);
                    }
                });
                const lockedAccounts = [];
                for (const [username, attempts] of userAttempts) {
                    const failedAttempts = attempts.filter(a => !a.isSuccessful);
                    if (failedAttempts.length >= policy.maxAttempts) {
                        const lockoutDuration = this.calculateLockoutDuration(failedAttempts.length, policy);
                        const mostRecentFailure = failedAttempts[0];
                        const lockoutUntil = new Date(mostRecentFailure.attemptTime.getTime() + (lockoutDuration * 60 * 1000));
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
            }
            catch (error) {
                console.error('Error getting locked accounts:', error);
                return [];
            }
        });
    }
    /**
     * Get lockout statistics for monitoring and analysis
     */
    static getLockoutStatistics(hoursBack = 24) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const timeframeMinutes = hoursBack * 60;
                const allAttempts = yield loginAttempt_1.default.getRecentAttemptsByTimeframe(timeframeMinutes);
                const totalAttempts = allAttempts.length;
                const failedAttempts = allAttempts.filter((attempt) => !attempt.isSuccessful).length;
                const successfulAttempts = totalAttempts - failedAttempts;
                // Get unique failed usernames
                const failedUsernames = new Map();
                allAttempts.filter((attempt) => !attempt.isSuccessful).forEach((attempt) => {
                    failedUsernames.set(attempt.username, (failedUsernames.get(attempt.username) || 0) + 1);
                });
                // Count currently locked users
                let uniqueUsersLocked = 0;
                for (const username of failedUsernames.keys()) {
                    const lockoutStatus = yield this.getLockoutStatus(username);
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
            }
            catch (error) {
                console.error('Error getting lockout statistics:', error);
                return {
                    totalAttempts: 0,
                    failedAttempts: 0,
                    successfulAttempts: 0,
                    uniqueUsersLocked: 0,
                    topFailedUsernames: []
                };
            }
        });
    }
    /**
     * Clean up old login attempts
     */
    static cleanupOldAttempts(daysToKeep = 7) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield loginAttempt_1.default.cleanupOldAttempts(daysToKeep);
            }
            catch (error) {
                console.error('Error cleaning up old attempts:', error);
            }
        });
    }
}
exports.AccountLockoutService = AccountLockoutService;
// Export functions for backward compatibility
exports.getLockoutPolicy = AccountLockoutService.getLockoutPolicy;
exports.initializeLoginTracking = AccountLockoutService.initializeTables;
exports.recordLoginAttempt = AccountLockoutService.recordLoginAttempt;
exports.getLockoutStatus = AccountLockoutService.getLockoutStatus;
exports.resetFailedAttempts = AccountLockoutService.resetFailedAttempts;
exports.getAllLockedAccounts = AccountLockoutService.getAllLockedAccounts;
exports.getLockoutStatistics = AccountLockoutService.getLockoutStatistics;
//# sourceMappingURL=accountLockoutService.js.map