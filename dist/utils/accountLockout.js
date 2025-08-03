"use strict";
/*
 * Account lockout management to prevent brute force attacks
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
exports.getLockoutStatistics = exports.getLockoutStatus = exports.recordLoginAttempt = exports.initializeLoginTracking = exports.getLockoutPolicy = void 0;
const alasql_1 = __importDefault(require("alasql"));
/**
 * Get current lockout policy configuration
 * Balances security with usability to prevent brute force without enabling DoS
 */
function getLockoutPolicy() {
    return {
        maxAttempts: 5,
        lockoutDurationMinutes: 15,
        progressiveLockout: true,
        maxLockoutMinutes: 60,
        attemptResetMinutes: 60 // Reset attempt counter after 1 hour of no attempts
    };
}
exports.getLockoutPolicy = getLockoutPolicy;
/**
 * Initialize login attempt tracking table
 */
function initializeLoginTracking() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            yield alasql_1.default.promise(`
            CREATE TABLE IF NOT EXISTS login_attempts(
                id serial primary key not null autoincrement,
                username text not null,
                attempt_time datetime not null,
                is_successful boolean not null,
                ip_address text
            );
        `);
            // AlaSQL doesn't support CREATE INDEX IF NOT EXISTS, so we handle errors gracefully
            try {
                yield alasql_1.default.promise('CREATE INDEX idx_login_attempts_username ON login_attempts(username);');
            }
            catch (indexError) {
                // Index might already exist, which is fine
                console.log('Note: Index idx_login_attempts_username already exists or creation failed');
            }
            try {
                yield alasql_1.default.promise('CREATE INDEX idx_login_attempts_time ON login_attempts(attempt_time);');
            }
            catch (indexError) {
                // Index might already exist, which is fine
                console.log('Note: Index idx_login_attempts_time already exists or creation failed');
            }
        }
        catch (error) {
            console.error('Failed to initialize login tracking:', error);
            throw error;
        }
    });
}
exports.initializeLoginTracking = initializeLoginTracking;
/**
 * Record a login attempt (successful or failed)
 */
function recordLoginAttempt(username, isSuccessful, ipAddress) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const attemptTime = new Date().toISOString();
            yield alasql_1.default.promise(`
            INSERT INTO login_attempts (username, attempt_time, is_successful, ip_address)
            VALUES (?, ?, ?, ?)
        `, [username.toLowerCase(), attemptTime, isSuccessful, ipAddress || null]);
            // Clean up old attempts (keep last 30 days for security analysis)
            const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
            yield alasql_1.default.promise(`
            DELETE FROM login_attempts 
            WHERE attempt_time < ?
        `, [thirtyDaysAgo]);
        }
        catch (error) {
            console.error('Failed to record login attempt:', error);
            // Don't throw - login should continue even if logging fails
        }
    });
}
exports.recordLoginAttempt = recordLoginAttempt;
/**
 * Get current lockout status for a username
 */
function getLockoutStatus(username) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const policy = getLockoutPolicy();
            const now = new Date();
            const lookbackTime = new Date(now.getTime() - policy.attemptResetMinutes * 60 * 1000);
            // Get recent failed attempts (within reset window)
            const recentAttempts = yield alasql_1.default.promise(`
            SELECT * FROM login_attempts 
            WHERE username = ? 
            AND attempt_time > ?
            ORDER BY attempt_time DESC
        `, [username.toLowerCase(), lookbackTime.toISOString()]);
            // Find the most recent successful login
            const lastSuccessfulLogin = yield alasql_1.default.promise(`
            SELECT attempt_time FROM login_attempts 
            WHERE username = ? 
            AND is_successful = true 
            ORDER BY attempt_time DESC 
            LIMIT 1
        `, [username.toLowerCase()]);
            // Count consecutive failed attempts since last successful login
            let consecutiveFailures = 0;
            let lastFailureTime = null;
            for (const attempt of recentAttempts) {
                const attemptTime = new Date(attempt.attempt_time);
                // If we found a successful login, stop counting
                if (attempt.is_successful) {
                    break;
                }
                // If this failure is after the last successful login (or no successful login exists)
                if (!lastSuccessfulLogin.length ||
                    attemptTime > new Date(lastSuccessfulLogin[0].attempt_time)) {
                    consecutiveFailures++;
                    if (!lastFailureTime || attemptTime > lastFailureTime) {
                        lastFailureTime = attemptTime;
                    }
                }
            }
            // Determine if account is currently locked
            if (consecutiveFailures >= policy.maxAttempts && lastFailureTime) {
                const lockoutDuration = calculateLockoutDuration(consecutiveFailures, policy);
                const lockoutUntil = new Date(lastFailureTime.getTime() + lockoutDuration * 60 * 1000);
                if (now < lockoutUntil) {
                    const remainingMinutes = Math.ceil((lockoutUntil.getTime() - now.getTime()) / (60 * 1000));
                    return {
                        isLocked: true,
                        lockoutUntil,
                        failedAttempts: consecutiveFailures,
                        remainingLockoutMinutes: remainingMinutes,
                        canAttemptAt: lockoutUntil
                    };
                }
            }
            return {
                isLocked: false,
                failedAttempts: consecutiveFailures
            };
        }
        catch (error) {
            console.error('Error checking lockout status:', error);
            // Fail securely - if we can't determine status, assume not locked
            return {
                isLocked: false,
                failedAttempts: 0
            };
        }
    });
}
exports.getLockoutStatus = getLockoutStatus;
/**
 * Calculate lockout duration based on number of attempts
 * Uses progressive backoff to discourage repeated attacks while preventing DoS
 */
function calculateLockoutDuration(attemptCount, policy) {
    if (!policy.progressiveLockout) {
        return policy.lockoutDurationMinutes;
    }
    // Progressive lockout: 15min, 30min, 60min (capped)
    const baseDuration = policy.lockoutDurationMinutes;
    const progressiveMultiplier = Math.min(attemptCount - policy.maxAttempts + 1, 4);
    const calculatedDuration = baseDuration * Math.pow(2, progressiveMultiplier - 1);
    // Cap the duration to prevent DoS attacks
    return Math.min(calculatedDuration, policy.maxLockoutMinutes);
}
/**
 * Get lockout statistics for monitoring and analysis
 */
function getLockoutStatistics(hoursBack = 24) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            // Get all attempts first, then filter in JavaScript for better AlaSQL compatibility
            const allAttempts = yield alasql_1.default.promise(`
            SELECT * FROM login_attempts
        `);
            // Filter attempts within the time window
            const recentAttempts = allAttempts.filter((attempt) => {
                const attemptTime = new Date(attempt.attempt_time);
                const cutoffTime = new Date(Date.now() - hoursBack * 60 * 60 * 1000);
                return attemptTime >= cutoffTime;
            });
            const totalAttempts = recentAttempts.length;
            const failedAttempts = recentAttempts.filter((attempt) => !attempt.is_successful).length;
            const successfulAttempts = recentAttempts.filter((attempt) => attempt.is_successful).length;
            // Group failed attempts by username
            const failedByUser = {};
            recentAttempts
                .filter((attempt) => !attempt.is_successful)
                .forEach((attempt) => {
                failedByUser[attempt.username] = (failedByUser[attempt.username] || 0) + 1;
            });
            const topFailedUsernames = Object.entries(failedByUser)
                .map(([username, attempts]) => ({ username, attempts }))
                .sort((a, b) => b.attempts - a.attempts)
                .slice(0, 10);
            const uniqueUsersLocked = topFailedUsernames.filter(u => u.attempts >= getLockoutPolicy().maxAttempts).length;
            return {
                totalAttempts,
                failedAttempts,
                successfulAttempts,
                uniqueUsersLocked,
                topFailedUsernames
            };
        }
        catch (error) {
            console.error('Failed to get lockout statistics:', error);
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
exports.getLockoutStatistics = getLockoutStatistics;
//# sourceMappingURL=accountLockout.js.map