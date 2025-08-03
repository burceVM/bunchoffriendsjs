"use strict";
/*
 * Login tracking service for monitoring user login attempts
 * Tracks successful and failed login attempts to inform users of account activity
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
exports.LoginTrackingService = void 0;
const alasql_1 = __importDefault(require("alasql"));
/**
 * Service for tracking and reporting login attempts
 */
class LoginTrackingService {
    /**
     * Record a login attempt (successful or failed)
     */
    static recordLoginAttempt(username, ipAddress, userAgent, wasSuccessful, userId) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield this.initializeTable();
                const timestamp = new Date();
                yield alasql_1.default.promise(`
                INSERT INTO login_tracking (
                    username, 
                    user_id, 
                    ip_address, 
                    user_agent, 
                    was_successful, 
                    attempt_time,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [
                    username,
                    userId || null,
                    ipAddress,
                    userAgent,
                    wasSuccessful ? 1 : 0,
                    timestamp.toISOString(),
                    timestamp.toISOString()
                ]);
                // Clean up old records (keep only last 50 per user)
                yield this.cleanupOldRecords(username);
            }
            catch (error) {
                console.error('Error recording login attempt:', error);
                // Don't throw - login tracking shouldn't prevent login
            }
        });
    }
    /**
     * Get the last login information for a user (excluding the current login)
     */
    static getLastLoginInfo(username, excludeCurrentSession = true) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield this.initializeTable();
                // Get the most recent login attempt (excluding current session if requested)
                const limit = excludeCurrentSession ? 2 : 1;
                const recentAttempts = yield alasql_1.default.promise(`
                SELECT * FROM login_tracking 
                WHERE username = ?
                ORDER BY attempt_time DESC
                LIMIT ${limit}
            `, [username]);
                let lastAttempt = null;
                if (recentAttempts.length > 0) {
                    const attempt = excludeCurrentSession && recentAttempts.length > 1
                        ? recentAttempts[1]
                        : recentAttempts[0];
                    if (attempt) {
                        lastAttempt = {
                            wasSuccessful: Boolean(attempt.was_successful),
                            ipAddress: attempt.ip_address,
                            userAgent: attempt.user_agent,
                            attemptTime: new Date(attempt.attempt_time),
                            timeAgo: this.formatTimeAgo(new Date(attempt.attempt_time))
                        };
                    }
                }
                // Count recent failed attempts (last 24 hours)
                const oneDayAgo = new Date(Date.now() - (24 * 60 * 60 * 1000));
                const failedAttempts = yield alasql_1.default.promise(`
                SELECT * FROM login_tracking 
                WHERE username = ? 
                AND was_successful = 0 
                AND attempt_time >= ?
            `, [username, oneDayAgo.toISOString()]);
                const recentFailedAttempts = failedAttempts.length;
                return {
                    lastAttempt: lastAttempt || undefined,
                    recentFailedAttempts
                };
            }
            catch (error) {
                console.error('Error getting last login info:', error);
                return { recentFailedAttempts: 0 };
            }
        });
    }
    /**
     * Format time difference as human-readable string
     */
    static formatTimeAgo(date) {
        const now = new Date();
        const diffMs = now.getTime() - date.getTime();
        const diffMinutes = Math.floor(diffMs / (1000 * 60));
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        if (diffMinutes < 1) {
            return 'just now';
        }
        else if (diffMinutes < 60) {
            return `${diffMinutes} minute${diffMinutes === 1 ? '' : 's'} ago`;
        }
        else if (diffHours < 24) {
            return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
        }
        else if (diffDays < 7) {
            return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
        }
        else {
            return date.toLocaleDateString();
        }
    }
    /**
     * Clean up old login tracking records
     */
    static cleanupOldRecords(username) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Keep only the most recent 50 records per user
                const keepRecords = yield alasql_1.default.promise(`
                SELECT id FROM login_tracking 
                WHERE username = ?
                ORDER BY attempt_time DESC
                LIMIT 50
            `, [username]);
                if (keepRecords.length > 0) {
                    const keepIds = keepRecords.map((r) => r.id);
                    const keepIdsStr = keepIds.join(',');
                    yield alasql_1.default.promise(`
                    DELETE FROM login_tracking 
                    WHERE username = ? AND id NOT IN (${keepIdsStr})
                `, [username]);
                }
                // Also clean up records older than 90 days
                const ninetyDaysAgo = new Date(Date.now() - (90 * 24 * 60 * 60 * 1000));
                yield alasql_1.default.promise(`
                DELETE FROM login_tracking 
                WHERE attempt_time < ?
            `, [ninetyDaysAgo.toISOString()]);
            }
            catch (error) {
                console.error('Error cleaning up login tracking records:', error);
            }
        });
    }
    /**
     * Get login statistics for a user (for admin/security purposes)
     */
    static getLoginStatistics(username) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield this.initializeTable();
                const stats = yield alasql_1.default.promise(`
                SELECT 
                    COUNT(*) as totalAttempts,
                    SUM(was_successful) as successfulLogins,
                    SUM(CASE WHEN was_successful = 0 THEN 1 ELSE 0 END) as failedAttempts,
                    MAX(CASE WHEN was_successful = 1 THEN attempt_time END) as lastSuccessfulLogin,
                    MAX(CASE WHEN was_successful = 0 THEN attempt_time END) as lastFailedAttempt,
                    COUNT(DISTINCT ip_address) as uniqueIpAddresses
                FROM login_tracking 
                WHERE username = ?
            `, [username]);
                const result = stats[0] || {};
                return {
                    totalAttempts: result.totalAttempts || 0,
                    successfulLogins: result.successfulLogins || 0,
                    failedAttempts: result.failedAttempts || 0,
                    lastSuccessfulLogin: result.lastSuccessfulLogin ? new Date(result.lastSuccessfulLogin) : undefined,
                    lastFailedAttempt: result.lastFailedAttempt ? new Date(result.lastFailedAttempt) : undefined,
                    uniqueIpAddresses: result.uniqueIpAddresses || 0
                };
            }
            catch (error) {
                console.error('Error getting login statistics:', error);
                return {
                    totalAttempts: 0,
                    successfulLogins: 0,
                    failedAttempts: 0,
                    uniqueIpAddresses: 0
                };
            }
        });
    }
    /**
     * Initialize the login tracking table
     */
    static initializeTable() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield alasql_1.default.promise(`
                CREATE TABLE IF NOT EXISTS login_tracking(
                    id serial primary key not null autoincrement,
                    username text not null,
                    user_id integer,
                    ip_address text not null,
                    user_agent text not null,
                    was_successful integer not null,
                    attempt_time datetime not null,
                    created_at datetime not null
                );
            `);
                // Create indexes for performance
                try {
                    yield alasql_1.default.promise(`
                    CREATE INDEX idx_login_tracking_username 
                    ON login_tracking(username);
                `);
                }
                catch (error) {
                    // Index might already exist, ignore error
                }
                try {
                    yield alasql_1.default.promise(`
                    CREATE INDEX idx_login_tracking_attempt_time 
                    ON login_tracking(attempt_time);
                `);
                }
                catch (error) {
                    // Index might already exist, ignore error
                }
                try {
                    yield alasql_1.default.promise(`
                    CREATE INDEX idx_login_tracking_user_success 
                    ON login_tracking(username, was_successful);
                `);
                }
                catch (error) {
                    // Index might already exist, ignore error
                }
            }
            catch (error) {
                console.error('Error initializing login tracking table:', error);
                throw error;
            }
        });
    }
}
exports.LoginTrackingService = LoginTrackingService;
//# sourceMappingURL=loginTrackingService.js.map