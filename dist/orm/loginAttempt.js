"use strict";
/*
 * Login Attempt ORM model
 * Handles database operations for login attempt tracking
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
const alasql_1 = __importDefault(require("alasql"));
/**
 * Login Attempt ORM model
 * Tracks login attempts for account lockout functionality
 */
class LoginAttempt {
    constructor(username, attemptTime, isSuccessful, ipAddress, id) {
        this.username = username;
        this.attemptTime = attemptTime;
        this.isSuccessful = isSuccessful;
        this.ipAddress = ipAddress;
        this.id = id;
    }
    /**
     * Create a new login attempt record in the database
     */
    create() {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield alasql_1.default.promise(`
            INSERT INTO login_attempts (username, attempt_time, is_successful, ip_address)
            VALUES (?, ?, ?, ?)
        `, [this.username, this.attemptTime.toISOString(), this.isSuccessful, this.ipAddress || null]);
            if (result && result.insertId) {
                this.id = result.insertId;
            }
        });
    }
    /**
     * Get recent login attempts for a username within specified time window
     */
    static getRecentAttemptsByUsername(username, timeWindowMinutes = 60) {
        return __awaiter(this, void 0, void 0, function* () {
            const cutoffTime = new Date();
            cutoffTime.setMinutes(cutoffTime.getMinutes() - timeWindowMinutes);
            const results = yield alasql_1.default.promise(`
            SELECT * FROM login_attempts 
            WHERE username = ? AND attempt_time >= ?
            ORDER BY attempt_time DESC
        `, [username, cutoffTime.toISOString()]);
            return results.map((row) => new LoginAttempt(row.username, new Date(row.attempt_time), row.is_successful, row.ip_address, row.id));
        });
    }
    /**
     * Get failed login attempts for a username within specified time window
     */
    static getFailedAttemptsByUsername(username, timeWindowMinutes = 60) {
        return __awaiter(this, void 0, void 0, function* () {
            const cutoffTime = new Date();
            cutoffTime.setMinutes(cutoffTime.getMinutes() - timeWindowMinutes);
            const results = yield alasql_1.default.promise(`
            SELECT * FROM login_attempts 
            WHERE username = ? AND attempt_time >= ? AND is_successful = ?
            ORDER BY attempt_time DESC
        `, [username, cutoffTime.toISOString(), false]);
            return results.map((row) => new LoginAttempt(row.username, new Date(row.attempt_time), row.is_successful, row.ip_address, row.id));
        });
    }
    /**
     * Clean up old login attempt records (older than specified days)
     */
    static cleanupOldAttempts(daysToKeep = 7) {
        return __awaiter(this, void 0, void 0, function* () {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);
            yield alasql_1.default.promise(`
            DELETE FROM login_attempts 
            WHERE attempt_time < ?
        `, [cutoffDate.toISOString()]);
        });
    }
    /**
     * Get all recent login attempts within specified time window
     */
    static getRecentAttemptsByTimeframe(timeWindowMinutes = 60) {
        return __awaiter(this, void 0, void 0, function* () {
            const cutoffTime = new Date();
            cutoffTime.setMinutes(cutoffTime.getMinutes() - timeWindowMinutes);
            const results = yield alasql_1.default.promise(`
            SELECT * FROM login_attempts 
            WHERE attempt_time >= ?
            ORDER BY attempt_time DESC
        `, [cutoffTime.toISOString()]);
            return results.map((row) => new LoginAttempt(row.username, new Date(row.attempt_time), row.is_successful, row.ip_address, row.id));
        });
    }
    /**
     * Initialize the login attempts table
     */
    static initializeTable() {
        return __awaiter(this, void 0, void 0, function* () {
            yield alasql_1.default.promise(`
            CREATE TABLE IF NOT EXISTS login_attempts(
                id serial primary key not null autoincrement,
                username text not null,
                attempt_time datetime not null,
                is_successful boolean not null,
                ip_address text
            );
        `);
            // Create index for performance
            try {
                yield alasql_1.default.promise(`
                CREATE INDEX idx_login_attempts_username_time 
                ON login_attempts(username, attempt_time);
            `);
            }
            catch (error) {
                // Index might already exist, ignore error
            }
        });
    }
}
exports.default = LoginAttempt;
//# sourceMappingURL=loginAttempt.js.map