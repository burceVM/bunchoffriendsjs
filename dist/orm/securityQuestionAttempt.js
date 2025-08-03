"use strict";
/*
 * Security Question Attempt ORM model
 * Handles database operations for security question attempt tracking
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
 * Security Question Attempt ORM model
 * Tracks attempts to answer security questions for rate limiting
 */
class SecurityQuestionAttempt {
    constructor(userId, attemptTime, wasSuccessful, ipAddress, id) {
        this.userId = userId;
        this.attemptTime = attemptTime;
        this.wasSuccessful = wasSuccessful;
        this.ipAddress = ipAddress;
        this.id = id;
    }
    /**
     * Create a new attempt record in the database
     */
    create() {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield alasql_1.default.promise(`
            INSERT INTO security_question_attempts (user_id, attempt_time, was_successful, ip_address)
            VALUES (?, ?, ?, ?)
        `, [this.userId, this.attemptTime.toISOString(), this.wasSuccessful, this.ipAddress || null]);
            if (result && result.insertId) {
                this.id = result.insertId;
            }
        });
    }
    /**
     * Get recent attempts for a user within specified time window
     */
    static getRecentAttemptsByUserId(userId, timeWindowHours = 1) {
        return __awaiter(this, void 0, void 0, function* () {
            const cutoffTime = new Date();
            cutoffTime.setHours(cutoffTime.getHours() - timeWindowHours);
            const results = yield alasql_1.default.promise(`
            SELECT * FROM security_question_attempts 
            WHERE user_id = ? AND attempt_time >= ?
            ORDER BY attempt_time DESC
        `, [userId, cutoffTime.toISOString()]);
            return results.map((row) => new SecurityQuestionAttempt(row.user_id, new Date(row.attempt_time), row.was_successful, row.ip_address, row.id));
        });
    }
    /**
     * Clean up old attempt records (older than specified days)
     */
    static cleanupOldAttempts(daysToKeep = 30) {
        return __awaiter(this, void 0, void 0, function* () {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);
            yield alasql_1.default.promise(`
            DELETE FROM security_question_attempts 
            WHERE attempt_time < ?
        `, [cutoffDate.toISOString()]);
        });
    }
    /**
     * Initialize the security question attempts table
     */
    static initializeTable() {
        return __awaiter(this, void 0, void 0, function* () {
            yield alasql_1.default.promise(`
            CREATE TABLE IF NOT EXISTS security_question_attempts(
                id serial primary key not null autoincrement,
                user_id integer not null,
                attempt_time datetime not null,
                was_successful boolean not null,
                ip_address text,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        `);
        });
    }
}
exports.default = SecurityQuestionAttempt;
//# sourceMappingURL=securityQuestionAttempt.js.map