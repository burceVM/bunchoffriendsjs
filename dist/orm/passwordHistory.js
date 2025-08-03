"use strict";
/*
 * Password history ORM model for preventing password reuse
 * Stores previous password hashes to enforce password history policies
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
 * Password history record for tracking previous passwords
 */
class PasswordHistory {
    constructor(userId, passwordHash, createdAt, id) {
        this.userId = userId;
        this.passwordHash = passwordHash;
        this.createdAt = createdAt;
        this.id = id;
    }
    /**
     * Create a new password history record
     */
    create() {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield alasql_1.default.promise(`
            INSERT INTO password_history (user_id, password_hash, created_at)
            VALUES (?, ?, ?)
        `, [this.userId, this.passwordHash, this.createdAt.toISOString()]);
            if (result && result.insertId) {
                this.id = result.insertId;
            }
        });
    }
    /**
     * Get password history for a user (most recent first)
     */
    static getHistoryByUserId(userId, limit = 5) {
        return __awaiter(this, void 0, void 0, function* () {
            const results = yield alasql_1.default.promise(`
            SELECT * FROM password_history 
            WHERE user_id = ${userId}
            ORDER BY created_at DESC
            LIMIT ${limit}
        `);
            return results.map((row) => new PasswordHistory(row.user_id, row.password_hash, new Date(row.created_at), row.id));
        });
    }
    /**
     * Check if a password has been used before by the user
     */
    static isPasswordReused(userId, newPasswordHash, historyLimit = 5) {
        return __awaiter(this, void 0, void 0, function* () {
            const history = yield this.getHistoryByUserId(userId, historyLimit);
            return history.some(record => record.passwordHash === newPasswordHash);
        });
    }
    /**
     * Check if the user's current password is old enough to be changed
     * Passwords must be at least one day old before they can be changed
     */
    static isPasswordOldEnoughToChange(userId, minimumAgeHours = 24) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Get the most recent password (current password)
                const recentHistory = yield this.getHistoryByUserId(userId, 1);
                if (recentHistory.length === 0) {
                    // No password history found, allow change (shouldn't happen in normal flow)
                    return { canChange: true };
                }
                const currentPasswordCreated = recentHistory[0].createdAt;
                const now = new Date();
                const ageInMilliseconds = now.getTime() - currentPasswordCreated.getTime();
                const ageInHours = ageInMilliseconds / (1000 * 60 * 60);
                if (ageInHours >= minimumAgeHours) {
                    return { canChange: true };
                }
                else {
                    const hoursRemaining = Math.ceil(minimumAgeHours - ageInHours);
                    return {
                        canChange: false,
                        error: `Password must be at least ${minimumAgeHours} hours old before it can be changed. Please wait ${hoursRemaining} more hour(s).`,
                        hoursRemaining
                    };
                }
            }
            catch (error) {
                console.error('Error checking password age:', error);
                return {
                    canChange: false,
                    error: 'Unable to verify password age'
                };
            }
        });
    }
    /**
     * Clean up old password history records beyond the limit
     */
    static cleanupOldHistory(userId, keepCount = 5) {
        return __awaiter(this, void 0, void 0, function* () {
            // Get IDs of records to keep (most recent)
            const keepRecords = yield alasql_1.default.promise(`
            SELECT id FROM password_history 
            WHERE user_id = ${userId}
            ORDER BY created_at DESC
            LIMIT ${keepCount}
        `);
            if (keepRecords.length > 0) {
                const keepIds = keepRecords.map((r) => r.id);
                const keepIdsStr = keepIds.join(',');
                yield alasql_1.default.promise(`
                DELETE FROM password_history 
                WHERE user_id = ${userId} AND id NOT IN (${keepIdsStr})
            `);
            }
        });
    }
    /**
     * Initialize the password history table
     */
    static initializeTable() {
        return __awaiter(this, void 0, void 0, function* () {
            yield alasql_1.default.promise(`
            CREATE TABLE IF NOT EXISTS password_history(
                id serial primary key not null autoincrement,
                user_id integer not null,
                password_hash text not null,
                created_at datetime not null
            );
        `);
            // Create index for performance
            try {
                yield alasql_1.default.promise(`
                CREATE INDEX idx_password_history_user_id 
                ON password_history(user_id);
            `);
            }
            catch (error) {
                // Index might already exist, ignore error
            }
            try {
                yield alasql_1.default.promise(`
                CREATE INDEX idx_password_history_created_at 
                ON password_history(created_at);
            `);
            }
            catch (error) {
                // Index might already exist, ignore error
            }
        });
    }
}
exports.default = PasswordHistory;
//# sourceMappingURL=passwordHistory.js.map