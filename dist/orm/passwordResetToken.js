"use strict";
/*
 * Password Reset Token ORM model
 * Handles database operations for password reset tokens
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
 * Password Reset Token ORM model
 * Represents a secure token for password reset operations
 */
class PasswordResetToken {
    constructor(token, userId, expiresAt, isUsed, securityQuestionVerified, createdAt, id) {
        this.token = token;
        this.userId = userId;
        this.expiresAt = expiresAt;
        this.isUsed = isUsed;
        this.securityQuestionVerified = securityQuestionVerified;
        this.createdAt = createdAt;
        this.id = id;
    }
    /**
     * Create a new token in the database
     */
    create() {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield alasql_1.default.promise(`
            INSERT INTO password_reset_tokens (token, user_id, expires_at, is_used, security_question_verified, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [
                this.token,
                this.userId,
                this.expiresAt.toISOString(),
                this.isUsed,
                this.securityQuestionVerified,
                this.createdAt.toISOString()
            ]);
            if (result && result.insertId) {
                this.id = result.insertId;
            }
        });
    }
    /**
     * Find token by token string
     */
    static byToken(token) {
        return __awaiter(this, void 0, void 0, function* () {
            const results = yield alasql_1.default.promise(`
            SELECT * FROM password_reset_tokens WHERE token = ?
        `, [token]);
            if (results.length === 0) {
                return null;
            }
            const row = results[0];
            return new PasswordResetToken(row.token, row.user_id, new Date(row.expires_at), row.is_used, row.security_question_verified, new Date(row.created_at), row.id);
        });
    }
    /**
     * Mark token as used
     */
    markAsUsed() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.id) {
                throw new Error('Token must have an ID to be marked as used');
            }
            this.isUsed = true;
            yield alasql_1.default.promise(`
            UPDATE password_reset_tokens SET is_used = ? WHERE id = ?
        `, [true, this.id]);
        });
    }
    /**
     * Check if token is valid (not expired, not used)
     */
    isValid() {
        const now = new Date();
        return !this.isUsed && this.expiresAt > now && this.securityQuestionVerified;
    }
    /**
     * Clean up expired tokens
     */
    static cleanupExpiredTokens() {
        return __awaiter(this, void 0, void 0, function* () {
            const now = new Date();
            yield alasql_1.default.promise(`
            DELETE FROM password_reset_tokens 
            WHERE expires_at < ? OR is_used = ?
        `, [now.toISOString(), true]);
        });
    }
    /**
     * Initialize the password reset tokens table
     */
    static initializeTable() {
        return __awaiter(this, void 0, void 0, function* () {
            yield alasql_1.default.promise(`
            CREATE TABLE IF NOT EXISTS password_reset_tokens(
                id serial primary key not null autoincrement,
                token text not null unique,
                user_id integer not null,
                expires_at datetime not null,
                is_used boolean not null default false,
                security_question_verified boolean not null default false,
                created_at datetime not null,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        `);
        });
    }
}
exports.default = PasswordResetToken;
//# sourceMappingURL=passwordResetToken.js.map