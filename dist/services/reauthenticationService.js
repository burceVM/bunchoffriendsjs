"use strict";
/*
 * Reauthentication service for verifying user identity before critical operations
 * Requires users to re-enter their current password for sensitive actions
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
exports.ReauthenticationService = void 0;
const user_1 = __importDefault(require("../orm/user"));
const alasql_1 = __importDefault(require("alasql"));
/**
 * Service for handling user re-authentication during critical operations
 */
class ReauthenticationService {
    /**
     * Verify user's current password for re-authentication
     */
    static verifyCurrentPassword(username, currentPassword) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Validate inputs
                if (!username || !currentPassword) {
                    return {
                        isValid: false,
                        error: 'Username and current password are required'
                    };
                }
                // Attempt to authenticate user with current credentials
                const user = yield user_1.default.byLogin(username, currentPassword);
                if (!user) {
                    return {
                        isValid: false,
                        error: 'Current password is incorrect'
                    };
                }
                return {
                    isValid: true,
                    userId: user.id
                };
            }
            catch (error) {
                console.error('Re-authentication error:', error);
                return {
                    isValid: false,
                    error: 'Authentication verification failed'
                };
            }
        });
    }
    /**
     * Create a re-authentication token that expires after a short time
     */
    static createReauthToken(userId, operation) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Generate a simple token (in production, use crypto.randomBytes)
                const token = `reauth_${userId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                const expiresAt = new Date(Date.now() + (this.REAUTHENTICATION_TIMEOUT_MINUTES * 60 * 1000));
                // Store token in database (create table if needed)
                yield this.initializeReauthTable();
                yield alasql_1.default.promise(`
                INSERT INTO reauthentication_tokens (user_id, token, operation, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?)
            `, [userId, token, operation, expiresAt.toISOString(), new Date().toISOString()]);
                return {
                    success: true,
                    token
                };
            }
            catch (error) {
                console.error('Error creating reauth token:', error);
                return {
                    success: false,
                    error: 'Failed to create authentication token'
                };
            }
        });
    }
    /**
     * Verify and consume a re-authentication token
     */
    static verifyAndConsumeReauthToken(userId, token, operation) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!token || !operation) {
                    return {
                        isValid: false,
                        error: 'Authentication token and operation are required'
                    };
                }
                // Find the token
                const tokenRecords = yield alasql_1.default.promise(`
                SELECT * FROM reauthentication_tokens 
                WHERE user_id = ? AND token = ? AND operation = ?
                ORDER BY created_at DESC
                LIMIT 1
            `, [userId, token, operation]);
                if (tokenRecords.length === 0) {
                    return {
                        isValid: false,
                        error: 'Invalid authentication token'
                    };
                }
                const tokenRecord = tokenRecords[0];
                const expiresAt = new Date(tokenRecord.expires_at);
                const now = new Date();
                // Check if token has expired
                if (now > expiresAt) {
                    // Clean up expired token
                    yield alasql_1.default.promise(`
                    DELETE FROM reauthentication_tokens 
                    WHERE id = ?
                `, [tokenRecord.id]);
                    return {
                        isValid: false,
                        error: 'Authentication token has expired. Please re-authenticate.'
                    };
                }
                // Token is valid, consume it (delete it so it can't be reused)
                yield alasql_1.default.promise(`
                DELETE FROM reauthentication_tokens 
                WHERE id = ?
            `, [tokenRecord.id]);
                return { isValid: true };
            }
            catch (error) {
                console.error('Error verifying reauth token:', error);
                return {
                    isValid: false,
                    error: 'Token verification failed'
                };
            }
        });
    }
    /**
     * Clean up expired re-authentication tokens
     */
    static cleanupExpiredTokens() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const now = new Date().toISOString();
                yield alasql_1.default.promise(`
                DELETE FROM reauthentication_tokens 
                WHERE expires_at < ?
            `, [now]);
            }
            catch (error) {
                console.error('Error cleaning up expired reauth tokens:', error);
            }
        });
    }
    /**
     * Initialize the re-authentication tokens table
     */
    static initializeReauthTable() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield alasql_1.default.promise(`
                CREATE TABLE IF NOT EXISTS reauthentication_tokens(
                    id serial primary key not null autoincrement,
                    user_id integer not null,
                    token text not null,
                    operation text not null,
                    expires_at datetime not null,
                    created_at datetime not null
                );
            `);
                // Create index for performance
                try {
                    yield alasql_1.default.promise(`
                    CREATE INDEX idx_reauthentication_tokens_user_id 
                    ON reauthentication_tokens(user_id);
                `);
                }
                catch (error) {
                    // Index might already exist, ignore error
                }
                try {
                    yield alasql_1.default.promise(`
                    CREATE INDEX idx_reauthentication_tokens_expires_at 
                    ON reauthentication_tokens(expires_at);
                `);
                }
                catch (error) {
                    // Index might already exist, ignore error
                }
            }
            catch (error) {
                console.error('Error initializing reauthentication table:', error);
                throw error;
            }
        });
    }
    /**
     * Get the re-authentication timeout in minutes
     */
    static getReauthTimeout() {
        return this.REAUTHENTICATION_TIMEOUT_MINUTES;
    }
}
exports.ReauthenticationService = ReauthenticationService;
ReauthenticationService.REAUTHENTICATION_TIMEOUT_MINUTES = 5;
//# sourceMappingURL=reauthenticationService.js.map