"use strict";
/*
 * Password history service for preventing password reuse
 * Implements password history policies and validation
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
exports.changePasswordWithHistory = exports.addPasswordToHistory = exports.checkPasswordHistory = exports.initializePasswordHistory = exports.PasswordHistoryService = void 0;
const passwordHistory_1 = __importDefault(require("../orm/passwordHistory"));
const passwordSecurity_1 = require("../utils/passwordSecurity");
/**
 * Password history service class
 * Encapsulates all password history related operations
 */
class PasswordHistoryService {
    /**
     * Get current password history policy
     */
    static getPasswordHistoryPolicy() {
        return {
            historyCount: 5,
            enforceHistory: true // Enforce password history by default
        };
    }
    /**
     * Initialize password history database tables
     */
    static initializeTables() {
        return __awaiter(this, void 0, void 0, function* () {
            yield passwordHistory_1.default.initializeTable();
        });
    }
    /**
     * Check if a new password violates history policy
     */
    static checkPasswordHistory(userId, newPassword) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const policy = this.getPasswordHistoryPolicy();
                if (!policy.enforceHistory) {
                    return { isValid: true };
                }
                // Get password history for the user
                const history = yield passwordHistory_1.default.getHistoryByUserId(userId, policy.historyCount);
                // Check each historical password
                for (const record of history) {
                    const isReused = yield passwordSecurity_1.verifyPassword(newPassword, record.passwordHash);
                    if (isReused) {
                        return {
                            isValid: false,
                            error: `Password cannot be one of your last ${policy.historyCount} passwords`
                        };
                    }
                }
                return { isValid: true };
            }
            catch (error) {
                console.error('Error checking password history:', error);
                return {
                    isValid: false,
                    error: 'Unable to verify password history'
                };
            }
        });
    }
    /**
     * Add a password to user's history
     */
    static addPasswordToHistory(userId, passwordHash) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Create history record
                const historyRecord = new passwordHistory_1.default(userId, passwordHash, new Date());
                yield historyRecord.create();
                // Clean up old history beyond policy limit
                const policy = this.getPasswordHistoryPolicy();
                yield passwordHistory_1.default.cleanupOldHistory(userId, policy.historyCount);
            }
            catch (error) {
                console.error('Error adding password to history:', error);
                throw new Error('Failed to update password history');
            }
        });
    }
    /**
     * Validate and change password with history checking and age restrictions
     */
    static changePasswordWithHistory(userId, newPassword, updateUserCallback) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Check if current password is old enough to be changed
                const ageCheck = yield passwordHistory_1.default.isPasswordOldEnoughToChange(userId);
                if (!ageCheck.canChange) {
                    return {
                        success: false,
                        error: ageCheck.error
                    };
                }
                // Check password history for reuse
                const historyCheck = yield this.checkPasswordHistory(userId, newPassword);
                if (!historyCheck.isValid) {
                    return {
                        success: false,
                        error: historyCheck.error
                    };
                }
                // Hash the new password
                const newPasswordHash = yield passwordSecurity_1.hashPassword(newPassword);
                // Update the user's password
                yield updateUserCallback(newPasswordHash);
                // Add to password history
                yield this.addPasswordToHistory(userId, newPasswordHash);
                return { success: true };
            }
            catch (error) {
                console.error('Error changing password with history:', error);
                return {
                    success: false,
                    error: 'Failed to change password'
                };
            }
        });
    }
    /**
     * Initialize password history for a new user
     */
    static initializePasswordHistoryForUser(userId, initialPasswordHash) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.addPasswordToHistory(userId, initialPasswordHash);
        });
    }
    /**
     * Get user's password history (for admin purposes)
     */
    static getUserPasswordHistory(userId) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const history = yield passwordHistory_1.default.getHistoryByUserId(userId);
                return history.map(record => ({
                    createdAt: record.createdAt,
                    id: record.id || 0
                }));
            }
            catch (error) {
                console.error('Error getting user password history:', error);
                return [];
            }
        });
    }
    /**
     * Clean up old password history for all users
     */
    static cleanupAllPasswordHistory() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const policy = this.getPasswordHistoryPolicy();
                // This is a simplified cleanup - in a real system you'd get all user IDs
                // For now, we'll let the per-user cleanup handle this
                console.log(`Password history cleanup: keeping last ${policy.historyCount} passwords per user`);
            }
            catch (error) {
                console.error('Error cleaning up password history:', error);
            }
        });
    }
}
exports.PasswordHistoryService = PasswordHistoryService;
// Export functions for backward compatibility
exports.initializePasswordHistory = PasswordHistoryService.initializeTables;
exports.checkPasswordHistory = PasswordHistoryService.checkPasswordHistory;
exports.addPasswordToHistory = PasswordHistoryService.addPasswordToHistory;
exports.changePasswordWithHistory = PasswordHistoryService.changePasswordWithHistory;
//# sourceMappingURL=passwordHistoryService.js.map