/*
 * Password history service for preventing password reuse
 * Implements password history policies and validation
 */

import PasswordHistory from '../orm/passwordHistory';
import { hashPassword, verifyPassword } from '../utils/passwordSecurity';

/**
 * Password history policy configuration
 */
export interface PasswordHistoryPolicy {
    historyCount: number;      // Number of previous passwords to remember
    enforceHistory: boolean;   // Whether to enforce password history
}

/**
 * Password history service class
 * Encapsulates all password history related operations
 */
export class PasswordHistoryService {
    
    /**
     * Get current password history policy
     */
    static getPasswordHistoryPolicy(): PasswordHistoryPolicy {
        return {
            historyCount: 5,        // Remember last 5 passwords
            enforceHistory: true    // Enforce password history by default
        };
    }

    /**
     * Initialize password history database tables
     */
    static async initializeTables(): Promise<void> {
        await PasswordHistory.initializeTable();
    }

    /**
     * Check if a new password violates history policy
     */
    static async checkPasswordHistory(
        userId: number, 
        newPassword: string
    ): Promise<{
        isValid: boolean;
        error?: string;
    }> {
        try {
            const policy = this.getPasswordHistoryPolicy();
            
            if (!policy.enforceHistory) {
                return { isValid: true };
            }

            // Get password history for the user
            const history = await PasswordHistory.getHistoryByUserId(userId, policy.historyCount);
            
            // Check each historical password
            for (const record of history) {
                const isReused = await verifyPassword(newPassword, record.passwordHash);
                if (isReused) {
                    return {
                        isValid: false,
                        error: `Password cannot be one of your last ${policy.historyCount} passwords`
                    };
                }
            }

            return { isValid: true };

        } catch (error) {
            console.error('Error checking password history:', error);
            return {
                isValid: false,
                error: 'Unable to verify password history'
            };
        }
    }

    /**
     * Add a password to user's history
     */
    static async addPasswordToHistory(
        userId: number, 
        passwordHash: string
    ): Promise<void> {
        try {
            // Create history record
            const historyRecord = new PasswordHistory(
                userId,
                passwordHash,
                new Date()
            );
            await historyRecord.create();

            // Clean up old history beyond policy limit
            const policy = this.getPasswordHistoryPolicy();
            await PasswordHistory.cleanupOldHistory(userId, policy.historyCount);

        } catch (error) {
            console.error('Error adding password to history:', error);
            throw new Error('Failed to update password history');
        }
    }

    /**
     * Validate and change password with history checking and age restrictions
     */
    static async changePasswordWithHistory(
        userId: number,
        newPassword: string,
        updateUserCallback: (passwordHash: string) => Promise<void>
    ): Promise<{
        success: boolean;
        error?: string;
    }> {
        try {
            // Check if current password is old enough to be changed
            const ageCheck = await PasswordHistory.isPasswordOldEnoughToChange(userId);
            if (!ageCheck.canChange) {
                return {
                    success: false,
                    error: ageCheck.error
                };
            }

            // Check password history for reuse
            const historyCheck = await this.checkPasswordHistory(userId, newPassword);
            if (!historyCheck.isValid) {
                return {
                    success: false,
                    error: historyCheck.error
                };
            }

            // Hash the new password
            const newPasswordHash = await hashPassword(newPassword);

            // Update the user's password
            await updateUserCallback(newPasswordHash);

            // Add to password history
            await this.addPasswordToHistory(userId, newPasswordHash);

            return { success: true };

        } catch (error) {
            console.error('Error changing password with history:', error);
            return {
                success: false,
                error: 'Failed to change password'
            };
        }
    }

    /**
     * Initialize password history for a new user
     */
    static async initializePasswordHistoryForUser(
        userId: number,
        initialPasswordHash: string
    ): Promise<void> {
        await this.addPasswordToHistory(userId, initialPasswordHash);
    }

    /**
     * Get user's password history (for admin purposes)
     */
    static async getUserPasswordHistory(userId: number): Promise<Array<{
        createdAt: Date;
        id: number;
    }>> {
        try {
            const history = await PasswordHistory.getHistoryByUserId(userId);
            return history.map(record => ({
                createdAt: record.createdAt,
                id: record.id || 0
            }));
        } catch (error) {
            console.error('Error getting user password history:', error);
            return [];
        }
    }

    /**
     * Clean up old password history for all users
     */
    static async cleanupAllPasswordHistory(): Promise<void> {
        try {
            const policy = this.getPasswordHistoryPolicy();
            
            // This is a simplified cleanup - in a real system you'd get all user IDs
            // For now, we'll let the per-user cleanup handle this
            console.log(`Password history cleanup: keeping last ${policy.historyCount} passwords per user`);
        } catch (error) {
            console.error('Error cleaning up password history:', error);
        }
    }
}

// Export functions for backward compatibility
export const initializePasswordHistory = PasswordHistoryService.initializeTables;
export const checkPasswordHistory = PasswordHistoryService.checkPasswordHistory;
export const addPasswordToHistory = PasswordHistoryService.addPasswordToHistory;
export const changePasswordWithHistory = PasswordHistoryService.changePasswordWithHistory;
