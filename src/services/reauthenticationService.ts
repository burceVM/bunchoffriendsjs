/*
 * Reauthentication service for verifying user identity before critical operations
 * Requires users to re-enter their current password for sensitive actions
 */

import User from '../orm/user';
import alasql from 'alasql';

/**
 * Service for handling user re-authentication during critical operations
 */
export class ReauthenticationService {
    private static readonly REAUTHENTICATION_TIMEOUT_MINUTES = 5;

    /**
     * Verify user's current password for re-authentication
     */
    static async verifyCurrentPassword(
        username: string,
        currentPassword: string
    ): Promise<{
        isValid: boolean;
        error?: string;
        userId?: number;
    }> {
        try {
            // Validate inputs
            if (!username || !currentPassword) {
                return {
                    isValid: false,
                    error: 'Username and current password are required'
                };
            }

            // Attempt to authenticate user with current credentials
            const user = await User.byLogin(username, currentPassword);
            
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

        } catch (error) {
            console.error('Re-authentication error:', error);
            return {
                isValid: false,
                error: 'Authentication verification failed'
            };
        }
    }

    /**
     * Create a re-authentication token that expires after a short time
     */
    static async createReauthToken(
        userId: number,
        operation: string
    ): Promise<{
        success: boolean;
        token?: string;
        error?: string;
    }> {
        try {
            // Generate a simple token (in production, use crypto.randomBytes)
            const token = `reauth_${userId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            const expiresAt = new Date(Date.now() + (this.REAUTHENTICATION_TIMEOUT_MINUTES * 60 * 1000));

            // Store token in database (create table if needed)
            await this.initializeReauthTable();

            await alasql.promise(`
                INSERT INTO reauthentication_tokens (user_id, token, operation, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?)
            `, [userId, token, operation, expiresAt.toISOString(), new Date().toISOString()]);

            return {
                success: true,
                token
            };

        } catch (error) {
            console.error('Error creating reauth token:', error);
            return {
                success: false,
                error: 'Failed to create authentication token'
            };
        }
    }

    /**
     * Verify and consume a re-authentication token
     */
    static async verifyAndConsumeReauthToken(
        userId: number,
        token: string,
        operation: string
    ): Promise<{
        isValid: boolean;
        error?: string;
    }> {
        try {
            if (!token || !operation) {
                return {
                    isValid: false,
                    error: 'Authentication token and operation are required'
                };
            }

            // Find the token
            const tokenRecords = await alasql.promise(`
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
                await alasql.promise(`
                    DELETE FROM reauthentication_tokens 
                    WHERE id = ?
                `, [tokenRecord.id]);

                return {
                    isValid: false,
                    error: 'Authentication token has expired. Please re-authenticate.'
                };
            }

            // Token is valid, consume it (delete it so it can't be reused)
            await alasql.promise(`
                DELETE FROM reauthentication_tokens 
                WHERE id = ?
            `, [tokenRecord.id]);

            return { isValid: true };

        } catch (error) {
            console.error('Error verifying reauth token:', error);
            return {
                isValid: false,
                error: 'Token verification failed'
            };
        }
    }

    /**
     * Clean up expired re-authentication tokens
     */
    static async cleanupExpiredTokens(): Promise<void> {
        try {
            const now = new Date().toISOString();
            await alasql.promise(`
                DELETE FROM reauthentication_tokens 
                WHERE expires_at < ?
            `, [now]);
        } catch (error) {
            console.error('Error cleaning up expired reauth tokens:', error);
        }
    }

    /**
     * Initialize the re-authentication tokens table
     */
    static async initializeReauthTable(): Promise<void> {
        try {
            await alasql.promise(`
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
                await alasql.promise(`
                    CREATE INDEX idx_reauthentication_tokens_user_id 
                    ON reauthentication_tokens(user_id);
                `);
            } catch (error) {
                // Index might already exist, ignore error
            }

            try {
                await alasql.promise(`
                    CREATE INDEX idx_reauthentication_tokens_expires_at 
                    ON reauthentication_tokens(expires_at);
                `);
            } catch (error) {
                // Index might already exist, ignore error
            }

        } catch (error) {
            console.error('Error initializing reauthentication table:', error);
            throw error;
        }
    }

    /**
     * Get the re-authentication timeout in minutes
     */
    static getReauthTimeout(): number {
        return this.REAUTHENTICATION_TIMEOUT_MINUTES;
    }
}
