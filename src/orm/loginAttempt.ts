/*
 * Login Attempt ORM model
 * Handles database operations for login attempt tracking
 */

import alasql from 'alasql';

/**
 * Login Attempt ORM model
 * Tracks login attempts for account lockout functionality
 */
export default class LoginAttempt {
    constructor(
        public username: string,
        public attemptTime: Date,
        public isSuccessful: boolean,
        public ipAddress?: string,
        public id?: number
    ) {}

    /**
     * Create a new login attempt record in the database
     */
    async create(): Promise<void> {
        const result = await alasql.promise(`
            INSERT INTO login_attempts (username, attempt_time, is_successful, ip_address)
            VALUES (?, ?, ?, ?)
        `, [this.username, this.attemptTime.toISOString(), this.isSuccessful, this.ipAddress || null]);
        
        if (result && result.insertId) {
            this.id = result.insertId;
        }
    }

    /**
     * Get recent login attempts for a username within specified time window
     */
    static async getRecentAttemptsByUsername(
        username: string, 
        timeWindowMinutes = 60
    ): Promise<LoginAttempt[]> {
        const cutoffTime = new Date();
        cutoffTime.setMinutes(cutoffTime.getMinutes() - timeWindowMinutes);

        const results = await alasql.promise(`
            SELECT * FROM login_attempts 
            WHERE username = ? AND attempt_time >= ?
            ORDER BY attempt_time DESC
        `, [username, cutoffTime.toISOString()]);

        return results.map((row: {
            username: string;
            attempt_time: string;
            is_successful: boolean;
            ip_address?: string;
            id: number;
        }) => new LoginAttempt(
            row.username,
            new Date(row.attempt_time),
            row.is_successful,
            row.ip_address,
            row.id
        ));
    }

    /**
     * Get failed login attempts for a username within specified time window
     */
    static async getFailedAttemptsByUsername(
        username: string, 
        timeWindowMinutes = 60
    ): Promise<LoginAttempt[]> {
        const cutoffTime = new Date();
        cutoffTime.setMinutes(cutoffTime.getMinutes() - timeWindowMinutes);

        const results = await alasql.promise(`
            SELECT * FROM login_attempts 
            WHERE username = ? AND attempt_time >= ? AND is_successful = ?
            ORDER BY attempt_time DESC
        `, [username, cutoffTime.toISOString(), false]);

        return results.map((row: {
            username: string;
            attempt_time: string;
            is_successful: boolean;
            ip_address?: string;
            id: number;
        }) => new LoginAttempt(
            row.username,
            new Date(row.attempt_time),
            row.is_successful,
            row.ip_address,
            row.id
        ));
    }

    /**
     * Clean up old login attempt records (older than specified days)
     */
    static async cleanupOldAttempts(daysToKeep = 7): Promise<void> {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

        await alasql.promise(`
            DELETE FROM login_attempts 
            WHERE attempt_time < ?
        `, [cutoffDate.toISOString()]);
    }

    /**
     * Get all recent login attempts within specified time window
     */
    static async getRecentAttemptsByTimeframe(timeWindowMinutes = 60): Promise<LoginAttempt[]> {
        const cutoffTime = new Date();
        cutoffTime.setMinutes(cutoffTime.getMinutes() - timeWindowMinutes);

        const results = await alasql.promise(`
            SELECT * FROM login_attempts 
            WHERE attempt_time >= ?
            ORDER BY attempt_time DESC
        `, [cutoffTime.toISOString()]);

        return results.map((row: {
            id: number;
            username: string;
            attempt_time: string;
            is_successful: boolean;
            ip_address?: string;
        }) => new LoginAttempt(
            row.username,
            new Date(row.attempt_time),
            row.is_successful,
            row.ip_address,
            row.id
        ));
    }

    /**
     * Initialize the login attempts table
     */
    static async initializeTable(): Promise<void> {
        await alasql.promise(`
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
            await alasql.promise(`
                CREATE INDEX idx_login_attempts_username_time 
                ON login_attempts(username, attempt_time);
            `);
        } catch (error) {
            // Index might already exist, ignore error
        }
    }
}
