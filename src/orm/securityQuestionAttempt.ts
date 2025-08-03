/*
 * Security Question Attempt ORM model
 * Handles database operations for security question attempt tracking
 */

import alasql from 'alasql';

/**
 * Security Question Attempt ORM model
 * Tracks attempts to answer security questions for rate limiting
 */
export default class SecurityQuestionAttempt {
    constructor(
        public userId: number,
        public attemptTime: Date,
        public wasSuccessful: boolean,
        public ipAddress?: string,
        public id?: number
    ) {}

    /**
     * Create a new attempt record in the database
     */
    async create(): Promise<void> {
        const result = await alasql.promise(`
            INSERT INTO security_question_attempts (user_id, attempt_time, was_successful, ip_address)
            VALUES (?, ?, ?, ?)
        `, [this.userId, this.attemptTime.toISOString(), this.wasSuccessful, this.ipAddress || null]);
        
        if (result && result.insertId) {
            this.id = result.insertId;
        }
    }

    /**
     * Get recent attempts for a user within specified time window
     */
    static async getRecentAttemptsByUserId(
        userId: number, 
        timeWindowHours = 1
    ): Promise<SecurityQuestionAttempt[]> {
        const cutoffTime = new Date();
        cutoffTime.setHours(cutoffTime.getHours() - timeWindowHours);

        const results = await alasql.promise(`
            SELECT * FROM security_question_attempts 
            WHERE user_id = ? AND attempt_time >= ?
            ORDER BY attempt_time DESC
        `, [userId, cutoffTime.toISOString()]);

        return results.map((row: {
            user_id: number;
            attempt_time: string;
            was_successful: boolean;
            ip_address?: string;
            id: number;
        }) => new SecurityQuestionAttempt(
            row.user_id,
            new Date(row.attempt_time),
            row.was_successful,
            row.ip_address,
            row.id
        ));
    }

    /**
     * Clean up old attempt records (older than specified days)
     */
    static async cleanupOldAttempts(daysToKeep = 30): Promise<void> {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

        await alasql.promise(`
            DELETE FROM security_question_attempts 
            WHERE attempt_time < ?
        `, [cutoffDate.toISOString()]);
    }

    /**
     * Initialize the security question attempts table
     */
    static async initializeTable(): Promise<void> {
        await alasql.promise(`
            CREATE TABLE IF NOT EXISTS security_question_attempts(
                id serial primary key not null autoincrement,
                user_id integer not null,
                attempt_time datetime not null,
                was_successful boolean not null,
                ip_address text,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        `);
    }
}
