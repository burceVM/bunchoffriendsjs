/*
 * Password history ORM model for preventing password reuse
 * Stores previous password hashes to enforce password history policies
 */

import alasql from 'alasql';

/**
 * Password history record for tracking previous passwords
 */
export default class PasswordHistory {
    constructor(
        public userId: number,
        public passwordHash: string,
        public createdAt: Date,
        public id?: number
    ) {}

    /**
     * Create a new password history record
     */
    async create(): Promise<void> {
        const result = await alasql.promise(`
            INSERT INTO password_history (user_id, password_hash, created_at)
            VALUES (?, ?, ?)
        `, [this.userId, this.passwordHash, this.createdAt.toISOString()]);

        if (result && result.insertId) {
            this.id = result.insertId;
        }
    }

    /**
     * Get password history for a user (most recent first)
     */
    static async getHistoryByUserId(
        userId: number, 
        limit = 5
    ): Promise<PasswordHistory[]> {
        const results = await alasql.promise(`
            SELECT * FROM password_history 
            WHERE user_id = ${userId}
            ORDER BY created_at DESC
            LIMIT ${limit}
        `);

        return results.map((row: {
            id: number;
            user_id: number;
            password_hash: string;
            created_at: string;
        }) => new PasswordHistory(
            row.user_id,
            row.password_hash,
            new Date(row.created_at),
            row.id
        ));
    }

    /**
     * Check if a password has been used before by the user
     */
    static async isPasswordReused(
        userId: number, 
        newPasswordHash: string,
        historyLimit = 5
    ): Promise<boolean> {
        const history = await this.getHistoryByUserId(userId, historyLimit);
        return history.some(record => record.passwordHash === newPasswordHash);
    }

    /**
     * Clean up old password history records beyond the limit
     */
    static async cleanupOldHistory(
        userId: number, 
        keepCount = 5
    ): Promise<void> {
        // Get IDs of records to keep (most recent)
        const keepRecords = await alasql.promise(`
            SELECT id FROM password_history 
            WHERE user_id = ${userId}
            ORDER BY created_at DESC
            LIMIT ${keepCount}
        `);

        if (keepRecords.length > 0) {
            const keepIds = keepRecords.map((r: { id: number }) => r.id);
            const keepIdsStr = keepIds.join(',');
            
            await alasql.promise(`
                DELETE FROM password_history 
                WHERE user_id = ${userId} AND id NOT IN (${keepIdsStr})
            `);
        }
    }

    /**
     * Initialize the password history table
     */
    static async initializeTable(): Promise<void> {
        await alasql.promise(`
            CREATE TABLE IF NOT EXISTS password_history(
                id serial primary key not null autoincrement,
                user_id integer not null,
                password_hash text not null,
                created_at datetime not null
            );
        `);

        // Create index for performance
        try {
            await alasql.promise(`
                CREATE INDEX idx_password_history_user_id 
                ON password_history(user_id);
            `);
        } catch (error) {
            // Index might already exist, ignore error
        }

        try {
            await alasql.promise(`
                CREATE INDEX idx_password_history_created_at 
                ON password_history(created_at);
            `);
        } catch (error) {
            // Index might already exist, ignore error
        }
    }
}
