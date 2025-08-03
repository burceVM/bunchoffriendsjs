/*
 * Password Reset Token ORM model
 * Handles database operations for password reset tokens
 */

import alasql from 'alasql';

/**
 * Password Reset Token ORM model
 * Represents a secure token for password reset operations
 */
export default class PasswordResetToken {
    constructor(
        public token: string,
        public userId: number,
        public expiresAt: Date,
        public isUsed: boolean,
        public securityQuestionVerified: boolean,
        public createdAt: Date,
        public id?: number
    ) {}

    /**
     * Create a new token in the database
     */
    async create(): Promise<void> {
        const result = await alasql.promise(`
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
    }

    /**
     * Find token by token string
     */
    static async byToken(token: string): Promise<PasswordResetToken | null> {
        const results = await alasql.promise(`
            SELECT * FROM password_reset_tokens WHERE token = ?
        `, [token]);

        if (results.length === 0) {
            return null;
        }

        const row = results[0];
        return new PasswordResetToken(
            row.token,
            row.user_id,
            new Date(row.expires_at),
            row.is_used,
            row.security_question_verified,
            new Date(row.created_at),
            row.id
        );
    }

    /**
     * Mark token as used
     */
    async markAsUsed(): Promise<void> {
        if (!this.id) {
            throw new Error('Token must have an ID to be marked as used');
        }

        this.isUsed = true;
        await alasql.promise(`
            UPDATE password_reset_tokens SET is_used = ? WHERE id = ?
        `, [true, this.id]);
    }

    /**
     * Check if token is valid (not expired, not used)
     */
    isValid(): boolean {
        const now = new Date();
        return !this.isUsed && this.expiresAt > now && this.securityQuestionVerified;
    }

    /**
     * Clean up expired tokens
     */
    static async cleanupExpiredTokens(): Promise<void> {
        const now = new Date();
        await alasql.promise(`
            DELETE FROM password_reset_tokens 
            WHERE expires_at < ? OR is_used = ?
        `, [now.toISOString(), true]);
    }

    /**
     * Initialize the password reset tokens table
     */
    static async initializeTable(): Promise<void> {
        await alasql.promise(`
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
    }
}
