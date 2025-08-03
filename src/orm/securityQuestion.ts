/*
 * Security Question ORM model
 * Handles database operations for user security questions
 */

import alasql from 'alasql';

/**
 * User Security Question ORM model
 * Represents a user's configured security question and hashed answer
 */
export default class UserSecurityQuestion {
    constructor(
        public userId: number,
        public questionId: string,
        public answerHash: string,
        public createdAt: Date,
        public id?: number
    ) {}

    /**
     * Create a new security question entry in the database
     */
    async create(): Promise<void> {
        const result = await alasql.promise(`
            INSERT INTO user_security_questions (user_id, question_id, answer_hash, created_at)
            VALUES (?, ?, ?, ?)
        `, [this.userId, this.questionId, this.answerHash, this.createdAt.toISOString()]);
        
        if (result && result.insertId) {
            this.id = result.insertId;
        }
    }

    /**
     * Find security question by user ID
     */
    static async byUserId(userId: number): Promise<UserSecurityQuestion | null> {
        const results = await alasql.promise(`
            SELECT * FROM user_security_questions WHERE user_id = ?
        `, [userId]);

        if (results.length === 0) {
            return null;
        }

        const row = results[0];
        return new UserSecurityQuestion(
            row.user_id,
            row.question_id,
            row.answer_hash,
            new Date(row.created_at),
            row.id
        );
    }

    /**
     * Update security question for a user (replaces existing)
     */
    static async updateForUser(
        userId: number, 
        questionId: string, 
        answerHash: string
    ): Promise<void> {
        // Remove existing security question
        await alasql.promise(`
            DELETE FROM user_security_questions WHERE user_id = ?
        `, [userId]);

        // Create new one
        const securityQuestion = new UserSecurityQuestion(
            userId,
            questionId,
            answerHash,
            new Date()
        );
        await securityQuestion.create();
    }

    /**
     * Delete security question by user ID
     */
    static async deleteByUserId(userId: number): Promise<void> {
        await alasql.promise(`
            DELETE FROM user_security_questions WHERE user_id = ?
        `, [userId]);
    }

    /**
     * Initialize the security questions table
     */
    static async initializeTable(): Promise<void> {
        await alasql.promise(`
            CREATE TABLE IF NOT EXISTS user_security_questions(
                id serial primary key not null autoincrement,
                user_id integer not null,
                question_id text not null,
                answer_hash text not null,
                created_at datetime not null,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        `);
    }
}
