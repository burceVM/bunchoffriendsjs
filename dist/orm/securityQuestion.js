"use strict";
/*
 * Security Question ORM model
 * Handles database operations for user security questions
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
 * User Security Question ORM model
 * Represents a user's configured security question and hashed answer
 */
class UserSecurityQuestion {
    constructor(userId, questionId, answerHash, createdAt, id) {
        this.userId = userId;
        this.questionId = questionId;
        this.answerHash = answerHash;
        this.createdAt = createdAt;
        this.id = id;
    }
    /**
     * Create a new security question entry in the database
     */
    create() {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield alasql_1.default.promise(`
            INSERT INTO user_security_questions (user_id, question_id, answer_hash, created_at)
            VALUES (?, ?, ?, ?)
        `, [this.userId, this.questionId, this.answerHash, this.createdAt.toISOString()]);
            if (result && result.insertId) {
                this.id = result.insertId;
            }
        });
    }
    /**
     * Find security question by user ID
     */
    static byUserId(userId) {
        return __awaiter(this, void 0, void 0, function* () {
            const results = yield alasql_1.default.promise(`
            SELECT * FROM user_security_questions WHERE user_id = ?
        `, [userId]);
            if (results.length === 0) {
                return null;
            }
            const row = results[0];
            return new UserSecurityQuestion(row.user_id, row.question_id, row.answer_hash, new Date(row.created_at), row.id);
        });
    }
    /**
     * Update security question for a user (replaces existing)
     */
    static updateForUser(userId, questionId, answerHash) {
        return __awaiter(this, void 0, void 0, function* () {
            // Remove existing security question
            yield alasql_1.default.promise(`
            DELETE FROM user_security_questions WHERE user_id = ?
        `, [userId]);
            // Create new one
            const securityQuestion = new UserSecurityQuestion(userId, questionId, answerHash, new Date());
            yield securityQuestion.create();
        });
    }
    /**
     * Delete security question by user ID
     */
    static deleteByUserId(userId) {
        return __awaiter(this, void 0, void 0, function* () {
            yield alasql_1.default.promise(`
            DELETE FROM user_security_questions WHERE user_id = ?
        `, [userId]);
        });
    }
    /**
     * Initialize the security questions table
     */
    static initializeTable() {
        return __awaiter(this, void 0, void 0, function* () {
            yield alasql_1.default.promise(`
            CREATE TABLE IF NOT EXISTS user_security_questions(
                id serial primary key not null autoincrement,
                user_id integer not null,
                question_id text not null,
                answer_hash text not null,
                created_at datetime not null,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        `);
        });
    }
}
exports.default = UserSecurityQuestion;
//# sourceMappingURL=securityQuestion.js.map