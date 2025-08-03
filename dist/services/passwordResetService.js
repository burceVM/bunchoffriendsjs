"use strict";
/*
 * Password reset service with proper ORM implementation
 * Implements secure password reset flow with rate limiting
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
exports.cleanupExpiredTokens = exports.markTokenAsUsed = exports.verifyPasswordResetToken = exports.generatePasswordResetToken = exports.verifyUserSecurityAnswer = exports.getUserSecurityQuestion = exports.setupUserSecurityQuestion = exports.initializePasswordReset = exports.PasswordResetService = void 0;
const crypto_1 = __importDefault(require("crypto"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const securityQuestion_1 = __importDefault(require("../orm/securityQuestion"));
const securityQuestionAttempt_1 = __importDefault(require("../orm/securityQuestionAttempt"));
const passwordResetToken_1 = __importDefault(require("../orm/passwordResetToken"));
/**
 * Password reset service class
 * Encapsulates all password reset related operations
 */
class PasswordResetService {
    /**
     * Initialize password reset database tables
     */
    static initializeTables() {
        return __awaiter(this, void 0, void 0, function* () {
            yield securityQuestion_1.default.initializeTable();
            yield securityQuestionAttempt_1.default.initializeTable();
            yield passwordResetToken_1.default.initializeTable();
        });
    }
    /**
     * Get available security questions
     */
    static getSecurityQuestions() {
        return [
            {
                id: 'first_pet_name',
                question: 'What was the name of your first pet?',
                minAnswerLength: 2,
                maxAnswerLength: 50,
                requiresNumeric: false,
                hint: 'Enter the name of your first pet'
            },
            {
                id: 'childhood_phone_last_four',
                question: 'What were the last four digits of your childhood telephone number?',
                minAnswerLength: 4,
                maxAnswerLength: 4,
                requiresNumeric: true,
                hint: 'Enter exactly 4 digits'
            },
            {
                id: 'first_school_name',
                question: 'What was the name of your first school?',
                minAnswerLength: 3,
                maxAnswerLength: 100,
                requiresNumeric: false,
                hint: 'Enter the full name of your first school'
            },
            {
                id: 'mother_maiden_name',
                question: 'What is your mother\'s maiden name?',
                minAnswerLength: 2,
                maxAnswerLength: 50,
                requiresNumeric: false,
                hint: 'Enter your mother\'s maiden name'
            },
            {
                id: 'birth_city',
                question: 'In what city were you born?',
                minAnswerLength: 2,
                maxAnswerLength: 50,
                requiresNumeric: false,
                hint: 'Enter the city where you were born'
            }
        ];
    }
    /**
     * Validate security question answer meets entropy requirements
     */
    static validateSecurityAnswer(question, answer) {
        const errors = [];
        const cleanAnswer = answer.trim().toUpperCase();
        // Length validation
        if (cleanAnswer.length < question.minAnswerLength) {
            errors.push(`Answer must be at least ${question.minAnswerLength} characters long`);
        }
        if (cleanAnswer.length > question.maxAnswerLength) {
            errors.push(`Answer must be no more than ${question.maxAnswerLength} characters long`);
        }
        // Numeric requirement validation
        if (question.requiresNumeric && !/\d/.test(cleanAnswer)) {
            errors.push('Answer must contain at least one number');
        }
        return {
            isValid: errors.length === 0,
            errors
        };
    }
    /**
     * Hash security answer using bcrypt with high work factor
     */
    static hashSecurityAnswer(answer) {
        return __awaiter(this, void 0, void 0, function* () {
            // Normalize answer (uppercase, trim) before hashing
            const normalizedAnswer = answer.trim().toUpperCase();
            // Use high work factor for security questions (slower than regular passwords)
            const saltRounds = 14;
            return yield bcrypt_1.default.hash(normalizedAnswer, saltRounds);
        });
    }
    /**
     * Verify security answer against stored hash
     */
    static verifySecurityAnswer(answer, hash) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Normalize answer same way as during creation
                const normalizedAnswer = answer.trim().toUpperCase();
                return yield bcrypt_1.default.compare(normalizedAnswer, hash);
            }
            catch (error) {
                console.error('Error verifying security answer:', error);
                return false;
            }
        });
    }
    /**
     * Check if user is rate limited for security question attempts
     */
    static isSecurityQuestionRateLimited(attempts) {
        const now = new Date();
        const oneHour = 60 * 60 * 1000;
        const recentAttempts = attempts.filter(attempt => (now.getTime() - attempt.attemptTime.getTime()) < oneHour);
        const failedAttempts = recentAttempts.filter(attempt => !attempt.wasSuccessful);
        // Allow 3 attempts per hour
        const maxAttempts = 3;
        if (failedAttempts.length >= maxAttempts) {
            const oldestFailedAttempt = failedAttempts.sort((a, b) => a.attemptTime.getTime() - b.attemptTime.getTime())[0];
            return {
                isLimited: true,
                nextAttemptTime: new Date(oldestFailedAttempt.attemptTime.getTime() + oneHour),
                attemptsRemaining: 0
            };
        }
        return {
            isLimited: false,
            attemptsRemaining: maxAttempts - failedAttempts.length
        };
    }
    /**
     * Set up security question for a user
     */
    static setupUserSecurityQuestion(userId, questionId, answer) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const questions = this.getSecurityQuestions();
                const question = questions.find((q) => q.id === questionId);
                if (!question) {
                    return { success: false, errors: ['Invalid security question'] };
                }
                // Validate answer
                const validation = this.validateSecurityAnswer(question, answer);
                if (!validation.isValid) {
                    return { success: false, errors: validation.errors };
                }
                // Hash the answer
                const answerHash = yield this.hashSecurityAnswer(answer);
                // Update security question using ORM
                yield securityQuestion_1.default.updateForUser(userId, questionId, answerHash);
                return { success: true, errors: [] };
            }
            catch (error) {
                console.error('Error setting up security question:', error);
                return { success: false, errors: ['Failed to set up security question'] };
            }
        });
    }
    /**
     * Get user's security question
     */
    static getUserSecurityQuestion(userId) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const userQuestion = yield securityQuestion_1.default.byUserId(userId);
                if (!userQuestion) {
                    return null;
                }
                const questions = this.getSecurityQuestions();
                return questions.find((q) => q.id === userQuestion.questionId) || null;
            }
            catch (error) {
                console.error('Error getting user security question:', error);
                return null;
            }
        });
    }
    /**
     * Verify user's security answer with rate limiting
     */
    static verifyUserSecurityAnswer(userId, answer, ipAddress) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Check rate limiting first
                const recentAttempts = yield securityQuestionAttempt_1.default.getRecentAttemptsByUserId(userId);
                const rateLimitCheck = this.isSecurityQuestionRateLimited(recentAttempts.map(attempt => ({
                    userId: attempt.userId,
                    attemptTime: attempt.attemptTime,
                    wasSuccessful: attempt.wasSuccessful,
                    ipAddress: attempt.ipAddress
                })));
                if (rateLimitCheck.isLimited) {
                    return {
                        success: false,
                        isRateLimited: true,
                        nextAttemptTime: rateLimitCheck.nextAttemptTime,
                        attemptsRemaining: rateLimitCheck.attemptsRemaining
                    };
                }
                // Get user's security question
                const userQuestion = yield securityQuestion_1.default.byUserId(userId);
                if (!userQuestion) {
                    // Log failed attempt
                    const attempt = new securityQuestionAttempt_1.default(userId, new Date(), false, ipAddress);
                    yield attempt.create();
                    return {
                        success: false,
                        isRateLimited: false,
                        attemptsRemaining: rateLimitCheck.attemptsRemaining
                    };
                }
                // Verify the answer
                const isCorrect = yield this.verifySecurityAnswer(answer, userQuestion.answerHash);
                // Log the attempt
                const attempt = new securityQuestionAttempt_1.default(userId, new Date(), isCorrect, ipAddress);
                yield attempt.create();
                return {
                    success: isCorrect,
                    isRateLimited: false,
                    attemptsRemaining: isCorrect ? undefined : (rateLimitCheck.attemptsRemaining || 1) - 1
                };
            }
            catch (error) {
                console.error('Error verifying security answer:', error);
                return {
                    success: false,
                    isRateLimited: false
                };
            }
        });
    }
    /**
     * Generate secure password reset token
     */
    static generatePasswordResetToken(userId) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Generate cryptographically secure token
                const token = crypto_1.default.randomBytes(32).toString('hex');
                const expiresAt = new Date();
                expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour expiry
                // Create token record
                const resetToken = new passwordResetToken_1.default(token, userId, expiresAt, false, // not used
                true, // security question verified
                new Date());
                yield resetToken.create();
                return token;
            }
            catch (error) {
                console.error('Error generating password reset token:', error);
                throw new Error('Failed to generate reset token');
            }
        });
    }
    /**
     * Verify password reset token
     */
    static verifyPasswordResetToken(token) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const tokenRecord = yield passwordResetToken_1.default.byToken(token);
                if (!tokenRecord || !tokenRecord.isValid()) {
                    return { isValid: false };
                }
                return {
                    isValid: true,
                    userId: tokenRecord.userId,
                    tokenRecord
                };
            }
            catch (error) {
                console.error('Error verifying password reset token:', error);
                return { isValid: false };
            }
        });
    }
    /**
     * Mark token as used
     */
    static markTokenAsUsed(token) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const tokenRecord = yield passwordResetToken_1.default.byToken(token);
                if (!tokenRecord) {
                    return false;
                }
                yield tokenRecord.markAsUsed();
                return true;
            }
            catch (error) {
                console.error('Error marking token as used:', error);
                return false;
            }
        });
    }
    /**
     * Clean up expired tokens and old attempts
     */
    static cleanupExpiredData() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield passwordResetToken_1.default.cleanupExpiredTokens();
                yield securityQuestionAttempt_1.default.cleanupOldAttempts(30); // Keep 30 days
            }
            catch (error) {
                console.error('Error cleaning up expired data:', error);
            }
        });
    }
}
exports.PasswordResetService = PasswordResetService;
// Export functions for backward compatibility
exports.initializePasswordReset = PasswordResetService.initializeTables;
exports.setupUserSecurityQuestion = PasswordResetService.setupUserSecurityQuestion;
exports.getUserSecurityQuestion = PasswordResetService.getUserSecurityQuestion;
exports.verifyUserSecurityAnswer = PasswordResetService.verifyUserSecurityAnswer;
exports.generatePasswordResetToken = PasswordResetService.generatePasswordResetToken;
exports.verifyPasswordResetToken = PasswordResetService.verifyPasswordResetToken;
exports.markTokenAsUsed = PasswordResetService.markTokenAsUsed;
exports.cleanupExpiredTokens = PasswordResetService.cleanupExpiredData;
//# sourceMappingURL=passwordResetService.js.map