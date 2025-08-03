/*
 * Password reset service with proper ORM implementation
 * Implements secure password reset flow with rate limiting
 */

import crypto from 'crypto';
import bcrypt from 'bcrypt';
import UserSecurityQuestion from '../orm/securityQuestion';
import SecurityQuestionAttempt from '../orm/securityQuestionAttempt';
import PasswordResetToken from '../orm/passwordResetToken';

/**
 * Security question configuration
 */
export interface SecurityQuestion {
    id: string;
    question: string;
    minAnswerLength: number;
    maxAnswerLength: number;
    requiresNumeric: boolean;
    hint?: string;
}

/**
 * Password reset service class
 * Encapsulates all password reset related operations
 */
export class PasswordResetService {
    
    /**
     * Initialize password reset database tables
     */
    static async initializeTables(): Promise<void> {
        await UserSecurityQuestion.initializeTable();
        await SecurityQuestionAttempt.initializeTable();
        await PasswordResetToken.initializeTable();
    }

    /**
     * Get available security questions
     */
    static getSecurityQuestions(): SecurityQuestion[] {
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
    private static validateSecurityAnswer(question: SecurityQuestion, answer: string): {
        isValid: boolean;
        errors: string[];
    } {
        const errors: string[] = [];
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
    private static async hashSecurityAnswer(answer: string): Promise<string> {
        // Normalize answer (uppercase, trim) before hashing
        const normalizedAnswer = answer.trim().toUpperCase();
        
        // Use high work factor for security questions (slower than regular passwords)
        const saltRounds = 14;
        return await bcrypt.hash(normalizedAnswer, saltRounds);
    }

    /**
     * Verify security answer against stored hash
     */
    private static async verifySecurityAnswer(answer: string, hash: string): Promise<boolean> {
        try {
            // Normalize answer same way as during creation
            const normalizedAnswer = answer.trim().toUpperCase();
            return await bcrypt.compare(normalizedAnswer, hash);
        } catch (error) {
            console.error('Error verifying security answer:', error);
            return false;
        }
    }

    /**
     * Check if user is rate limited for security question attempts
     */
    private static isSecurityQuestionRateLimited(attempts: Array<{
        userId: number;
        attemptTime: Date;
        wasSuccessful: boolean;
        ipAddress?: string;
    }>): {
        isLimited: boolean;
        nextAttemptTime?: Date;
        attemptsRemaining?: number;
    } {
        const now = new Date();
        const oneHour = 60 * 60 * 1000;
        const recentAttempts = attempts.filter(
            attempt => (now.getTime() - attempt.attemptTime.getTime()) < oneHour
        );

        const failedAttempts = recentAttempts.filter(attempt => !attempt.wasSuccessful);
        
        // Allow 3 attempts per hour
        const maxAttempts = 3;
        
        if (failedAttempts.length >= maxAttempts) {
            const oldestFailedAttempt = failedAttempts.sort(
                (a, b) => a.attemptTime.getTime() - b.attemptTime.getTime()
            )[0];
            
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
    static async setupUserSecurityQuestion(
        userId: number, 
        questionId: string, 
        answer: string
    ): Promise<{ success: boolean; errors: string[] }> {
        try {
            const questions = this.getSecurityQuestions();
            const question = questions.find((q: SecurityQuestion) => q.id === questionId);
            
            if (!question) {
                return { success: false, errors: ['Invalid security question'] };
            }

            // Validate answer
            const validation = this.validateSecurityAnswer(question, answer);
            if (!validation.isValid) {
                return { success: false, errors: validation.errors };
            }

            // Hash the answer
            const answerHash = await this.hashSecurityAnswer(answer);

            // Update security question using ORM
            await UserSecurityQuestion.updateForUser(userId, questionId, answerHash);

            return { success: true, errors: [] };

        } catch (error) {
            console.error('Error setting up security question:', error);
            return { success: false, errors: ['Failed to set up security question'] };
        }
    }

    /**
     * Get user's security question
     */
    static async getUserSecurityQuestion(userId: number): Promise<SecurityQuestion | null> {
        try {
            const userQuestion = await UserSecurityQuestion.byUserId(userId);
            if (!userQuestion) {
                return null;
            }

            const questions = this.getSecurityQuestions();
            return questions.find((q: SecurityQuestion) => q.id === userQuestion.questionId) || null;

        } catch (error) {
            console.error('Error getting user security question:', error);
            return null;
        }
    }

    /**
     * Verify user's security answer with rate limiting
     */
    static async verifyUserSecurityAnswer(
        userId: number, 
        answer: string, 
        ipAddress?: string
    ): Promise<{
        success: boolean;
        isRateLimited: boolean;
        nextAttemptTime?: Date;
        attemptsRemaining?: number;
    }> {
        try {
            // Check rate limiting first
            const recentAttempts = await SecurityQuestionAttempt.getRecentAttemptsByUserId(userId);
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
            const userQuestion = await UserSecurityQuestion.byUserId(userId);
            if (!userQuestion) {
                // Log failed attempt
                const attempt = new SecurityQuestionAttempt(userId, new Date(), false, ipAddress);
                await attempt.create();
                
                return {
                    success: false,
                    isRateLimited: false,
                    attemptsRemaining: rateLimitCheck.attemptsRemaining
                };
            }

            // Verify the answer
            const isCorrect = await this.verifySecurityAnswer(answer, userQuestion.answerHash);

            // Log the attempt
            const attempt = new SecurityQuestionAttempt(userId, new Date(), isCorrect, ipAddress);
            await attempt.create();

            return {
                success: isCorrect,
                isRateLimited: false,
                attemptsRemaining: isCorrect ? undefined : (rateLimitCheck.attemptsRemaining || 1) - 1
            };

        } catch (error) {
            console.error('Error verifying security answer:', error);
            return {
                success: false,
                isRateLimited: false
            };
        }
    }

    /**
     * Generate secure password reset token
     */
    static async generatePasswordResetToken(userId: number): Promise<string> {
        try {
            // Generate cryptographically secure token
            const token = crypto.randomBytes(32).toString('hex');
            const expiresAt = new Date();
            expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour expiry

            // Create token record
            const resetToken = new PasswordResetToken(
                token,
                userId,
                expiresAt,
                false, // not used
                true,  // security question verified
                new Date()
            );
            
            await resetToken.create();
            return token;

        } catch (error) {
            console.error('Error generating password reset token:', error);
            throw new Error('Failed to generate reset token');
        }
    }

    /**
     * Verify password reset token
     */
    static async verifyPasswordResetToken(token: string): Promise<{
        isValid: boolean;
        userId?: number;
        tokenRecord?: PasswordResetToken;
    }> {
        try {
            const tokenRecord = await PasswordResetToken.byToken(token);
            
            if (!tokenRecord || !tokenRecord.isValid()) {
                return { isValid: false };
            }

            return {
                isValid: true,
                userId: tokenRecord.userId,
                tokenRecord
            };

        } catch (error) {
            console.error('Error verifying password reset token:', error);
            return { isValid: false };
        }
    }

    /**
     * Mark token as used
     */
    static async markTokenAsUsed(token: string): Promise<boolean> {
        try {
            const tokenRecord = await PasswordResetToken.byToken(token);
            if (!tokenRecord) {
                return false;
            }

            await tokenRecord.markAsUsed();
            return true;

        } catch (error) {
            console.error('Error marking token as used:', error);
            return false;
        }
    }

    /**
     * Clean up expired tokens and old attempts
     */
    static async cleanupExpiredData(): Promise<void> {
        try {
            await PasswordResetToken.cleanupExpiredTokens();
            await SecurityQuestionAttempt.cleanupOldAttempts(30); // Keep 30 days
        } catch (error) {
            console.error('Error cleaning up expired data:', error);
        }
    }
}

// Export functions for backward compatibility
export const initializePasswordReset = PasswordResetService.initializeTables;
export const setupUserSecurityQuestion = PasswordResetService.setupUserSecurityQuestion;
export const getUserSecurityQuestion = PasswordResetService.getUserSecurityQuestion;
export const verifyUserSecurityAnswer = PasswordResetService.verifyUserSecurityAnswer;
export const generatePasswordResetToken = PasswordResetService.generatePasswordResetToken;
export const verifyPasswordResetToken = PasswordResetService.verifyPasswordResetToken;
export const markTokenAsUsed = PasswordResetService.markTokenAsUsed;
export const cleanupExpiredTokens = PasswordResetService.cleanupExpiredData;
