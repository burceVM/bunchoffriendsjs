import { Request } from 'express';
import ValidationFailureLog from '../orm/validationFailureLog';

/**
 * ValidationLogger - Service for logging input validation failures
 * Provides centralized logging for all validation failures to enable admin monitoring
 */
export class ValidationLogger {
    /**
     * Log a validation failure
     * @param req - Express request object
     * @param fieldName - Name of the field that failed validation
     * @param fieldValue - The value that failed validation (truncated for security)
     * @param validationType - Type of validation that failed (e.g., 'length', 'format', 'range')
     * @param errorMessage - User-friendly error message
     */
    static async logValidationFailure(
        req: Request,
        fieldName: string,
        fieldValue: string,
        validationType: string,
        errorMessage: string
    ): Promise<void> {
        try {
            // Extract user info if available
            const userId = req.session?.user?.id || null;
            const username = req.session?.user?.username || null;
            
            // Get client information
            const endpoint = req.originalUrl || req.url;
            const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';
            const userAgent = req.get('User-Agent') || 'unknown';
            
            // Truncate field value for security and storage efficiency
            const truncatedValue = fieldValue.length > 100 ? 
                fieldValue.substring(0, 100) + '...' : 
                fieldValue;
            
            // Create and save the log entry
            const log = new ValidationFailureLog(
                null, // id - will be auto-generated
                userId,
                username,
                fieldName,
                truncatedValue,
                validationType,
                errorMessage,
                endpoint,
                ipAddress,
                userAgent
            );
            
            await log.create();
        } catch (error) {
            // Don't let logging failures disrupt the application
            console.error('Failed to log validation failure:', error);
        }
    }

    /**
     * Log multiple validation failures at once
     * @param req - Express request object
     * @param failures - Array of validation failure details
     */
    static async logMultipleValidationFailures(
        req: Request,
        failures: Array<{
            fieldName: string;
            fieldValue: string;
            validationType: string;
            errorMessage: string;
        }>
    ): Promise<void> {
        // Log each failure individually to maintain detailed tracking
        for (const failure of failures) {
            await this.logValidationFailure(
                req,
                failure.fieldName,
                failure.fieldValue,
                failure.validationType,
                failure.errorMessage
            );
        }
    }

    /**
     * Log validation failure for length constraint violations
     */
    static async logLengthValidationFailure(
        req: Request,
        fieldName: string,
        fieldValue: string,
        maxLength: number,
        errorMessage: string
    ): Promise<void> {
        await this.logValidationFailure(
            req,
            fieldName,
            fieldValue,
            `length_max_${maxLength}`,
            errorMessage
        );
    }

    /**
     * Log validation failure for format/pattern constraint violations
     */
    static async logFormatValidationFailure(
        req: Request,
        fieldName: string,
        fieldValue: string,
        pattern: string,
        errorMessage: string
    ): Promise<void> {
        await this.logValidationFailure(
            req,
            fieldName,
            fieldValue,
            `format_${pattern}`,
            errorMessage
        );
    }

    /**
     * Log validation failure for empty/required field violations
     */
    static async logRequiredFieldFailure(
        req: Request,
        fieldName: string,
        errorMessage: string
    ): Promise<void> {
        await this.logValidationFailure(
            req,
            fieldName,
            '',
            'required',
            errorMessage
        );
    }

    /**
     * Log validation failure for range constraint violations
     */
    static async logRangeValidationFailure(
        req: Request,
        fieldName: string,
        fieldValue: string,
        min: number | null,
        max: number | null,
        errorMessage: string
    ): Promise<void> {
        const rangeType = min !== null && max !== null ? 
            `range_${min}_${max}` : 
            min !== null ? `min_${min}` : `max_${max}`;
            
        await this.logValidationFailure(
            req,
            fieldName,
            fieldValue,
            rangeType,
            errorMessage
        );
    }
}
