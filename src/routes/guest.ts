/*
 * WARNING!
 *
 * This project is intentionally insecure.
 *
 * DO NOT use in production.
 *
 * It is designed for educational purposes - to teach common vulnerabilities in web applications.
 */

import Router from 'express-promise-router';
import { User } from '../orm';
import { validatePasswordStrength, getPasswordRequirements } from '../utils/passwordSecurity';
import { AccountLockoutService } from '../services/accountLockoutService';
import { LoginTrackingService } from '../services/loginTrackingService';
import { PasswordResetService } from '../services/passwordResetService';
import { ValidationLogger } from '../services/validationLogger';

// Standardized authentication error message to prevent username enumeration
const AUTH_ERROR_MESSAGE = 'Invalid username and/or password';
const GENERIC_ERROR_MESSAGE = 'Authentication failed. Please try again.';

const route = Router();

//--------------------------------------------------------
// Routes that are accessible by all users / guests
//--------------------------------------------------------

// Show the login form
route.get('/', (_req, res) => {
    res.render('index', { view: 'index' });
});

// Handle the login data posted from the home page 
// Usernames are case insensitive
// Implements account lockout to prevent brute force attacks
route.post('/login', async (req, res) => {
    try {
        // Fail securely: validate input parameters
        const username = String(req.body.username || '').toLowerCase().trim();
        const password = String(req.body.password || '');
        const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';

        // Fail securely: validate input length and format with user-friendly messages
        if (!username || username.length === 0) {
            // Log validation failure
            await ValidationLogger.logRequiredFieldFailure(req, 'username', 'Please enter your username.');
            // Record failed attempt even for invalid input to prevent enumeration
            await AccountLockoutService.recordLoginAttempt(username || 'invalid', false, ipAddress);
            res.render('index', { view: 'index', messages: ['Please enter your username.']});
            return;
        }
        
        if (username.length > 50) {
            // Log validation failure
            await ValidationLogger.logLengthValidationFailure(req, 'username', username, 50, 'Username is too long. Please enter a valid username.');
            await AccountLockoutService.recordLoginAttempt(username, false, ipAddress);
            res.render('index', { view: 'index', messages: ['Username is too long. Please enter a valid username.']});
            return;
        }

        if (!password || password.length === 0) {
            // Log validation failure
            await ValidationLogger.logRequiredFieldFailure(req, 'password', 'Please enter your password.');
            await AccountLockoutService.recordLoginAttempt(username, false, ipAddress);
            res.render('index', { view: 'index', messages: ['Please enter your password.']});
            return;
        }
        
        if (password.length > 200) {
            // Log validation failure
            await ValidationLogger.logLengthValidationFailure(req, 'password', '[REDACTED]', 200, 'Password is too long. Please enter a valid password.');
            await AccountLockoutService.recordLoginAttempt(username, false, ipAddress);
            res.render('index', { view: 'index', messages: ['Password is too long. Please enter a valid password.']});
            return;
        }

        // Check account lockout status BEFORE attempting authentication
        const lockoutStatus = await AccountLockoutService.getLockoutStatus(username);
        if (lockoutStatus.isLocked) {
            // Account is currently locked - record attempt and show lockout message
            await AccountLockoutService.recordLoginAttempt(username, false, ipAddress);
            
            const lockoutPolicy = AccountLockoutService.getLockoutPolicy();
            const remainingMinutes = lockoutStatus.lockoutUntil ? 
                Math.ceil((lockoutStatus.lockoutUntil.getTime() - Date.now()) / (1000 * 60)) : 
                lockoutPolicy.lockoutDurationMinutes;
            
            res.render('index', { 
                view: 'index', 
                messages: [
                    'Account temporarily locked due to multiple failed login attempts. ' +
                    `Please try again in ${remainingMinutes} minute${remainingMinutes !== 1 ? 's' : ''}.`
                ]
            });
            return;
        }

        // Fail securely: ensure session is properly initialized and secure
        if (!req.session || typeof req.session !== 'object') {
            await AccountLockoutService.recordLoginAttempt(username, false, ipAddress);
            res.render('index', { view: 'index', messages: [GENERIC_ERROR_MESSAGE]});
            return;
        }

        // Business rule: prevent session hijacking by validating session integrity
        if (req.session.user) {
            // User already logged in - enforce business rule: one session per user
            delete req.session.user;
            delete req.session.lastLoginInfo;
        }

        // Attempt authentication
        const user = await User.byLogin(username, password);
        
        // Get client information for tracking
        const userAgent = req.get('User-Agent') || 'unknown';
        
        // Fail securely: validate user object structure before storing in session
        if (user != null && 
            typeof user === 'object' &&
            typeof user.id === 'number' &&
            typeof user.username === 'string' &&
            typeof user.role === 'string' &&
            typeof user.fullName === 'string' &&
            user.id > 0 &&
            user.username.length > 0 &&
            user.role.length > 0 &&
            // Business rule: ensure role is valid
            ['normie', 'moderator', 'admin'].includes(user.role.toLowerCase()) &&
            // Business rule: prevent escalation through malformed data
            user.username.toLowerCase() === username.toLowerCase()) {
            
            // Successful login - record success and clear any lockout
            await AccountLockoutService.recordLoginAttempt(username, true, ipAddress);
            
            // Record successful login in tracking system
            await LoginTrackingService.recordLoginAttempt(username, ipAddress, userAgent, true, user.id);
            
            // Get last login information for this user
            const lastLoginInfo = await LoginTrackingService.getLastLoginInfo(username, true);
            
            // Business rule: secure session establishment with validated user data
            // Create clean user object for session to prevent data contamination
            const sessionUser = {
                id: user.id,
                username: user.username.toLowerCase(), // Normalize for consistency
                role: user.role.toLowerCase(),
                fullName: user.fullName
            } as User;
            
            req.session.user = sessionUser;
            req.session.lastLoginInfo = lastLoginInfo; // Store for display on home page
            
            // Business rule: immediate redirect to prevent replay attacks
            res.redirect(303, 'home');
        } else {
            // Failed authentication - record failed attempt
            await AccountLockoutService.recordLoginAttempt(username, false, ipAddress);
            
            // Record failed login in tracking system
            const userAgent = req.get('User-Agent') || 'unknown';
            await LoginTrackingService.recordLoginAttempt(username, ipAddress, userAgent, false);
            
            // Check if this failure triggers a lockout
            const newLockoutStatus = await AccountLockoutService.getLockoutStatus(username);
            if (newLockoutStatus.isLocked && !lockoutStatus.isLocked) {
                // Account just became locked
                const lockoutPolicy = AccountLockoutService.getLockoutPolicy();
                res.render('index', { 
                    view: 'index', 
                    messages: [
                        `Too many failed login attempts. Account temporarily locked for ${lockoutPolicy.lockoutDurationMinutes} minutes.`
                    ]
                });
            } else {
                // Regular failed attempt - use standardized error message
                res.render('index', { view: 'index', messages: [AUTH_ERROR_MESSAGE]});
            }
        }
    } catch (error) {
        // Fail securely: any error in login process denies access
        console.error('Login error:', error);
        
        // Still try to record the attempt if possible
        try {
            const username = String(req.body.username || '').toLowerCase().trim();
            const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';
            await AccountLockoutService.recordLoginAttempt(username || 'error', false, ipAddress);
        } catch (recordError) {
            console.error('Failed to record login attempt during error:', recordError);
        }
        
        res.render('index', { view: 'index', messages: [GENERIC_ERROR_MESSAGE]});
        return;
    }
});

// Form for signing up for a new account
route.get('/signup', (_req, res) => {
    const passwordRequirements = getPasswordRequirements();
    const securityQuestions = PasswordResetService.getSecurityQuestions();
    res.render('signup', { view: 'signup', passwordRequirements, securityQuestions });
});

// Create a new account
// Checks for empty field values
// Prevents duplicate account creation
route.post('/signup', async (req, res) => {
    // Validate the input
    const username = String(req.body.username || '').toLowerCase();
    const password = String(req.body.password || '');
    const fullName = String(req.body.fullName || '');
    const securityQuestionId = String(req.body.securityQuestionId || '');
    const securityAnswer = String(req.body.securityAnswer || '');

    const messages = [];
    const passwordRequirements = getPasswordRequirements();
    const securityQuestions = PasswordResetService.getSecurityQuestions();

    // Enhanced input validation with helpful error messages
    if (username.length == 0) {
        await ValidationLogger.logRequiredFieldFailure(req, 'username', 'Username cannot be empty');
        messages.push('Username cannot be empty');
    } else if (username.length > 50) {
        await ValidationLogger.logLengthValidationFailure(req, 'username', username, 50, 'Username must be 50 characters or less');
        messages.push('Username must be 50 characters or less');
    } else if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
        await ValidationLogger.logFormatValidationFailure(req, 'username', username, 'alphanumeric_with_dots_underscores_dashes', 'Username can only contain letters, numbers, dots, underscores, and dashes');
        messages.push('Username can only contain letters, numbers, dots, underscores, and dashes');
    }
        
    if (password.length == 0) {
        await ValidationLogger.logRequiredFieldFailure(req, 'password', 'Password cannot be empty');
        messages.push('Password cannot be empty');
    }
        
    if (fullName.length == 0) {
        await ValidationLogger.logRequiredFieldFailure(req, 'fullName', 'Full name cannot be empty');
        messages.push('Full name cannot be empty');
    } else if (fullName.length > 100) {
        await ValidationLogger.logLengthValidationFailure(req, 'fullName', fullName, 100, 'Full name must be 100 characters or less');
        messages.push('Full name must be 100 characters or less');
    }
        
    if (securityQuestionId.length == 0) {
        await ValidationLogger.logRequiredFieldFailure(req, 'securityQuestionId', 'Please select a security question');
        messages.push('Please select a security question');
    }
        
    if (securityAnswer.length == 0) {
        await ValidationLogger.logRequiredFieldFailure(req, 'securityAnswer', 'Security answer cannot be empty');
        messages.push('Security answer cannot be empty');
    } else if (securityAnswer.length > 500) {
        await ValidationLogger.logLengthValidationFailure(req, 'securityAnswer', securityAnswer, 500, 'Security answer must be 500 characters or less');
        messages.push('Security answer must be 500 characters or less');
    }

    // Comprehensive password validation
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.isValid) {
        // Log each password validation failure
        for (const error of passwordValidation.errors) {
            await ValidationLogger.logValidationFailure(req, 'password', '[REDACTED]', 'password_strength', error);
        }
        messages.push(...passwordValidation.errors);
    }

    // Validate security question and answer
    if (securityQuestionId && securityAnswer) {
        const selectedQuestion = securityQuestions.find(q => q.id === securityQuestionId);
        if (!selectedQuestion) {
            await ValidationLogger.logValidationFailure(req, 'securityQuestionId', securityQuestionId, 'invalid_selection', 'Invalid security question selected');
            messages.push('Invalid security question selected');
        } else {
            // Validate the security answer directly
            const cleanAnswer = securityAnswer.trim().toUpperCase();
            
            if (cleanAnswer.length < selectedQuestion.minAnswerLength) {
                const errorMsg = `Security answer must be at least ${selectedQuestion.minAnswerLength} characters long`;
                await ValidationLogger.logLengthValidationFailure(req, 'securityAnswer', securityAnswer, selectedQuestion.minAnswerLength, errorMsg);
                messages.push(errorMsg);
            }
            if (cleanAnswer.length > selectedQuestion.maxAnswerLength) {
                const errorMsg = `Security answer must be no more than ${selectedQuestion.maxAnswerLength} characters long`;
                await ValidationLogger.logLengthValidationFailure(req, 'securityAnswer', securityAnswer, selectedQuestion.maxAnswerLength, errorMsg);
                messages.push(errorMsg);
            }
            if (selectedQuestion.requiresNumeric && !/\d/.test(cleanAnswer)) {
                const errorMsg = 'Security answer must contain at least one number';
                await ValidationLogger.logFormatValidationFailure(req, 'securityAnswer', securityAnswer, 'numeric_required', errorMsg);
                messages.push(errorMsg);
            }
        }
    }

    try {
        // Are there any validation errors?
        if (messages.length == 0) {
            // No errors - so create the new user with secure password hashing
            const newUser = await User.createUser(username, password, fullName, 'normie');
            
            // Set up security question for the new user
            if (newUser && newUser.id) {
                const securitySetup = await PasswordResetService.setupUserSecurityQuestion(
                    newUser.id, 
                    securityQuestionId, 
                    securityAnswer
                );
                
                if (!securitySetup.success) {
                    console.error('Failed to set up security question for new user:', securitySetup.errors);
                    // Continue with signup - security question can be set up later
                }
            }
            
            return res.render('signup_success', { view: 'signup_success' });
        }
    } catch (e) {
        // Don't reveal specific error details that might indicate username availability
        console.error('User creation error:', e);
        messages.push('Account creation failed. Please try again or choose a different username.');
    }
    res.render('signup', { 
        view: 'signup', 
        username, 
        password, 
        fullName, 
        securityQuestionId,
        securityAnswer,
        messages, 
        passwordRequirements, 
        securityQuestions 
    });
});

// Remove the currently logged in user from the session
route.get('/logout', (req, res) => {
    try {
        // Business rule: secure session cleanup to prevent data leakage
        if (req.session) {
            // Clear all session data securely
            delete req.session.user;
            delete req.session.lastLoginInfo;
            
            // Clear any other sensitive session data that might exist
            const sessionKeys = Object.keys(req.session);
            sessionKeys.forEach(key => {
                if (key !== 'cookie') {
                    delete (req.session as Record<string, unknown>)[key];
                }
            });
        }
        
        // Business rule: always redirect to prevent information disclosure
        res.redirect(303, '/');
    } catch (error) {
        // Fail securely: any error still logs out and redirects
        console.error('Logout error:', error);
        res.redirect(303, '/');
    }
});

//--------------------------------------------------------
// Password Reset Routes
//--------------------------------------------------------

// Show setup security question form (for authenticated users)
route.get('/setup-security-question', async (req, res) => {
    // Business rule: enforce authentication for security-sensitive operations
    if (!req.session?.user?.id) {
        res.redirect(303, '/');
        return;
    }
    
    try {
        const questions = PasswordResetService.getSecurityQuestions();
        res.render('security_question_setup', { 
            view: 'security_question_setup', 
            questions 
        });
    } catch (error) {
        console.error('Error loading security questions:', error);
        res.redirect(303, '/');
    }
});

// Handle security question setup
route.post('/setup-security-question', async (req, res) => {
    // Business rule: enforce authentication for security-sensitive operations
    if (!req.session?.user?.id) {
        res.redirect(303, '/');
        return;
    }
    
    const questions = PasswordResetService.getSecurityQuestions();
    let messages: string[] = [];
    
    try {
        // Business rule: use authenticated user's ID, not arbitrary values
        const userId = req.session.user.id;
        const questionId = String(req.body.questionId || '').trim();
        const answer = String(req.body.answer || '').trim();

        // Business rule: validate input before processing
        if (!questionId || !answer) {
            messages.push('Please select a question and provide an answer');
        } else if (!userId || typeof userId !== 'number' || userId <= 0) {
            // Fail securely: invalid user ID
            res.redirect(303, '/');
            return;
        } else {
            const result = await PasswordResetService.setupUserSecurityQuestion(userId, questionId, answer);
            
            if (result.success) {
                res.render('security_question_setup', { 
                    view: 'security_question_setup', 
                    questions,
                    success: 'Security question setup successfully!' 
                });
                return;
            } else {
                messages = result.errors;
            }
        }
    } catch (error) {
        console.error('Error setting up security question:', error);
        messages.push('Failed to setup security question. Please try again.');
    }

    res.render('security_question_setup', { 
        view: 'security_question_setup', 
        questions,
        messages,
        selectedQuestionId: req.body.questionId,
        answer: req.body.answer
    });
});

// Show forgot password form
route.get('/forgot-password', (_req, res) => {
    res.render('forgot_password', { view: 'forgot_password' });
});

// Handle forgot password submission
route.post('/forgot-password', async (req, res) => {
    const messages: string[] = [];
    const username = String(req.body.username || '').toLowerCase().trim();

    try {
        // Enhanced validation with helpful messages
        if (!username || username.length === 0) {
            await ValidationLogger.logRequiredFieldFailure(req, 'username', 'Please enter your username');
            messages.push('Please enter your username');
        } else if (username.length > 50) {
            await ValidationLogger.logLengthValidationFailure(req, 'username', username, 50, 'Username is too long. Please enter a valid username.');
            messages.push('Username is too long. Please enter a valid username.');
        } else if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
            await ValidationLogger.logFormatValidationFailure(req, 'username', username, 'alphanumeric_with_dots_underscores_dashes', 'Username contains invalid characters. Please use only letters, numbers, dots, underscores, and dashes.');
            messages.push('Username contains invalid characters. Please use only letters, numbers, dots, underscores, and dashes.');
        } else {
            // Find user by username
            const user = await User.byUsername(username);
            
            if (!user || !user.id) {
                // Don't reveal if user exists - security best practice
                res.render('forgot_password', { 
                    view: 'forgot_password',
                    success: 'If this username exists and has a security question set up, you will be redirected to answer it.'
                });
                return;
            }

            // Check if user has security question set up
            const securityQuestion = await PasswordResetService.getUserSecurityQuestion(user.id);
            
            if (!securityQuestion) {
                // Don't reveal specific reason - security best practice
                res.render('forgot_password', { 
                    view: 'forgot_password',
                    success: 'If this username exists and has a security question set up, you will be redirected to answer it.'
                });
                return;
            }

            // Redirect to security question verification
            res.redirect(303, `/verify-security-question?username=${encodeURIComponent(username)}`);
            return;
        }
    } catch (error) {
        console.error('Error in forgot password:', error);
        messages.push('An error occurred. Please try again.');
    }

    res.render('forgot_password', { 
        view: 'forgot_password', 
        messages,
        username 
    });
});

// Show security question verification
route.get('/verify-security-question', async (req, res) => {
    const username = String(req.query.username || '').toLowerCase().trim();

    try {
        // Business rule: validate input format first
        if (!username || username.length === 0 || username.length > 50) {
            res.redirect(303, '/forgot-password');
            return;
        }

        // Business rule: rate limit security question requests by IP
        // const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';
        // TODO: Implement IP-based rate limiting for security questions

        const user = await User.byUsername(username);
        if (!user || typeof user.id !== 'number' || user.id <= 0) {
            // Fail securely: don't reveal if user exists
            res.redirect(303, '/forgot-password');
            return;
        }

        const securityQuestion = await PasswordResetService.getUserSecurityQuestion(user.id);
        if (!securityQuestion || !securityQuestion.question) {
            // Fail securely: don't reveal if user has security question
            res.redirect(303, '/forgot-password');
            return;
        }

        res.render('verify_security_question', {
            view: 'verify_security_question',
            username,
            securityQuestion: securityQuestion.question,
            questionHint: securityQuestion.hint || '',
            attemptsRemaining: 3
        });

    } catch (error) {
        console.error('Error showing security question:', error);
        // Fail securely: any error redirects to start
        res.redirect(303, '/forgot-password');
    }
});

// Handle security question verification
route.post('/verify-security-question', async (req, res) => {
    const username = String(req.body.username || '').toLowerCase().trim();
    const answer = String(req.body.answer || '').trim();
    const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';
    const messages: string[] = [];

    try {
        // Business rule: validate input format and length with helpful messages  
        if (!username || username.length === 0) {
            await ValidationLogger.logRequiredFieldFailure(req, 'username', 'Please enter your username');
            messages.push('Please enter your username');
            res.render('verify_security_question', {
                view: 'verify_security_question',
                messages,
                username: '',
                securityQuestion: '',
                questionHint: '',
                attemptsRemaining: 3
            });
            return;
        }
        
        if (username.length > 50) {
            await ValidationLogger.logLengthValidationFailure(req, 'username', username, 50, 'Username is too long');
            messages.push('Username is too long');
            res.render('verify_security_question', {
                view: 'verify_security_question',
                messages,
                username: '',
                securityQuestion: '',
                questionHint: '',
                attemptsRemaining: 3
            });
            return;
        }
        
        if (!answer || answer.length === 0) {
            await ValidationLogger.logRequiredFieldFailure(req, 'answer', 'Please provide your security answer');
            messages.push('Please provide your security answer');
            res.redirect(303, '/forgot-password');
            return;
        }
        
        if (answer.length > 500) {
            await ValidationLogger.logLengthValidationFailure(req, 'answer', answer, 500, 'Security answer is too long');
            messages.push('Security answer is too long');
            res.redirect(303, '/forgot-password');
            return;
        }

        const user = await User.byUsername(username);
        if (!user || typeof user.id !== 'number' || user.id <= 0) {
            // Fail securely: don't reveal if user exists
            res.redirect(303, '/forgot-password');
            return;
        }

        const securityQuestion = await PasswordResetService.getUserSecurityQuestion(user.id);
        if (!securityQuestion || !securityQuestion.question) {
            // Fail securely: don't reveal security question status
            res.redirect(303, '/forgot-password');
            return;
        }

        // Verify the security answer with proper rate limiting
        const verification = await PasswordResetService.verifyUserSecurityAnswer(user.id, answer, ipAddress);

        if (verification.isRateLimited) {
            res.render('verify_security_question', {
                view: 'verify_security_question',
                username,
                securityQuestion: securityQuestion.question,
                questionHint: securityQuestion.hint || '',
                rateLimited: true,
                nextAttemptTime: verification.nextAttemptTime?.toLocaleString()
            });
            return;
        }

        if (!verification.success) {
            messages.push('Incorrect answer. Please try again.');
            res.render('verify_security_question', {
                view: 'verify_security_question',
                username,
                securityQuestion: securityQuestion.question,
                questionHint: securityQuestion.hint || '',
                messages,
                attemptsRemaining: 2 // TODO: Get actual remaining attempts
            });
            return;
        }

        // Business rule: generate secure token only after successful verification
        const token = await PasswordResetService.generatePasswordResetToken(user.id);
        if (!token || token.length === 0) {
            // Fail securely: token generation failed
            res.redirect(303, '/forgot-password');
            return;
        }
        
        // Redirect to password reset form
        res.redirect(303, `/reset-password?token=${encodeURIComponent(token)}`);

    } catch (error) {
        console.error('Error verifying security question:', error);
        // Fail securely: any error redirects to start
        res.redirect(303, '/forgot-password');
    }
});

// Show password reset form
route.get('/reset-password', async (req, res) => {
    const token = String(req.query.token || '').trim();

    try {
        if (!token) {
            res.redirect(303, '/forgot-password');
            return;
        }

        const verification = await PasswordResetService.verifyPasswordResetToken(token);
        
        if (!verification.isValid) {
            let message = 'Invalid or expired password reset link.';
            if (verification.tokenRecord) {
                const isExpired = verification.tokenRecord.expiresAt <= new Date();
                const isUsed = verification.tokenRecord.isUsed;
                
                if (isExpired) {
                    message = 'Password reset link has expired. Please start over.';
                } else if (isUsed) {
                    message = 'Password reset link has already been used.';
                }
            }
            
            res.render('forgot_password', {
                view: 'forgot_password',
                messages: [message]
            });
            return;
        }

        res.render('reset_password', {
            view: 'reset_password',
            token
        });

    } catch (error) {
        console.error('Error showing password reset form:', error);
        res.redirect(303, '/forgot-password');
    }
});

// Handle password reset submission
route.post('/reset-password', async (req, res) => {
    const token = String(req.body.token || '').trim();
    const password = String(req.body.password || '');
    const confirmPassword = String(req.body.confirmPassword || '');
    let messages: string[] = [];

    try {
        if (!token) {
            res.redirect(303, '/forgot-password');
            return;
        }

        const verification = await PasswordResetService.verifyPasswordResetToken(token);
        
        if (!verification.isValid || !verification.userId) {
            res.redirect(303, '/forgot-password');
            return;
        }

        // Validate passwords
        if (!password || !confirmPassword) {
            messages.push('Please enter and confirm your new password');
        } else if (password !== confirmPassword) {
            messages.push('Passwords do not match');
        } else {
            // Validate password strength
            const passwordValidation = validatePasswordStrength(password);
            if (!passwordValidation.isValid) {
                messages = passwordValidation.errors;
            } else {
                // Update user password
                const user = await User.byId(verification.userId);
                if (user) {
                    await user.changePassword(password);
                    
                    // Mark token as used
                    await PasswordResetService.markTokenAsUsed(token);

                    // Clean up expired tokens
                    await PasswordResetService.cleanupExpiredData();                    // Reset login attempts for this user
                    await AccountLockoutService.recordLoginAttempt(user.username, true, 'password-reset');
                    
                    res.render('index', {
                        view: 'index',
                        messages: ['Password reset successfully! You can now log in with your new password.']
                    });
                    return;
                } else {
                    messages.push('User not found');
                }
            }
        }
    } catch (error) {
        console.error('Error resetting password:', error);
        messages.push('An error occurred while resetting password. Please try again.');
    }

    res.render('reset_password', {
        view: 'reset_password',
        token,
        messages
    });
});

export default route;