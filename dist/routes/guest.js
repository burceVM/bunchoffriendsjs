"use strict";
/*
 * WARNING!
 *
 * This project is intentionally insecure.
 *
 * DO NOT use in production.
 *
 * It is designed for educational purposes - to teach common vulnerabilities in web applications.
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
const express_promise_router_1 = __importDefault(require("express-promise-router"));
const orm_1 = require("../orm");
const passwordSecurity_1 = require("../utils/passwordSecurity");
const accountLockoutService_1 = require("../services/accountLockoutService");
// Standardized authentication error message to prevent username enumeration
const AUTH_ERROR_MESSAGE = 'Invalid username and/or password';
const GENERIC_ERROR_MESSAGE = 'Authentication failed. Please try again.';
const route = express_promise_router_1.default();
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
route.post('/login', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b;
    try {
        // Fail securely: validate input parameters
        const username = String(req.body.username || '').toLowerCase().trim();
        const password = String(req.body.password || '');
        const ipAddress = req.ip || ((_a = req.socket) === null || _a === void 0 ? void 0 : _a.remoteAddress) || 'unknown';
        // Fail securely: validate input length and format
        if (!username || username.length === 0 || username.length > 50) {
            // Record failed attempt even for invalid input to prevent enumeration
            yield accountLockoutService_1.AccountLockoutService.recordLoginAttempt(username || 'invalid', false, ipAddress);
            res.render('index', { view: 'index', messages: [AUTH_ERROR_MESSAGE] });
            return;
        }
        if (!password || password.length === 0 || password.length > 200) {
            yield accountLockoutService_1.AccountLockoutService.recordLoginAttempt(username, false, ipAddress);
            res.render('index', { view: 'index', messages: [AUTH_ERROR_MESSAGE] });
            return;
        }
        // Check account lockout status BEFORE attempting authentication
        const lockoutStatus = yield accountLockoutService_1.AccountLockoutService.getLockoutStatus(username);
        if (lockoutStatus.isLocked) {
            // Account is currently locked - record attempt and show lockout message
            yield accountLockoutService_1.AccountLockoutService.recordLoginAttempt(username, false, ipAddress);
            const lockoutPolicy = accountLockoutService_1.AccountLockoutService.getLockoutPolicy();
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
        // Fail securely: ensure session is properly initialized
        if (!req.session || typeof req.session !== 'object') {
            yield accountLockoutService_1.AccountLockoutService.recordLoginAttempt(username, false, ipAddress);
            res.render('index', { view: 'index', messages: [GENERIC_ERROR_MESSAGE] });
            return;
        }
        // Attempt authentication
        const user = yield orm_1.User.byLogin(username, password);
        // Fail securely: validate user object structure before storing in session
        if (user != null &&
            typeof user === 'object' &&
            typeof user.id === 'number' &&
            typeof user.username === 'string' &&
            typeof user.role === 'string' &&
            user.id > 0 &&
            user.username.length > 0) {
            // Successful login - record success and clear any lockout
            yield accountLockoutService_1.AccountLockoutService.recordLoginAttempt(username, true, ipAddress);
            req.session.user = user;
            res.redirect(303, 'home');
        }
        else {
            // Failed authentication - record failed attempt
            yield accountLockoutService_1.AccountLockoutService.recordLoginAttempt(username, false, ipAddress);
            // Check if this failure triggers a lockout
            const newLockoutStatus = yield accountLockoutService_1.AccountLockoutService.getLockoutStatus(username);
            if (newLockoutStatus.isLocked && !lockoutStatus.isLocked) {
                // Account just became locked
                const lockoutPolicy = accountLockoutService_1.AccountLockoutService.getLockoutPolicy();
                res.render('index', {
                    view: 'index',
                    messages: [
                        `Too many failed login attempts. Account temporarily locked for ${lockoutPolicy.lockoutDurationMinutes} minutes.`
                    ]
                });
            }
            else {
                // Regular failed attempt - use standardized error message
                res.render('index', { view: 'index', messages: [AUTH_ERROR_MESSAGE] });
            }
        }
    }
    catch (error) {
        // Fail securely: any error in login process denies access
        console.error('Login error:', error);
        // Still try to record the attempt if possible
        try {
            const username = String(req.body.username || '').toLowerCase().trim();
            const ipAddress = req.ip || ((_b = req.socket) === null || _b === void 0 ? void 0 : _b.remoteAddress) || 'unknown';
            yield accountLockoutService_1.AccountLockoutService.recordLoginAttempt(username || 'error', false, ipAddress);
        }
        catch (recordError) {
            console.error('Failed to record login attempt during error:', recordError);
        }
        res.render('index', { view: 'index', messages: [GENERIC_ERROR_MESSAGE] });
        return;
    }
}));
// Form for signing up for a new account
route.get('/signup', (_req, res) => {
    const passwordRequirements = passwordSecurity_1.getPasswordRequirements();
    const securityQuestions = passwordResetService_1.PasswordResetService.getSecurityQuestions();
    res.render('signup', { view: 'signup', passwordRequirements, securityQuestions });
});
// Create a new account
// Checks for empty field values
// Prevents duplicate account creation
route.post('/signup', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    // Validate the input
    const username = String(req.body.username || '').toLowerCase();
    const password = String(req.body.password || '');
    const fullName = String(req.body.fullName || '');
    const securityQuestionId = String(req.body.securityQuestionId || '');
    const securityAnswer = String(req.body.securityAnswer || '');
    const messages = [];
    const passwordRequirements = passwordSecurity_1.getPasswordRequirements();
    const securityQuestions = passwordResetService_1.PasswordResetService.getSecurityQuestions();
    if (username.length == 0)
        messages.push('Username cannot be empty');
    if (password.length == 0)
        messages.push('Password cannot be empty');
    if (fullName.length == 0)
        messages.push('Full name cannot be empty');
    if (securityQuestionId.length == 0)
        messages.push('Please select a security question');
    if (securityAnswer.length == 0)
        messages.push('Security answer cannot be empty');
    // Comprehensive password validation
    const passwordValidation = passwordSecurity_1.validatePasswordStrength(password);
    if (!passwordValidation.isValid) {
        messages.push(...passwordValidation.errors);
    }
    // Validate security question and answer
    if (securityQuestionId && securityAnswer) {
        const selectedQuestion = securityQuestions.find(q => q.id === securityQuestionId);
        if (!selectedQuestion) {
            messages.push('Invalid security question selected');
        }
        else {
            // Validate the security answer directly
            const cleanAnswer = securityAnswer.trim().toUpperCase();
            if (cleanAnswer.length < selectedQuestion.minAnswerLength) {
                messages.push(`Security answer must be at least ${selectedQuestion.minAnswerLength} characters long`);
            }
            if (cleanAnswer.length > selectedQuestion.maxAnswerLength) {
                messages.push(`Security answer must be no more than ${selectedQuestion.maxAnswerLength} characters long`);
            }
            if (selectedQuestion.requiresNumeric && !/\d/.test(cleanAnswer)) {
                messages.push('Security answer must contain at least one number');
            }
        }
    }
    try {
        // Are there any validation errors?
        if (messages.length == 0) {
            // No errors - so create the new user with secure password hashing
            const newUser = yield orm_1.User.createUser(username, password, fullName, 'normie');
            // Set up security question for the new user
            if (newUser && newUser.id) {
                const securitySetup = yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(newUser.id, securityQuestionId, securityAnswer);
                if (!securitySetup.success) {
                    console.error('Failed to set up security question for new user:', securitySetup.errors);
                    // Continue with signup - security question can be set up later
                }
            }
            return res.render('signup_success', { view: 'signup_success' });
        }
    }
    catch (e) {
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
}));
// Remove the currently logged in user from the session
route.get('/logout', (req, res) => {
    delete req.session.user;
    res.redirect(303, '/');
});
//--------------------------------------------------------
// Password Reset Routes
//--------------------------------------------------------
// Import password reset utilities
const passwordResetService_1 = require("../services/passwordResetService");
// Show setup security question form (for authenticated users)
route.get('/setup-security-question', (_req, res) => __awaiter(void 0, void 0, void 0, function* () {
    // This route should be moved to secured routes, but adding here for now
    const questions = passwordResetService_1.PasswordResetService.getSecurityQuestions();
    res.render('security_question_setup', {
        view: 'security_question_setup',
        questions
    });
}));
// Handle security question setup
route.post('/setup-security-question', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const questions = passwordResetService_1.PasswordResetService.getSecurityQuestions();
    let messages = [];
    try {
        // This should be from authenticated session, but using mock for now
        const userId = 1; // TODO: Get from session
        const questionId = String(req.body.questionId || '').trim();
        const answer = String(req.body.answer || '').trim();
        if (!questionId || !answer) {
            messages.push('Please select a question and provide an answer');
        }
        else {
            const result = yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(userId, questionId, answer);
            if (result.success) {
                res.render('security_question_setup', {
                    view: 'security_question_setup',
                    questions,
                    success: 'Security question setup successfully!'
                });
                return;
            }
            else {
                messages = result.errors;
            }
        }
    }
    catch (error) {
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
}));
// Show forgot password form
route.get('/forgot-password', (_req, res) => {
    res.render('forgot_password', { view: 'forgot_password' });
});
// Handle forgot password submission
route.post('/forgot-password', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const messages = [];
    const username = String(req.body.username || '').toLowerCase().trim();
    try {
        if (!username) {
            messages.push('Please enter your username');
        }
        else {
            // Find user by username
            const user = yield orm_1.User.byUsername(username);
            if (!user || !user.id) {
                // Don't reveal if user exists - security best practice
                res.render('forgot_password', {
                    view: 'forgot_password',
                    success: 'If this username exists and has a security question set up, you will be redirected to answer it.'
                });
                return;
            }
            // Check if user has security question set up
            const securityQuestion = yield passwordResetService_1.PasswordResetService.getUserSecurityQuestion(user.id);
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
    }
    catch (error) {
        console.error('Error in forgot password:', error);
        messages.push('An error occurred. Please try again.');
    }
    res.render('forgot_password', {
        view: 'forgot_password',
        messages,
        username
    });
}));
// Show security question verification
route.get('/verify-security-question', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const username = String(req.query.username || '').toLowerCase().trim();
    try {
        if (!username) {
            res.redirect(303, '/forgot-password');
            return;
        }
        const user = yield orm_1.User.byUsername(username);
        if (!user || typeof user.id !== 'number') {
            res.redirect(303, '/forgot-password');
            return;
        }
        const securityQuestion = yield passwordResetService_1.PasswordResetService.getUserSecurityQuestion(user.id);
        if (!securityQuestion) {
            res.redirect(303, '/forgot-password');
            return;
        }
        res.render('verify_security_question', {
            view: 'verify_security_question',
            username,
            securityQuestion: securityQuestion.question,
            questionHint: securityQuestion.hint,
            attemptsRemaining: 3
        });
    }
    catch (error) {
        console.error('Error showing security question:', error);
        res.redirect(303, '/forgot-password');
    }
}));
// Handle security question verification
route.post('/verify-security-question', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _c, _d;
    const username = String(req.body.username || '').toLowerCase().trim();
    const answer = String(req.body.answer || '').trim();
    const ipAddress = req.ip || ((_c = req.socket) === null || _c === void 0 ? void 0 : _c.remoteAddress) || 'unknown';
    const messages = [];
    try {
        if (!username || !answer) {
            messages.push('Please provide your username and answer');
            res.redirect(303, '/forgot-password');
            return;
        }
        const user = yield orm_1.User.byUsername(username);
        if (!user || typeof user.id !== 'number') {
            res.redirect(303, '/forgot-password');
            return;
        }
        const securityQuestion = yield passwordResetService_1.PasswordResetService.getUserSecurityQuestion(user.id);
        if (!securityQuestion) {
            res.redirect(303, '/forgot-password');
            return;
        }
        // Verify the security answer
        const verification = yield passwordResetService_1.PasswordResetService.verifyUserSecurityAnswer(user.id, answer, ipAddress);
        if (verification.isRateLimited) {
            res.render('verify_security_question', {
                view: 'verify_security_question',
                username,
                securityQuestion: securityQuestion.question,
                questionHint: securityQuestion.hint,
                rateLimited: true,
                nextAttemptTime: (_d = verification.nextAttemptTime) === null || _d === void 0 ? void 0 : _d.toLocaleString()
            });
            return;
        }
        if (!verification.success) {
            messages.push('Incorrect answer. Please try again.');
            res.render('verify_security_question', {
                view: 'verify_security_question',
                username,
                securityQuestion: securityQuestion.question,
                questionHint: securityQuestion.hint,
                messages,
                attemptsRemaining: 2 // TODO: Get actual remaining attempts
            });
            return;
        }
        // Generate password reset token
        const token = yield passwordResetService_1.PasswordResetService.generatePasswordResetToken(user.id);
        // Redirect to password reset form
        res.redirect(303, `/reset-password?token=${token}`);
    }
    catch (error) {
        console.error('Error verifying security question:', error);
        messages.push('An error occurred. Please try again.');
        res.render('verify_security_question', {
            view: 'verify_security_question',
            username,
            messages
        });
    }
}));
// Show password reset form
route.get('/reset-password', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const token = String(req.query.token || '').trim();
    try {
        if (!token) {
            res.redirect(303, '/forgot-password');
            return;
        }
        const verification = yield passwordResetService_1.PasswordResetService.verifyPasswordResetToken(token);
        if (!verification.isValid) {
            let message = 'Invalid or expired password reset link.';
            if (verification.tokenRecord) {
                const isExpired = verification.tokenRecord.expiresAt <= new Date();
                const isUsed = verification.tokenRecord.isUsed;
                if (isExpired) {
                    message = 'Password reset link has expired. Please start over.';
                }
                else if (isUsed) {
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
    }
    catch (error) {
        console.error('Error showing password reset form:', error);
        res.redirect(303, '/forgot-password');
    }
}));
// Handle password reset submission
route.post('/reset-password', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const token = String(req.body.token || '').trim();
    const password = String(req.body.password || '');
    const confirmPassword = String(req.body.confirmPassword || '');
    let messages = [];
    try {
        if (!token) {
            res.redirect(303, '/forgot-password');
            return;
        }
        const verification = yield passwordResetService_1.PasswordResetService.verifyPasswordResetToken(token);
        if (!verification.isValid || !verification.userId) {
            res.redirect(303, '/forgot-password');
            return;
        }
        // Validate passwords
        if (!password || !confirmPassword) {
            messages.push('Please enter and confirm your new password');
        }
        else if (password !== confirmPassword) {
            messages.push('Passwords do not match');
        }
        else {
            // Validate password strength
            const passwordValidation = passwordSecurity_1.validatePasswordStrength(password);
            if (!passwordValidation.isValid) {
                messages = passwordValidation.errors;
            }
            else {
                // Update user password
                const user = yield orm_1.User.byId(verification.userId);
                if (user) {
                    yield user.changePassword(password);
                    // Mark token as used
                    yield passwordResetService_1.PasswordResetService.markTokenAsUsed(token);
                    // Clean up expired tokens
                    yield passwordResetService_1.PasswordResetService.cleanupExpiredData(); // Reset login attempts for this user
                    yield accountLockoutService_1.AccountLockoutService.recordLoginAttempt(user.username, true, 'password-reset');
                    res.render('index', {
                        view: 'index',
                        messages: ['Password reset successfully! You can now log in with your new password.']
                    });
                    return;
                }
                else {
                    messages.push('User not found');
                }
            }
        }
    }
    catch (error) {
        console.error('Error resetting password:', error);
        messages.push('An error occurred while resetting password. Please try again.');
    }
    res.render('reset_password', {
        view: 'reset_password',
        token,
        messages
    });
}));
exports.default = route;
//# sourceMappingURL=guest.js.map