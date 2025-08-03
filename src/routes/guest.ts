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
import { 
    getLockoutStatus, 
    recordLoginAttempt, 
    getLockoutPolicy 
} from '../utils/accountLockout';

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

        // Fail securely: validate input length and format
        if (!username || username.length === 0 || username.length > 50) {
            // Record failed attempt even for invalid input to prevent enumeration
            await recordLoginAttempt(username || 'invalid', false, ipAddress);
            res.render('index', { view: 'index', messages: [AUTH_ERROR_MESSAGE]});
            return;
        }

        if (!password || password.length === 0 || password.length > 200) {
            await recordLoginAttempt(username, false, ipAddress);
            res.render('index', { view: 'index', messages: [AUTH_ERROR_MESSAGE]});
            return;
        }

        // Check account lockout status BEFORE attempting authentication
        const lockoutStatus = await getLockoutStatus(username);
        if (lockoutStatus.isLocked) {
            // Account is currently locked - record attempt and show lockout message
            await recordLoginAttempt(username, false, ipAddress);
            
            const lockoutPolicy = getLockoutPolicy();
            const remainingMinutes = lockoutStatus.remainingLockoutMinutes || lockoutPolicy.lockoutDurationMinutes;
            
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
            await recordLoginAttempt(username, false, ipAddress);
            res.render('index', { view: 'index', messages: [GENERIC_ERROR_MESSAGE]});
            return;
        }

        // Attempt authentication
        const user = await User.byLogin(username, password);
        
        // Fail securely: validate user object structure before storing in session
        if (user != null && 
            typeof user === 'object' &&
            typeof user.id === 'number' &&
            typeof user.username === 'string' &&
            typeof user.role === 'string' &&
            user.id > 0 &&
            user.username.length > 0) {
            
            // Successful login - record success and clear any lockout
            await recordLoginAttempt(username, true, ipAddress);
            
            req.session.user = user;
            res.redirect(303, 'home');
        } else {
            // Failed authentication - record failed attempt
            await recordLoginAttempt(username, false, ipAddress);
            
            // Check if this failure triggers a lockout
            const newLockoutStatus = await getLockoutStatus(username);
            if (newLockoutStatus.isLocked && !lockoutStatus.isLocked) {
                // Account just became locked
                const lockoutPolicy = getLockoutPolicy();
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
            await recordLoginAttempt(username || 'error', false, ipAddress);
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
    res.render('signup', { view: 'signup', passwordRequirements });
});

// Create a new account
// Checks for empty field values
// Prevents duplicate account creation
route.post('/signup', async (req, res) => {
    // Validate the input
    const username = String(req.body.username || '').toLowerCase();
    const password = String(req.body.password || '');
    const fullName = String(req.body.fullName || '');

    const messages = [];
    const passwordRequirements = getPasswordRequirements();

    if (username.length == 0)
        messages.push('Username cannot be empty');
    if (password.length == 0)
        messages.push('Password cannot be empty');
    if (fullName.length == 0)
        messages.push('Full name cannot be empty');

    // Comprehensive password validation
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.isValid) {
        messages.push(...passwordValidation.errors);
    }

    try {
        // Are there any validation errors?
        if (messages.length == 0) {
            // No errors - so create the new user with secure password hashing
            await User.createUser(username, password, fullName, 'normie');
            return res.render('signup_success', { view: 'signup_success' });
        }
    } catch (e) {
        // Don't reveal specific error details that might indicate username availability
        console.error('User creation error:', e);
        messages.push('Account creation failed. Please try again or choose a different username.');
    }
    res.render('signup', { view: 'signup', username, password, fullName, messages, passwordRequirements });
});

// Remove the currently logged in user from the session
route.get('/logout', (req, res) => {
    delete req.session.user;
    res.redirect(303, '/');
});

export default route;