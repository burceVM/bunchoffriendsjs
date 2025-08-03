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
route.post('/login', async (req, res) => {
    try {
        // Fail securely: validate input parameters
        const username = String(req.body.username || '').toLowerCase().trim();
        const password = String(req.body.password || '');

        // Fail securely: validate input length and format
        if (!username || username.length === 0 || username.length > 50) {
            res.render('index', { view: 'index', messages: [AUTH_ERROR_MESSAGE]});
            return;
        }

        if (!password || password.length === 0 || password.length > 200) {
            res.render('index', { view: 'index', messages: [AUTH_ERROR_MESSAGE]});
            return;
        }

        // Fail securely: ensure session is properly initialized
        if (!req.session || typeof req.session !== 'object') {
            res.render('index', { view: 'index', messages: [GENERIC_ERROR_MESSAGE]});
            return;
        }

        const user = await User.byLogin(username, password);
        
        // Fail securely: validate user object structure before storing in session
        if (user != null && 
            typeof user === 'object' &&
            typeof user.id === 'number' &&
            typeof user.username === 'string' &&
            typeof user.role === 'string' &&
            user.id > 0 &&
            user.username.length > 0) {
            
            req.session.user = user;
            res.redirect(303, 'home');
        } else {
            // Fail securely: same error message for invalid credentials and invalid user data
            res.render('index', { view: 'index', messages: [AUTH_ERROR_MESSAGE]});
        }
    } catch (error) {
        // Fail securely: any error in login process denies access
        console.error('Login error:', error);
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