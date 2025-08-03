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
import { validatePasswordStrength } from '../utils/passwordSecurity';
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
            res.render('index', { view: 'index', messages: ['Invalid username or password']});
            return;
        }

        if (!password || password.length === 0 || password.length > 200) {
            res.render('index', { view: 'index', messages: ['Invalid username or password']});
            return;
        }

        // Fail securely: ensure session is properly initialized
        if (!req.session || typeof req.session !== 'object') {
            res.render('index', { view: 'index', messages: ['Session error. Please try again.']});
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
            res.render('index', { view: 'index', messages: ['Invalid username or password']});
        }
    } catch (error) {
        // Fail securely: any error in login process denies access
        console.error('Login error:', error);
        res.render('index', { view: 'index', messages: ['Login failed. Please try again.']});
        return;
    }
});

// Form for signing up for a new account
route.get('/signup', (_req, res) => {
    res.render('signup', { view: 'signup' });
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

    if (username.length == 0)
        messages.push('Username cannot be empty');
    if (password.length == 0)
        messages.push('Password cannot be empty');
    if (fullName.length == 0)
        messages.push('Full name cannot be empty');
    if (!validatePasswordStrength(password))
        messages.push('Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and one number');


    try {
        // Are there any validation errors?
        if (messages.length == 0) {
            // No errors - so create the new user with secure password hashing
            await User.createUser(username, password, fullName, 'normie');
            return res.render('signup_success', { view: 'signup_success' });
        }
    } catch (e) {
        messages.push((e as Error)?.message || 'An error occurred');
    }
    res.render('signup', { view: 'signup', username, password, fullName, messages });
});

// Remove the currently logged in user from the session
route.get('/logout', (req, res) => {
    delete req.session.user;
    res.redirect(303, '/');
});

export default route;