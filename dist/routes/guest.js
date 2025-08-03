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
route.post('/login', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        // Fail securely: validate input parameters
        const username = String(req.body.username || '').toLowerCase().trim();
        const password = String(req.body.password || '');
        // Fail securely: validate input length and format
        if (!username || username.length === 0 || username.length > 50) {
            res.render('index', { view: 'index', messages: [AUTH_ERROR_MESSAGE] });
            return;
        }
        if (!password || password.length === 0 || password.length > 200) {
            res.render('index', { view: 'index', messages: [AUTH_ERROR_MESSAGE] });
            return;
        }
        // Fail securely: ensure session is properly initialized
        if (!req.session || typeof req.session !== 'object') {
            res.render('index', { view: 'index', messages: [GENERIC_ERROR_MESSAGE] });
            return;
        }
        const user = yield orm_1.User.byLogin(username, password);
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
        }
        else {
            // Fail securely: same error message for invalid credentials and invalid user data
            res.render('index', { view: 'index', messages: [AUTH_ERROR_MESSAGE] });
        }
    }
    catch (error) {
        // Fail securely: any error in login process denies access
        console.error('Login error:', error);
        res.render('index', { view: 'index', messages: [GENERIC_ERROR_MESSAGE] });
        return;
    }
}));
// Form for signing up for a new account
route.get('/signup', (_req, res) => {
    const passwordRequirements = passwordSecurity_1.getPasswordRequirements();
    res.render('signup', { view: 'signup', passwordRequirements });
});
// Create a new account
// Checks for empty field values
// Prevents duplicate account creation
route.post('/signup', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    // Validate the input
    const username = String(req.body.username || '').toLowerCase();
    const password = String(req.body.password || '');
    const fullName = String(req.body.fullName || '');
    const messages = [];
    const passwordRequirements = passwordSecurity_1.getPasswordRequirements();
    if (username.length == 0)
        messages.push('Username cannot be empty');
    if (password.length == 0)
        messages.push('Password cannot be empty');
    if (fullName.length == 0)
        messages.push('Full name cannot be empty');
    // Comprehensive password validation
    const passwordValidation = passwordSecurity_1.validatePasswordStrength(password);
    if (!passwordValidation.isValid) {
        messages.push(...passwordValidation.errors);
    }
    try {
        // Are there any validation errors?
        if (messages.length == 0) {
            // No errors - so create the new user with secure password hashing
            yield orm_1.User.createUser(username, password, fullName, 'normie');
            return res.render('signup_success', { view: 'signup_success' });
        }
    }
    catch (e) {
        // Don't reveal specific error details that might indicate username availability
        console.error('User creation error:', e);
        messages.push('Account creation failed. Please try again or choose a different username.');
    }
    res.render('signup', { view: 'signup', username, password, fullName, messages, passwordRequirements });
}));
// Remove the currently logged in user from the session
route.get('/logout', (req, res) => {
    delete req.session.user;
    res.redirect(303, '/');
});
exports.default = route;
//# sourceMappingURL=guest.js.map