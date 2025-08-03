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
import { User, Post, Friend } from '../orm';
import { allowRoles } from '../middleware/auth';
import { validatePasswordStrength, getPasswordRequirements } from '../utils/passwordSecurity';

// Standardized authentication error message to prevent information disclosure
// const AUTH_ERROR_MESSAGE = 'Invalid username and/or password';

const route = Router();

//--------------------------------------------------------
// Routes that may only be used by logged in users
//--------------------------------------------------------

// Check the session is logged in before continuing
// If the user has not logged in, redirect back to home
// Fail securely with comprehensive validation
route.use((req, res, next) => {
    try {
        // Fail securely: comprehensive authentication check
        if (!req.session || 
            req.session === null || 
            typeof req.session !== 'object' || 
            !req.session.user || 
            req.session.user === null ||
            typeof req.session.user !== 'object' ||
            !req.session.user.id ||
            !req.session.user.username ||
            typeof req.session.user.id !== 'number' ||
            typeof req.session.user.username !== 'string' ||
            req.session.user.username.trim() === '') {
            res.redirect(303, '/');
            return;
        }
        next();
    } catch (error) {
        // Fail securely: any exception denies access
        console.error('Secured route authentication error:', error);
        res.redirect(303, '/');
        return;
    }
});

// Render the home page
// Includes a list of posts by friends
// If the user is a moderator or admin, show all posts
route.get('/home', async (req, res) => {
    let posts;
    if (req.session.user?.role === 'moderator' || req.session.user?.role === 'admin') {
        posts = await Post.byWhere('1=1', 'creationDate desc'); // all posts
    } else {
        posts = await req.session.user?.findFriendPosts();
    }
    res.render('home', { ...req.session, view: 'home', posts });
});


// Show a list of current friends and people who are not yet friends
route.get('/friend_list', async (req, res) => {
    const friends = await req.session.user?.findFriends();
    const notFriends = await req.session.user?.findNotFriends();
    res.render('friend_list', { ...req.session, view: 'friend_list', friends, notFriends});
});

// Show a list of posts by the current user
route.get('/posts_me', async (req, res) => {
    const posts = await req.session.user?.findPosts();
    res.render('posts_me', { ...req.session, view: 'posts_me', posts});
});

// Create a new post and redirect back to the back parameter
// Note: the back parameter can be used for invalidated redirects
route.post('/post', async (req, res) => {
    const message = String(req.body.message || '');
    const back = String(req.body.back || 'home');
    if (req.session.user)
        await new Post(req.session.user, message, new Date(), 0).create();
    res.redirect(303, back);
});

// Add/connect to a friend based on their ID
// Note: a GET request and no CSRF protections makes CSRF possible 
route.get('/friend_add', async (req, res) => {
    const friendId = Number(req.query.friend);
    // Retrieve the new friend
    const friend = await User.byId(friendId);
    // If found, then add the new relationship/connection
    if (friend && req.session.user)
        new Friend(req.session.user, friend).create();
    res.render('friend_add', { ...req.session, view: 'friend_add', friend});
});

// Show change password form
route.get('/change-password', (req, res) => {
    if (!req.session.user) {
        return res.redirect(303, '/');
    }
    const passwordRequirements = getPasswordRequirements();
    res.render('change_password', { view: 'change_password', messages: [], passwordRequirements });
});

// Handle change password submission
route.post('/change-password', async (req, res) => {
    if (!req.session.user) {
        return res.redirect(303, '/');
    }
    const { oldPassword, newPassword } = req.body;
    const username = req.session.user.username;
    const user = await User.byLogin(username, oldPassword);
    const messages = [];
    const passwordRequirements = getPasswordRequirements();
    
    if (!user) {
        // Use standardized error message to prevent information disclosure
        messages.push('Invalid old password.');
    } else if (!newPassword || newPassword.length === 0) {
        messages.push('New password cannot be empty.');
    } else {
        // Comprehensive password validation
        const passwordValidation = validatePasswordStrength(newPassword);
        if (!passwordValidation.isValid) {
            messages.push(...passwordValidation.errors);
        } else {
            await user.changePassword(newPassword);
            messages.push('Password changed successfully.');
        }
    }
    res.render('change_password', { view: 'change_password', messages, passwordRequirements });
});

// Delete a post by ID (moderator/admin only)
route.post('/delete-post/:id', allowRoles('moderator', 'admin'), async (req, res) => {
    const postId = Number(req.params.id);
    if (!isNaN(postId)) {
        await Post.deleteById(postId);
    }
    res.redirect(303, '/home');
});

export default route;