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
import { ReauthenticationService } from '../services/reauthenticationService';

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
    try {
        let posts: Post[] = [];
        if (req.session.user?.role === 'moderator' || req.session.user?.role === 'admin') {
            posts = await Post.byWhere('1=1', 'creationDate desc'); // all posts
        } else {
            // Create a proper User instance to call methods on
            if (req.session.user && req.session.user.id) {
                const user = await User.byId(req.session.user.id);
                if (user) {
                    posts = await user.findFriendPosts();
                }
            }
        }
        
        // Get last login info from session (set during login)
        const lastLoginInfo = req.session.lastLoginInfo;
        
        // Clear the lastLoginInfo from session after displaying it once
        if (req.session.lastLoginInfo) {
            req.session.lastLoginInfo = undefined;
        }
        
        res.render('home', { 
            ...req.session, 
            view: 'home', 
            posts, 
            user: req.session.user,
            lastLoginInfo 
        });
    } catch (error) {
        console.error('Error in /home route:', error);
        res.render('error', { 
            view: 'error', 
            message: 'An error occurred while loading the home page. Please try again.',
            user: req.session.user 
        });
    }
});


// Show a list of current friends and people who are not yet friends
route.get('/friend_list', async (req, res) => {
    try {
        let friends: User[] = [];
        let notFriends: User[] = [];
        
        if (req.session.user && req.session.user.id) {
            const user = await User.byId(req.session.user.id);
            if (user) {
                friends = await user.findFriends();
                notFriends = await user.findNotFriends();
            }
        }
        
        res.render('friend_list', { 
            ...req.session, 
            view: 'friend_list', 
            friends, 
            notFriends, 
            user: req.session.user 
        });
    } catch (error) {
        console.error('Error in /friend_list route:', error);
        res.render('error', { 
            view: 'error', 
            message: 'An error occurred while loading the friend list. Please try again.',
            user: req.session.user 
        });
    }
});

// Show a list of posts by the current user
route.get('/posts_me', async (req, res) => {
    try {
        let posts: Post[] = [];
        
        if (req.session.user && req.session.user.id) {
            const user = await User.byId(req.session.user.id);
            if (user) {
                posts = await user.findPosts();
            }
        }
        
        res.render('posts_me', { 
            ...req.session, 
            view: 'posts_me', 
            posts, 
            user: req.session.user
        });
    } catch (error) {
        console.error('Error in /posts_me route:', error);
        res.render('error', { 
            view: 'error', 
            message: 'An error occurred while loading your posts. Please try again.',
            user: req.session.user 
        });
    }
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
    res.render('friend_add', { ...req.session, view: 'friend_add', friend, user: req.session.user});
});

// Show change password form
route.get('/change-password', (req, res) => {
    if (!req.session.user) {
        return res.redirect(303, '/');
    }
    const passwordRequirements = getPasswordRequirements();
    const reauthTimeout = ReauthenticationService.getReauthTimeout();
    res.render('change_password', { 
        view: 'change_password', 
        messages: [], 
        passwordRequirements, 
        user: req.session.user,
        reauthTimeout 
    });
});

// Handle re-authentication for password change
route.post('/reauth-password-change', async (req, res) => {
    if (!req.session.user) {
        return res.redirect(303, '/');
    }

    const { currentPassword } = req.body;
    const username = req.session.user.username;
    const messages = [];
    const passwordRequirements = getPasswordRequirements();
    const reauthTimeout = ReauthenticationService.getReauthTimeout();

    try {
        // Verify current password for re-authentication
        const reauthResult = await ReauthenticationService.verifyCurrentPassword(username, currentPassword);
        
        if (!reauthResult.isValid) {
            messages.push(reauthResult.error || 'Current password is incorrect.');
            return res.render('change_password', { 
                view: 'change_password', 
                messages, 
                passwordRequirements, 
                user: req.session.user,
                reauthTimeout,
                step: 'reauth'
            });
        }

        // Create re-authentication token
        if (!reauthResult.userId) {
            messages.push('Authentication failed. Please try again.');
            return res.render('change_password', { 
                view: 'change_password', 
                messages, 
                passwordRequirements, 
                user: req.session.user,
                reauthTimeout,
                step: 'reauth'
            });
        }

        const tokenResult = await ReauthenticationService.createReauthToken(
            reauthResult.userId, 
            'password_change'
        );

        if (!tokenResult.success) {
            messages.push('Authentication failed. Please try again.');
            return res.render('change_password', { 
                view: 'change_password', 
                messages, 
                passwordRequirements, 
                user: req.session.user,
                reauthTimeout,
                step: 'reauth'
            });
        }

        // Proceed to password change form with token
        res.render('change_password', { 
            view: 'change_password', 
            messages: ['Authentication successful. You can now change your password.'], 
            passwordRequirements, 
            user: req.session.user,
            reauthTimeout,
            reauthToken: tokenResult.token,
            step: 'change'
        });

    } catch (error) {
        console.error('Re-authentication error:', error);
        messages.push('Authentication failed. Please try again.');
        res.render('change_password', { 
            view: 'change_password', 
            messages, 
            passwordRequirements, 
            user: req.session.user,
            reauthTimeout,
            step: 'reauth'
        });
    }
});

// Handle change password submission (requires re-authentication token)
route.post('/change-password', async (req, res) => {
    if (!req.session.user) {
        return res.redirect(303, '/');
    }

    const { newPassword, reauthToken } = req.body;
    const username = req.session.user.username;
    const messages = [];
    const passwordRequirements = getPasswordRequirements();
    const reauthTimeout = ReauthenticationService.getReauthTimeout();
    
    try {
        // Find the user
        const user = await User.byUsername(username);
        if (!user || !user.id) {
            messages.push('User not found.');
            return res.render('change_password', { 
                view: 'change_password', 
                messages, 
                passwordRequirements, 
                user: req.session.user,
                reauthTimeout,
                step: 'reauth'
            });
        }

        // Verify re-authentication token
        if (!reauthToken) {
            messages.push('Authentication required. Please re-enter your current password.');
            return res.render('change_password', { 
                view: 'change_password', 
                messages, 
                passwordRequirements, 
                user: req.session.user,
                reauthTimeout,
                step: 'reauth'
            });
        }

        const tokenVerification = await ReauthenticationService.verifyAndConsumeReauthToken(
            user.id, 
            reauthToken, 
            'password_change'
        );

        if (!tokenVerification.isValid) {
            messages.push(tokenVerification.error || 'Authentication expired. Please re-authenticate.');
            return res.render('change_password', { 
                view: 'change_password', 
                messages, 
                passwordRequirements, 
                user: req.session.user,
                reauthTimeout,
                step: 'reauth'
            });
        }

        // Validate new password
        if (!newPassword || newPassword.length === 0) {
            messages.push('New password cannot be empty.');
        } else {
            // Comprehensive password validation
            const passwordValidation = validatePasswordStrength(newPassword);
            if (!passwordValidation.isValid) {
                messages.push(...passwordValidation.errors);
            } else {
                // Attempt to change password (includes age and history checks)
                try {
                    await user.changePassword(newPassword);
                    messages.push('Password changed successfully.');
                    
                    // Redirect to prevent form resubmission
                    return res.render('change_password', { 
                        view: 'change_password', 
                        messages, 
                        passwordRequirements, 
                        user: req.session.user,
                        reauthTimeout,
                        step: 'success'
                    });
                } catch (changeError) {
                    // Handle password change errors (age restriction, reuse, etc.)
                    messages.push(changeError instanceof Error ? changeError.message : 'Failed to change password.');
                }
            }
        }

        // Return to re-authentication step on error
        res.render('change_password', { 
            view: 'change_password', 
            messages, 
            passwordRequirements, 
            user: req.session.user,
            reauthTimeout,
            step: 'reauth'
        });

    } catch (error) {
        console.error('Password change error:', error);
        messages.push('An error occurred while changing your password. Please try again.');
        res.render('change_password', { 
            view: 'change_password', 
            messages, 
            passwordRequirements, 
            user: req.session.user,
            reauthTimeout,
            step: 'reauth'
        });
    }
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