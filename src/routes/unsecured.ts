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
import { User, Post, raw } from '../orm';
import { requireAuth, allowRoles } from '../middleware/auth';
const route = Router();

//--------------------------------------------------------
// Routes that require authentication
// These routes now properly enforce authentication
//--------------------------------------------------------

// Apply authentication middleware to all routes in this file
route.use(requireAuth);

// Shows the list of posts by a friend
// Note: now includes proper validation that the friend actually is a friend of the current user
route.get('/posts_friend', async (req, res) => {
    try {
        // Fail securely: validate all inputs
        const friendId = Number(req.query.friend);
        
        // Fail securely: validate friend ID is valid
        if (!friendId || isNaN(friendId) || friendId <= 0) {
            res.status(400).send('Invalid friend ID');
            return;
        }

        // Fail securely: ensure current user session is valid
        if (!req.session?.user?.id || typeof req.session.user.id !== 'number') {
            res.redirect(303, '/');
            return;
        }

        const friend = await User.byId(friendId);
        let posts: Post[] = [];
        
        // Fail securely: only show posts if friend exists and is actually a friend
        if (friend != null) {
            // Validate friendship before showing posts
            const currentUser = await User.byId(req.session.user.id);
            if (currentUser) {
                const friends = await currentUser.findFriends();
                const isFriend = friends.some(f => f.id === friendId);
                
                // Fail securely: only show posts if they are actually friends
                if (isFriend) {
                    posts = await friend.findPosts();
                }
            }
        }
        
        res.render('posts_friend', { view: 'posts_friend', friend, posts, user: req.session.user });
    } catch (error) {
        // Fail securely: any error results in empty response
        console.error('Error in posts_friend route:', error);
        res.status(500).send('Internal Server Error');
        return;
    }
});

// Like a post and redirect to the 'back' parameter
// Now includes validation to prevent users from liking their own posts and validates redirects
route.get('/like', async (req, res) => {
    try {
        // Fail securely: validate all inputs
        const postId = Number(req.query.post);
        const back = String(req.query.back || '/home'); // Safe default redirect
        const friendId = req.query.friend ? Number(req.query.friend) : null;

        // Fail securely: validate post ID
        if (!postId || isNaN(postId) || postId <= 0) {
            res.redirect(303, '/home');
            return;
        }

        // Fail securely: validate user session
        if (!req.session?.user?.id || typeof req.session.user.id !== 'number') {
            res.redirect(303, '/');
            return;
        }

        // Fail securely: validate redirect URL to prevent open redirects
        const safeBack = validateRedirectUrl(back);

        const post = await Post.byId(postId);
        if (post != null) {
            // Fail securely: prevent users from liking their own posts
            if (post.creator.id === req.session.user.id) {
                res.redirect(303, safeBack + (friendId ? `?friend=${friendId}` : ''));
                return;
            }
            
            await post.like();
        }
        
        res.redirect(303, safeBack + (friendId ? `?friend=${friendId}` : ''));
    } catch (error) {
        // Fail securely: any error redirects to safe location
        console.error('Error in like route:', error);
        res.redirect(303, '/home');
        return;
    }
});

// Helper function to validate redirect URLs (fail securely)
function validateRedirectUrl(url: string): string {
    try {
        // Fail securely: only allow relative URLs within the application
        if (!url || typeof url !== 'string') {
            return '/home';
        }

        // Remove any potential protocol or domain
        const cleanUrl = url.trim();
        
        // Fail securely: block absolute URLs, protocol-relative URLs, and javascript:
        if (cleanUrl.includes('://') || 
            cleanUrl.startsWith('//') || 
            cleanUrl.toLowerCase().startsWith('javascript:') ||
            cleanUrl.toLowerCase().startsWith('data:') ||
            cleanUrl.toLowerCase().startsWith('vbscript:')) {
            return '/home';
        }

        // Fail securely: ensure URL starts with / and doesn't go outside app
        if (!cleanUrl.startsWith('/')) {
            return '/home';
        }

        // Additional safety: limit to known safe paths
        const safePaths = ['/home', '/friend_list', '/posts_me', '/posts_friend', '/messages'];
        const basePath = cleanUrl.split('?')[0]; // Remove query parameters for validation
        
        if (safePaths.includes(basePath) || basePath.startsWith('/posts_friend')) {
            return cleanUrl;
        }

        return '/home'; // Fail securely to safe default
    } catch (error) {
        console.error('URL validation error:', error);
        return '/home'; // Fail securely
    }
}

// Show the admin zone - restricted to admin users only
route.get('/admin', allowRoles('admin'), (_req, res) => {
    res.render('admin', { view: 'admin'});
});

// Handle a query posted to the admin zone - restricted to admin users only
route.post('/admin', allowRoles('admin'), async (req, res) => {
    try {
        // Fail securely: validate admin session is still valid
        if (!req.session?.user?.role || req.session.user.role !== 'admin') {
            res.status(403).send('Forbidden');
            return;
        }

        const query = String(req.body.query || '').trim();
        let rows = null;
        let errors = null;

        // Fail securely: validate query input
        if (!query) {
            errors = 'Query cannot be empty';
        } else if (query.length > 1000) {
            // Fail securely: prevent excessively long queries
            errors = 'Query too long (maximum 1000 characters)';
        } else {
            try {
                // Fail securely: restrict dangerous SQL operations
                const dangerousOperations = [
                    'drop', 'delete', 'truncate', 'alter', 'create', 'insert', 'update',
                    'grant', 'revoke', 'exec', 'execute', 'sp_', 'xp_'
                ];
                
                const lowerQuery = query.toLowerCase();
                const containsDangerous = dangerousOperations.some(op => 
                    lowerQuery.includes(op.toLowerCase())
                );

                if (containsDangerous) {
                    errors = 'Query contains restricted operations. Only SELECT queries are allowed.';
                } else {
                    // Perform the SQL query with additional safety
                    const results = await raw(query);

                    // Convert the results from any[] into [string[], ...any[][]]
                    rows = [];
                    if (results && results.length > 0) {
                        // Fail securely: limit result size to prevent memory exhaustion
                        const maxRows = 100;
                        const limitedResults = results.slice(0, maxRows);
                        
                        if (results.length > maxRows) {
                            errors = `Results truncated to ${maxRows} rows (query returned ${results.length} rows)`;
                        }

                        // Use the first row of results to get the column names
                        const header = [];
                        for (const key in limitedResults[0]) {
                            // Fail securely: validate column names
                            if (typeof key === 'string' && key.length > 0) {
                                header.push(key);
                            }
                        }
                        
                        if (header.length > 0) {
                            rows.push(header);

                            // Now iterate through each row to build an array of values
                            for (const result of limitedResults) {
                                const row = [];
                                for (const key of header) {
                                    // Fail securely: sanitize output values
                                    const value = result[key];
                                    if (value === null || value === undefined) {
                                        row.push('NULL');
                                    } else if (typeof value === 'string' && value.length > 200) {
                                        row.push(value.substring(0, 200) + '...[truncated]');
                                    } else {
                                        row.push(String(value));
                                    }
                                }
                                rows.push(row);
                            }
                        }
                    }
                }
            } catch (e) {
                // Fail securely: sanitize error messages to prevent information disclosure
                const error = e as Error;
                console.error('Admin query error:', error);
                errors = 'Query execution failed. Check logs for details.';
            }
        }
        
        res.render('admin', { view: 'admin', query, rows, errors, user: req.session.user });
    } catch (error) {
        // Fail securely: any unexpected error results in access denial
        console.error('Admin route error:', error);
        res.status(500).send('Internal Server Error');
        return;
    }
});

export default route;