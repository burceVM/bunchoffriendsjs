import Router from 'express-promise-router';
import { User } from '../orm';
import { allowRoles } from '../middleware/auth';
import alasql from 'alasql';
import UserManagementLog from '../orm/userManagementLog';

const route = Router();

// Only moderators and admins can access this page
route.get('/manage-users', allowRoles('moderator', 'admin'), async (req, res) => {
    const currentUser = req.session.user!; // non-null assertion, safe because allowRoles ran
    let users;

    if (currentUser.role === 'moderator') {
        // Moderators can only see normies
        users = await User.byWhere(`role = 'normie'`, 'fullName asc');
    } else {
        // Admins can see everyone except themselves
        users = await User.byWhere(`id <> ${currentUser.id}`, 'fullName asc');
    }

    res.render('manage_users', { ...req.session, view: 'manage_users', users });
});

// Delete user (mods: only normies, admins: anyone except themselves)
route.post('/delete-user/:id', allowRoles('moderator', 'admin'), async (req, res) => {
    const currentUser = req.session.user!; // safe due to allowRoles
    const targetId = Number(req.params.id);

    if (isNaN(targetId) || targetId === currentUser.id) {
        res.status(400).send('Invalid user ID');
        return;
    }

    const targetUser = await User.byId(targetId);
    if (!targetUser) {
        res.status(404).send('User not found');
        return;
    }

    if (currentUser.role === 'moderator' && targetUser.role !== 'normie') {
        res.status(403).send('You can only delete normie accounts.');
        return;
    }

    await alasql.promise(`DELETE FROM users WHERE id = ${targetId}`);

    // Log deletion
    const log = new UserManagementLog(
        currentUser.id!,
        currentUser.username,
        'delete',
        targetUser.id!,
        targetUser.username,
        targetUser.role
    );
    await log.create();

    res.redirect(303, '/manage-users');
});

// Change user role (admin only)
route.post('/change-role/:id', allowRoles('admin'), async (req, res) => {
    const currentUser = req.session.user!;
    const targetId = Number(req.params.id);
    const newRole = String(req.body.role || '').toLowerCase();

    const validRoles = ['normie', 'moderator', 'admin'];
    if (!validRoles.includes(newRole)) {
        res.status(400).send('Invalid role');
        return;
    }

    const targetUser = await User.byId(targetId);
    if (!targetUser) {
        res.status(404).send('User not found');
        return;
    }

    const oldRole = targetUser.role;
    await alasql.promise(`UPDATE users SET role = '${newRole}' WHERE id = ${targetId}`);

    // Log promotion/demotion
    let action = '';
    if (oldRole !== newRole) {
        if (newRole === 'admin' || newRole === 'moderator') {
            action = 'promote';
        } else {
            action = 'demote';
        }
        const log = new UserManagementLog(
            currentUser.id!,
            currentUser.username,
            action,
            targetUser.id!,
            targetUser.username,
            newRole
        );
        await log.create();
    }

    res.redirect(303, '/manage-users');
});

export default route;
