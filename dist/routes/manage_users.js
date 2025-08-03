"use strict";
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
const auth_1 = require("../middleware/auth");
const alasql_1 = __importDefault(require("alasql"));
const route = express_promise_router_1.default();
// Only moderators and admins can access this page
route.get('/manage-users', auth_1.allowRoles('moderator', 'admin'), (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const currentUser = req.session.user; // non-null assertion, safe because allowRoles ran
    let users;
    if (currentUser.role === 'moderator') {
        // Moderators can only see normies
        users = yield orm_1.User.byWhere(`role = 'normie'`, 'fullName asc');
    }
    else {
        // Admins can see everyone except themselves
        users = yield orm_1.User.byWhere(`id <> ${currentUser.id}`, 'fullName asc');
    }
    res.render('manage_users', Object.assign(Object.assign({}, req.session), { view: 'manage_users', users }));
}));
// Delete user (mods: only normies, admins: anyone except themselves)
route.post('/delete-user/:id', auth_1.allowRoles('moderator', 'admin'), (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const currentUser = req.session.user; // safe due to allowRoles
    const targetId = Number(req.params.id);
    if (isNaN(targetId) || targetId === currentUser.id) {
        res.status(400).send('Invalid user ID');
        return;
    }
    const targetUser = yield orm_1.User.byId(targetId);
    if (!targetUser) {
        res.status(404).send('User not found');
        return;
    }
    if (currentUser.role === 'moderator' && targetUser.role !== 'normie') {
        res.status(403).send('You can only delete normie accounts.');
        return;
    }
    yield alasql_1.default.promise(`DELETE FROM users WHERE id = ${targetId}`);
    res.redirect(303, '/manage-users');
}));
// Change user role (admin only)
route.post('/change-role/:id', auth_1.allowRoles('admin'), (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const targetId = Number(req.params.id);
    const newRole = String(req.body.role || '').toLowerCase();
    const validRoles = ['normie', 'moderator', 'admin'];
    if (!validRoles.includes(newRole)) {
        res.status(400).send('Invalid role');
        return;
    }
    yield alasql_1.default.promise(`UPDATE users SET role = '${newRole}' WHERE id = ${targetId}`);
    res.redirect(303, '/manage-users');
}));
exports.default = route;
//# sourceMappingURL=manage_users.js.map