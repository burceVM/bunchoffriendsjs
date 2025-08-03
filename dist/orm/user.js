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
const alasql_1 = __importDefault(require("alasql"));
const post_1 = __importDefault(require("./post"));
const passwordSecurity_1 = require("../utils/passwordSecurity");
const passwordHistoryService_1 = require("../services/passwordHistoryService");
// A user in the system
class User {
    constructor(username, // Login name
    passwordHash, // Bcrypt salted hash of password
    fullName, // Display name for the user interface
    role, // Role of the user (e.g., 'normie', 'moderator', 'admin')
    id) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.fullName = fullName;
        this.role = role;
        this.id = id;
    }
    // Find the unique user with a matching id
    // returns null if there is no such user
    static byId(id) {
        return __awaiter(this, void 0, void 0, function* () {
            const users = yield User.byWhere(`id = ${id}`);
            if (users.length > 0)
                return users[0];
            else
                return null;
        });
    }
    // Find the unique user with a matching login username and password
    // Uses secure password verification with bcrypt
    // returns null if there is no such user or password doesn't match
    static byLogin(username, password) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Input validation
                if (!username || !password ||
                    typeof username !== 'string' ||
                    typeof password !== 'string') {
                    return null;
                }
                // First find user by username only
                const users = yield User.byWhere(`username = '${username.replace(/'/g, '\'\'')}'`);
                if (users.length === 0) {
                    return null;
                }
                const user = users[0];
                // Verify password using bcrypt
                const isPasswordValid = yield passwordSecurity_1.verifyPassword(password, user.passwordHash);
                if (!isPasswordValid) {
                    return null;
                }
                // Check if password hash needs updating (due to security improvements)
                if (passwordSecurity_1.needsRehashing(user.passwordHash)) {
                    console.log(`Password hash for user ${username} needs updating to current security standards`);
                    // Note: In production, you might want to automatically rehash here
                }
                return user;
            }
            catch (error) {
                console.error('Login verification error:', error);
                return null; // Fail securely
            }
        });
    }
    // Find all users matching the supplied SQL 'where' clause
    static byWhere(where, order) {
        return __awaiter(this, void 0, void 0, function* () {
            const rows = yield alasql_1.default.promise(`select id, username, password, fullName, role
             from users
             where ${where}
             ` + (order ? `order by ${order}` : ''));
            // Map database rows to User objects with proper type safety
            return rows
                .map(row => new User(row.username, row.password, row.fullName, row.role, row.id));
        });
    }
    // Create a new user in the database with secure password hashing
    // Updates 'this' with the new 'id'
    create() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield alasql_1.default.promise(`insert into users (username, password, fullName, role) 
                values ('${this.username}', '${this.passwordHash}', '${this.fullName}', '${this.role}')`);
                // Retrieve the identifier of the new row
                this.id = alasql_1.default.autoval('users', 'id');
            }
            catch (e) {
                throw new Error('Username already exists');
            }
        });
    }
    // Find the unique user with a matching username
    // returns null if there is no such user
    static byUsername(username) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!username || typeof username !== 'string') {
                    return null;
                }
                const users = yield User.byWhere(`username = '${username.replace(/'/g, '\'\'')}'`);
                if (users.length > 0)
                    return users[0];
                else
                    return null;
            }
            catch (error) {
                console.error('Error finding user by username:', error);
                return null;
            }
        });
    }
    // Change the password for this user with secure hashing and history tracking
    changePassword(newPassword) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!this.id) {
                    throw new Error('User must have an ID to change password');
                }
                // Use password history service to handle password change with reuse prevention
                const result = yield passwordHistoryService_1.PasswordHistoryService.changePasswordWithHistory(this.id, newPassword, (passwordHash) => __awaiter(this, void 0, void 0, function* () {
                    // Update password hash in AlaSQL
                    yield alasql_1.default('UPDATE users SET password = ? WHERE username = ?', [passwordHash, this.username]);
                    // Update the instance
                    this.passwordHash = passwordHash;
                }));
                if (!result.success) {
                    throw new Error(result.error || 'Failed to change password');
                }
            }
            catch (error) {
                console.error('Password change error:', error);
                throw error; // Preserve the original error (might be about password reuse)
            }
        });
    }
    // Static method to create a new user with secure password hashing
    static createUser(username, plainPassword, fullName, role) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Input validation
                if (!username || !plainPassword || !fullName || !role) {
                    throw new Error('All user fields are required');
                }
                // Hash the password securely
                const passwordHash = yield passwordSecurity_1.hashPassword(plainPassword);
                // Create user instance with hashed password
                const user = new User(username, passwordHash, fullName, role);
                // Save to database
                yield user.create();
                // Initialize password history for the new user
                if (user.id) {
                    yield passwordHistoryService_1.PasswordHistoryService.initializePasswordHistoryForUser(user.id, passwordHash);
                }
                return user;
            }
            catch (error) {
                console.error('User creation error:', error);
                throw error; // Re-throw to allow caller to handle
            }
        });
    }
    // Find all friends of this user
    // (i.e., users that this user has connected to)
    findFriends() {
        return User.byWhere(`id in (
                    select friendTo
                    from friends
                    where friendFrom = ${this.id}
             )`, 'fullName asc');
    }
    // Find all users in the system who the user could befriend (connect)
    // (i.e., users that this user has not already connected to)
    findNotFriends() {
        return User.byWhere(`id not in (
                    select friendTo
                    from friends
                    where friendFrom = ${this.id}
                    union all
                    select ${this.id}
             )`, 'fullName asc');
    }
    // Find all posts by this user
    findPosts() {
        return post_1.default.byWhere(`creator = ${this.id}`, 'creationDate desc');
    }
    // Find all posts by this user and friends of this user
    findFriendPosts() {
        return post_1.default.byWhere(`creator in (
                select friendTo
                from friends
                where friendFrom = ${this.id}
                union all
                select ${this.id}
             )`, 'creationDate desc');
    }
}
exports.default = User;
//# sourceMappingURL=user.js.map