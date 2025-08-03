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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
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
const user_1 = __importDefault(require("./user"));
const friend_1 = __importDefault(require("./friend"));
const post_1 = __importDefault(require("./post"));
const passwordHistory_1 = __importDefault(require("./passwordHistory"));
const accountLockoutService_1 = require("../services/accountLockoutService");
const passwordResetService_1 = require("../services/passwordResetService");
const userManagementLog_1 = __importDefault(require("./userManagementLog"));
const reauthenticationService_1 = require("../services/reauthenticationService");
// Initialize the database with a schema and sample data
// Run once on system startup
function initialize() {
    return __awaiter(this, void 0, void 0, function* () {
        // Create the database schema
        yield alasql_1.default.promise(`create table users(
            id serial primary key not null autoincrement,
            username text unique,
            password text,
            fullName text,
            role text
        );
        
        create table friends(
            id serial primary key not null autoincrement,
            friendFrom integer,
            friendTo integer,
            constraint friendFrom_fk foreign key (friendFrom) references users(id),
            constraint friendTo_fk foreign key (friendTo) references users(id)
        );
        
        create table posts(
            id serial primary key not null autoincrement,
            creator integer,
            message text,
            creationDate Date,
            likes integer,
            constraint creator_fk foreign key (creator) references users(id)
        )`);
        // Initialize core tables for security features before creating users
        yield accountLockoutService_1.AccountLockoutService.initializeTables();
        yield passwordResetService_1.PasswordResetService.initializeTables();
        yield passwordHistory_1.default.initializeTable();
        yield userManagementLog_1.default.initializeTable();
        yield reauthenticationService_1.ReauthenticationService.initializeReauthTable();
        // Populate the database with sample data using secure password hashing
        const max = yield user_1.default.createUser('max', 'Maximuth1', 'Max LOLL', 'admin');
        const malcolm = yield user_1.default.createUser('malcolm', 'Malcolm1', 'Malcolm Todd', 'moderator');
        const carol = yield user_1.default.createUser('carol', 'password', 'Carol', 'normie');
        const mike = yield user_1.default.createUser('mike', 'qwerty', 'Mike', 'normie');
        const alice = yield user_1.default.createUser('alice', '123456', 'Alice', 'normie');
        const sam = yield user_1.default.createUser('sam', 'iloveyou', 'Sam', 'normie');
        const greg = yield user_1.default.createUser('greg', 'bravo', 'Greg', 'normie');
        const peter = yield user_1.default.createUser('peter', 'volcano', 'Peter', 'normie');
        const bobby = yield user_1.default.createUser('bobby', 'racecar', 'Bobby', 'normie');
        const marcia = yield user_1.default.createUser('marcia', 'davyjones', 'Marcia', 'normie');
        const jan = yield user_1.default.createUser('jan', 'glass', 'Jan', 'normie');
        const cindy = yield user_1.default.createUser('cindy', 'thindy', 'Cindy', 'normie');
        // Setup Carol's account for testing time-gated security features
        // Backdate her password history to make it immediately changeable
        if (carol.id) {
            console.log('Setting up Carol as a test account for password security features...');
            // Update Carol's password history to be 25 hours old (older than 24-hour minimum)
            const backdatedTime = new Date(Date.now() - (25 * 60 * 60 * 1000)); // 25 hours ago
            yield alasql_1.default.promise(`
            UPDATE password_history 
            SET created_at = ? 
            WHERE user_id = ?
        `, [backdatedTime.toISOString(), carol.id]);
            // Add some additional historical passwords for testing password reuse prevention
            // These will be older passwords that Carol "used" in the past
            const historicalPasswords = ['oldpassword1', 'oldpassword2', 'temppass123', 'password123'];
            for (let i = 0; i < historicalPasswords.length; i++) {
                const { hashPassword } = yield Promise.resolve().then(() => __importStar(require('../utils/passwordSecurity')));
                const hashedPassword = yield hashPassword(historicalPasswords[i]);
                const historyDate = new Date(Date.now() - ((26 + i) * 60 * 60 * 1000)); // 26+ hours ago
                const historyRecord = new passwordHistory_1.default(carol.id, hashedPassword, historyDate);
                yield historyRecord.create();
            }
            console.log('Carol\'s account setup complete:');
            console.log('- Password history backdated to allow immediate changes');
            console.log('- Historical passwords added for reuse testing');
            console.log('- Login: carol / password');
            console.log('- Cannot reuse: oldpassword1, oldpassword2, temppass123, password123, password');
        }
        // Users are already created with secure password hashes
        // No need to call create() again as createUser() handles it
        yield new friend_1.default(marcia, carol).create();
        yield new friend_1.default(marcia, jan).create();
        yield new friend_1.default(jan, marcia).create();
        yield new friend_1.default(jan, alice).create();
        yield new friend_1.default(jan, cindy).create();
        yield new friend_1.default(cindy, jan).create();
        yield new friend_1.default(cindy, mike).create();
        yield new friend_1.default(carol, marcia).create();
        yield new friend_1.default(carol, greg).create();
        yield new friend_1.default(carol, alice).create();
        yield new friend_1.default(alice, carol).create();
        yield new friend_1.default(alice, jan).create();
        yield new friend_1.default(alice, peter).create();
        yield new friend_1.default(alice, mike).create();
        yield new friend_1.default(mike, alice).create();
        yield new friend_1.default(mike, cindy).create();
        yield new friend_1.default(mike, bobby).create();
        yield new friend_1.default(greg, carol).create();
        yield new friend_1.default(greg, peter).create();
        yield new friend_1.default(peter, greg).create();
        yield new friend_1.default(peter, alice).create();
        yield new friend_1.default(peter, bobby).create();
        yield new friend_1.default(bobby, peter).create();
        yield new friend_1.default(bobby, mike).create();
        yield new friend_1.default(alice, sam).create();
        yield new friend_1.default(sam, alice).create();
        yield new post_1.default(mike, 'It has been a busy week', new Date('2020-1-2 09:00:00'), 5).create();
        yield new post_1.default(mike, 'Finished designs for new building.', new Date('2020-1-4 16:15:00'), 2).create();
        yield new post_1.default(mike, 'Received Father of the Year award. Wow!', new Date('2020-1-5 12:33:00'), 5).create();
        yield new post_1.default(carol, 'Enjoying a nightcap with hubby', new Date('2020-1-5 18:42:00'), 5).create();
        yield new post_1.default(carol, 'Teaching the boys to dance', new Date('2020-1-8 4:55:00'), 4).create();
        yield new post_1.default(alice, 'Cleaning, cleaning. Always cleaning.', new Date('2020-1-1 13:21:00'), 3).create();
        yield new post_1.default(alice, 'Cooking up a storm in the kitchen', new Date('2020-1-2 11:49:00'), 2).create();
        yield new post_1.default(sam, 'At the meat market', new Date('2020-1-5 08:01:00'), 2).create();
        yield new post_1.default(sam, 'Thinking of buying a new refrigerator', new Date('2020-1-6 12:05:00'), 1).create();
        yield new post_1.default(greg, 'Bobby is so immature', new Date('2020-1-2 16:59:00'), 3).create();
        yield new post_1.default(greg, 'Another school day. :(', new Date('2020-1-4 07:32:00'), 5).create();
        yield new post_1.default(greg, 'Listening to the new Jonny Bravo single', new Date('2020-1-7 17:38:00'), 8).create();
        yield new post_1.default(peter, 'Saved a life today', new Date('2020-1-3 18:05:00'), 1).create();
        yield new post_1.default(peter, 'Am I dull?', new Date('2020-1-3 18:22:00'), 0).create();
        yield new post_1.default(bobby, 'Clairol #43. Ugh!', new Date('2020-1-5 10:10:00'), 4).create();
        yield new post_1.default(bobby, 'Feeling afraid of heights', new Date('2020-1-7 13:52:00'), 0).create();
        yield new post_1.default(marcia, 'I could listen to Davy Jones all night', new Date('2020-1-7 20:19:00'), 0).create();
        yield new post_1.default(jan, 'Feeling low', new Date('2020-1-8 09:15:00'), 0).create();
        yield new post_1.default(cindy, 'I have just heard an amazing secret', new Date('2020-1-11 13:11:00'), 0).create();
        // Set up security questions for all users
        console.log('Setting up security questions for all users...');
        // Admin and moderator users
        if (max.id !== undefined) {
            yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(max.id, 'first_pet_name', 'Buddy');
        }
        if (malcolm.id !== undefined) {
            yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(malcolm.id, 'favorite_food', 'Pizza');
        }
        // Regular users with diverse security questions
        if (carol.id !== undefined) {
            yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(carol.id, 'childhood_hero', 'Wonder Woman');
        }
        if (mike.id !== undefined) {
            yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(mike.id, 'first_pet_name', 'Tiger');
        }
        if (alice.id !== undefined) {
            yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(alice.id, 'favorite_food', 'Chocolate');
        }
        if (sam.id !== undefined) {
            yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(sam.id, 'childhood_phone_last_four', '5678');
        }
        if (greg.id !== undefined) {
            yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(greg.id, 'childhood_hero', 'Superman');
        }
        if (peter.id !== undefined) {
            yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(peter.id, 'college_not_attended', 'Harvard University');
        }
        if (bobby.id !== undefined) {
            yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(bobby.id, 'first_pet_name', 'Fluffy');
        }
        if (marcia.id !== undefined) {
            yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(marcia.id, 'favorite_food', 'Strawberries');
        }
        if (jan.id !== undefined) {
            yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(jan.id, 'childhood_hero', 'Nancy Drew');
        }
        if (cindy.id !== undefined) {
            yield passwordResetService_1.PasswordResetService.setupUserSecurityQuestion(cindy.id, 'childhood_phone_last_four', '1234');
        }
        console.log('Security questions setup completed for all users.');
    });
}
exports.default = initialize;
//# sourceMappingURL=initialize.js.map