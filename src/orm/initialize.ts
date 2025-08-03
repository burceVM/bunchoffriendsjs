/*
 * WARNING!
 *
 * This project is intentionally insecure.
 *
 * DO NOT use in production.
 *
 * It is designed for educational purposes - to teach common vulnerabilities in web applications.
 */

import alasql from 'alasql';
import User from './user';
import Friend from './friend';
import Post from './post';
import PasswordHistory from './passwordHistory';
import { AccountLockoutService } from '../services/accountLockoutService';
import { PasswordResetService } from '../services/passwordResetService';
import UserManagementLog from './userManagementLog';
import { ReauthenticationService } from '../services/reauthenticationService';
import { LoginTrackingService } from '../services/loginTrackingService';

// Initialize the database with a schema and sample data
// Run once on system startup
export default async function initialize(): Promise<void> {
    // Create the database schema
    await alasql.promise(
        `create table users(
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
        )`
    );

    // Initialize core tables for security features before creating users
    await AccountLockoutService.initializeTables();
    await PasswordResetService.initializeTables();
    await PasswordHistory.initializeTable();
    await UserManagementLog.initializeTable();
    await ReauthenticationService.initializeReauthTable();
    await LoginTrackingService.initializeTable();

    // Populate the database with sample data using secure password hashing
    const max = await User.createUser('max', 'Maximuth1', 'Max LOLL', 'admin');

    const malcolm = await User.createUser('malcolm', 'Malcolm1', 'Malcolm Todd', 'moderator');

    const carol = await User.createUser('carol', 'password', 'Carol', 'normie');
    const mike = await User.createUser('mike', 'qwerty', 'Mike', 'normie');
    const alice = await User.createUser('alice', '123456', 'Alice', 'normie');
    const sam = await User.createUser('sam', 'iloveyou', 'Sam', 'normie');
    const greg = await User.createUser('greg', 'bravo', 'Greg', 'normie');
    const peter = await User.createUser('peter', 'volcano', 'Peter', 'normie');
    const bobby = await User.createUser('bobby', 'racecar', 'Bobby', 'normie');
    const marcia = await User.createUser('marcia', 'davyjones', 'Marcia', 'normie');
    const jan = await User.createUser('jan', 'glass', 'Jan', 'normie');
    const cindy = await User.createUser('cindy', 'thindy', 'Cindy', 'normie');
    
    // Setup Carol's account for testing time-gated security features
    // Backdate her password history to make it immediately changeable
    if (carol.id) {
        console.log('Setting up Carol as a test account for password security features...');
        
        // Update Carol's password history to be 25 hours old (older than 24-hour minimum)
        const backdatedTime = new Date(Date.now() - (25 * 60 * 60 * 1000)); // 25 hours ago
        
        await alasql.promise(`
            UPDATE password_history 
            SET created_at = ? 
            WHERE user_id = ?
        `, [backdatedTime.toISOString(), carol.id]);
        
        // Add some additional historical passwords for testing password reuse prevention
        // These will be older passwords that Carol "used" in the past
        const historicalPasswords = ['oldpassword1', 'oldpassword2', 'temppass123', 'password123'];
        
        for (let i = 0; i < historicalPasswords.length; i++) {
            const { hashPassword } = await import('../utils/passwordSecurity');
            const hashedPassword = await hashPassword(historicalPasswords[i]);
            const historyDate = new Date(Date.now() - ((26 + i) * 60 * 60 * 1000)); // 26+ hours ago
            
            const historyRecord = new PasswordHistory(
                carol.id,
                hashedPassword,
                historyDate
            );
            await historyRecord.create();
        }
        
        console.log('Carol\'s account setup complete:');
        console.log('- Password history backdated to allow immediate changes');
        console.log('- Historical passwords added for reuse testing');
        console.log('- Login: carol / password');
        console.log('- Cannot reuse: oldpassword1, oldpassword2, temppass123, password123, password');
        
        // Add some historical login attempts for testing login tracking
        console.log('Setting up test login history for Carol...');
        
        const testLoginHistory = [
            // Successful logins from different times and locations
            {
                ipAddress: '192.168.1.100',
                userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0',
                wasSuccessful: true,
                hoursAgo: 48 // 2 days ago
            },
            {
                ipAddress: '10.0.0.5',
                userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) Safari/604.1',
                wasSuccessful: true,
                hoursAgo: 72 // 3 days ago
            },
            // Failed login attempts (potential security incidents)
            {
                ipAddress: '203.0.113.42', // Different IP (potential attacker)
                userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/90.0',
                wasSuccessful: false,
                hoursAgo: 6 // 6 hours ago (recent failed attempt)
            },
            {
                ipAddress: '203.0.113.42', // Same suspicious IP
                userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/90.0',
                wasSuccessful: false,
                hoursAgo: 8 // 8 hours ago
            },
            {
                ipAddress: '198.51.100.123', // Another suspicious IP
                userAgent: 'Python-requests/2.25.1', // Automated tool
                wasSuccessful: false,
                hoursAgo: 12 // 12 hours ago
            }
        ];
        
        for (const loginRecord of testLoginHistory) {
            const attemptTime = new Date(Date.now() - (loginRecord.hoursAgo * 60 * 60 * 1000));
            
            // Insert login record directly with custom timestamp
            await alasql.promise(`
                INSERT INTO login_tracking (
                    username, 
                    user_id, 
                    ip_address, 
                    user_agent, 
                    was_successful, 
                    attempt_time,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [
                'carol',
                carol.id,
                loginRecord.ipAddress,
                loginRecord.userAgent,
                loginRecord.wasSuccessful ? 1 : 0,
                attemptTime.toISOString(),
                attemptTime.toISOString()
            ]);
        }
        
        console.log('Test login history added for Carol:');
        console.log('- 2 successful logins from trusted devices');
        console.log('- 3 failed login attempts from suspicious IPs');
        console.log('- Recent failed attempts will trigger security warnings');
        
        // Debug: Verify the data was inserted
        const verifyData = await alasql.promise(`
            SELECT * FROM login_tracking WHERE username = 'carol' ORDER BY attempt_time DESC
        `);
        console.log('DEBUG: Carol login tracking records:', verifyData.length, 'records found');
        if (verifyData.length > 0) {
            console.log('DEBUG: Most recent record:', JSON.stringify(verifyData[0], null, 2));
        }
    }
    
    // Users are already created with secure password hashes
    // No need to call create() again as createUser() handles it

    await new Friend(marcia, carol).create();
    await new Friend(marcia, jan).create();
    await new Friend(jan, marcia).create();
    await new Friend(jan, alice).create();
    await new Friend(jan, cindy).create();
    await new Friend(cindy, jan).create();
    await new Friend(cindy, mike).create();
    await new Friend(carol, marcia).create();
    await new Friend(carol, greg).create();
    await new Friend(carol, alice).create();
    await new Friend(alice, carol).create();
    await new Friend(alice, jan).create();
    await new Friend(alice, peter).create();
    await new Friend(alice, mike).create();
    await new Friend(mike, alice).create();
    await new Friend(mike, cindy).create();
    await new Friend(mike, bobby).create();
    await new Friend(greg, carol).create();
    await new Friend(greg, peter).create();
    await new Friend(peter, greg).create();
    await new Friend(peter, alice).create();
    await new Friend(peter, bobby).create();
    await new Friend(bobby, peter).create();
    await new Friend(bobby, mike).create();
    await new Friend(alice, sam).create();
    await new Friend(sam, alice).create();


    await new Post(mike, 'It has been a busy week', new Date('2020-1-2 09:00:00'), 5).create();
    await new Post(mike, 'Finished designs for new building.', new Date('2020-1-4 16:15:00'), 2).create();
    await new Post(mike, 'Received Father of the Year award. Wow!', new Date('2020-1-5 12:33:00'), 5).create();
    await new Post(carol, 'Enjoying a nightcap with hubby', new Date('2020-1-5 18:42:00'), 5).create();
    await new Post(carol, 'Teaching the boys to dance', new Date('2020-1-8 4:55:00'), 4).create();
    await new Post(alice, 'Cleaning, cleaning. Always cleaning.', new Date('2020-1-1 13:21:00'), 3).create();
    await new Post(alice, 'Cooking up a storm in the kitchen', new Date('2020-1-2 11:49:00'), 2).create();
    await new Post(sam, 'At the meat market', new Date('2020-1-5 08:01:00'), 2).create();
    await new Post(sam, 'Thinking of buying a new refrigerator', new Date('2020-1-6 12:05:00'), 1).create();
    await new Post(greg, 'Bobby is so immature', new Date('2020-1-2 16:59:00'), 3).create();
    await new Post(greg, 'Another school day. :(', new Date('2020-1-4 07:32:00'), 5).create();
    await new Post(greg, 'Listening to the new Jonny Bravo single', new Date('2020-1-7 17:38:00'), 8).create();
    await new Post(peter, 'Saved a life today', new Date('2020-1-3 18:05:00'), 1).create();
    await new Post(peter, 'Am I dull?', new Date('2020-1-3 18:22:00'), 0).create();
    await new Post(bobby, 'Clairol #43. Ugh!', new Date('2020-1-5 10:10:00'), 4).create();
    await new Post(bobby, 'Feeling afraid of heights', new Date('2020-1-7 13:52:00'), 0).create();
    await new Post(marcia, 'I could listen to Davy Jones all night', new Date('2020-1-7 20:19:00'), 0).create();
    await new Post(jan, 'Feeling low', new Date('2020-1-8 09:15:00'), 0).create();
    await new Post(cindy, 'I have just heard an amazing secret', new Date('2020-1-11 13:11:00'), 0).create();
    
    // Set up security questions for all users
    console.log('Setting up security questions for all users...');
    
    // Admin and moderator users
    if (max.id !== undefined) {
        await PasswordResetService.setupUserSecurityQuestion(max.id, 'first_pet_name', 'Buddy');
    }
    if (malcolm.id !== undefined) {
        await PasswordResetService.setupUserSecurityQuestion(malcolm.id, 'favorite_food', 'Pizza');
    }
    
    // Regular users with diverse security questions
    if (carol.id !== undefined) {
        await PasswordResetService.setupUserSecurityQuestion(carol.id, 'childhood_hero', 'Wonder Woman');
    }
    if (mike.id !== undefined) {
        await PasswordResetService.setupUserSecurityQuestion(mike.id, 'first_pet_name', 'Tiger');
    }
    if (alice.id !== undefined) {
        await PasswordResetService.setupUserSecurityQuestion(alice.id, 'favorite_food', 'Chocolate');
    }
    if (sam.id !== undefined) {
        await PasswordResetService.setupUserSecurityQuestion(sam.id, 'childhood_phone_last_four', '5678');
    }
    if (greg.id !== undefined) {
        await PasswordResetService.setupUserSecurityQuestion(greg.id, 'childhood_hero', 'Superman');
    }
    if (peter.id !== undefined) {
        await PasswordResetService.setupUserSecurityQuestion(peter.id, 'college_not_attended', 'Harvard University');
    }
    if (bobby.id !== undefined) {
        await PasswordResetService.setupUserSecurityQuestion(bobby.id, 'first_pet_name', 'Fluffy');
    }
    if (marcia.id !== undefined) {
        await PasswordResetService.setupUserSecurityQuestion(marcia.id, 'favorite_food', 'Strawberries');
    }
    if (jan.id !== undefined) {
        await PasswordResetService.setupUserSecurityQuestion(jan.id, 'childhood_hero', 'Nancy Drew');
    }
    if (cindy.id !== undefined) {
        await PasswordResetService.setupUserSecurityQuestion(cindy.id, 'childhood_phone_last_four', '1234');
    }
    
    console.log('Security questions setup completed for all users.');
}