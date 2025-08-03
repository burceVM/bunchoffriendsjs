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