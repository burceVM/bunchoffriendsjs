"use strict";
/*
 * Cryptographically secure password hashing utilities
 * Uses bcrypt for one-way salted password hashing
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
exports.validatePasswordStrength = exports.needsRehashing = exports.verifyPassword = exports.hashPassword = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
/**
 * Configuration for password hashing security
 */
const SALT_ROUNDS = 12; // High security salt rounds (2^12 iterations)
/**
 * Hash a password using bcrypt with cryptographically strong salt
 * @param plainPassword - The plain text password to hash
 * @returns Promise<string> - The salted hash of the password
 */
function hashPassword(plainPassword) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            // Input validation
            if (!plainPassword || typeof plainPassword !== 'string') {
                throw new Error('Password must be a non-empty string');
            }
            // Generate cryptographically secure salt and hash
            const saltedHash = yield bcrypt_1.default.hash(plainPassword, SALT_ROUNDS);
            return saltedHash;
        }
        catch (error) {
            console.error('Password hashing error:', error);
            throw new Error('Failed to hash password securely');
        }
    });
}
exports.hashPassword = hashPassword;
/**
 * Verify a password against its stored hash
 * @param plainPassword - The plain text password to verify
 * @param storedHash - The stored bcrypt hash to compare against
 * @returns Promise<boolean> - True if password matches, false otherwise
 */
function verifyPassword(plainPassword, storedHash) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            // Input validation
            if (!plainPassword || typeof plainPassword !== 'string') {
                return false;
            }
            if (!storedHash || typeof storedHash !== 'string') {
                return false;
            }
            // Validate hash format (bcrypt hashes start with $2a$, $2b$, or $2y$)
            if (!storedHash.match(/^\$2[ayb]\$\d{2}\$[./0-9A-Za-z]{53}$/)) {
                console.warn('Invalid hash format detected');
                return false;
            }
            // Use bcrypt's constant-time comparison
            const isValid = yield bcrypt_1.default.compare(plainPassword, storedHash);
            return isValid;
        }
        catch (error) {
            console.error('Password verification error:', error);
            // Fail securely - any error in verification means denial
            return false;
        }
    });
}
exports.verifyPassword = verifyPassword;
/**
 * Check if a stored password needs rehashing (due to updated security parameters)
 * @param storedHash - The stored bcrypt hash to check
 * @returns boolean - True if the hash needs to be updated
 */
function needsRehashing(storedHash) {
    try {
        if (!storedHash || typeof storedHash !== 'string') {
            return true;
        }
        // Check if hash was created with current salt rounds
        const hashRounds = bcrypt_1.default.getRounds(storedHash);
        return hashRounds < SALT_ROUNDS;
    }
    catch (error) {
        console.error('Hash checking error:', error);
        // Fail securely - if we can't verify the hash strength, assume it needs updating
        return true;
    }
}
exports.needsRehashing = needsRehashing;
/**
 * Validate password strength before hashing
 * @param password - The password to validate
 * @returns boolean - True if password meets security requirements
 */
function validatePasswordStrength(password) {
    if (!password || typeof password !== 'string') {
        return false;
    }
    // Password strength requirements
    const minLength = 8;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    return password.length >= minLength &&
        hasUppercase &&
        hasLowercase &&
        hasNumber;
}
exports.validatePasswordStrength = validatePasswordStrength;
//# sourceMappingURL=passwordSecurity.js.map