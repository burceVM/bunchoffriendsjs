/**
 * Client-side password validation for immediate user feedback
 * Mirrors server-side validation requirements
 */

document.addEventListener('DOMContentLoaded', function() {
    const passwordInputs = document.querySelectorAll('input[type="password"][name="password"], input[type="password"][name="newPassword"]');
    
    passwordInputs.forEach(function(passwordInput) {
        // Create validation display container
        const validationContainer = document.createElement('div');
        validationContainer.className = 'password-validation-live';
        validationContainer.style.marginTop = '10px';
        
        // Insert after the password input
        passwordInput.parentNode.insertBefore(validationContainer, passwordInput.nextSibling);
        
        // Add real-time validation
        passwordInput.addEventListener('input', function() {
            validatePasswordRealTime(passwordInput.value, validationContainer);
        });
        
        // Validate on form submission
        const form = passwordInput.closest('form');
        if (form) {
            form.addEventListener('submit', function(e) {
                const validation = validatePassword(passwordInput.value);
                if (!validation.isValid) {
                    e.preventDefault();
                    showValidationErrors(validation.errors, validationContainer);
                }
            });
        }
    });
});

/**
 * Validate password against requirements (client-side version)
 */
function validatePassword(password) {
    const errors = [];
    
    if (!password) {
        return { isValid: false, errors: ['Password is required'] };
    }
    
    // Length validation
    if (password.length < 8) {
        errors.push('Password must be at least 8 characters long');
    }
    
    if (password.length > 128) {
        errors.push('Password must not exceed 128 characters');
    }
    
    // Character type requirements
    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter (A-Z)');
    }
    
    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter (a-z)');
    }
    
    if (!/\d/.test(password)) {
        errors.push('Password must contain at least one number (0-9)');
    }
    
    if (!/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?~`]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }
    
    // Common weak passwords
    const blockedPasswords = [
        'password', 'password123', '12345678', 'qwerty123',
        'letmein', 'welcome123', 'admin123', 'user1234',
        'changeme', 'temporary', 'newpassword', 'secret123'
    ];
    
    const lowerPassword = password.toLowerCase();
    for (const blocked of blockedPasswords) {
        if (lowerPassword.includes(blocked)) {
            errors.push('Password contains common words or patterns that are not allowed');
            break;
        }
    }
    
    // Sequential characters
    if (/123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(password)) {
        errors.push('Password should not contain sequential characters or common patterns');
    }
    
    // Repeated characters
    if (/(.)\1{2,}/.test(password)) {
        errors.push('Password should not contain more than 2 consecutive identical characters');
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

/**
 * Real-time password validation with visual feedback
 */
function validatePasswordRealTime(password, container) {
    const validation = validatePassword(password);
    
    if (!password) {
        container.innerHTML = '';
        return;
    }
    
    container.innerHTML = '';
    
    // Create status indicators
    const requirements = [
        { test: password.length >= 8, text: 'At least 8 characters' },
        { test: /[A-Z]/.test(password), text: 'One uppercase letter' },
        { test: /[a-z]/.test(password), text: 'One lowercase letter' },
        { test: /\d/.test(password), text: 'One number' },
        { test: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?~`]/.test(password), text: 'One special character' },
        { test: !(/123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(password)), text: 'No sequential patterns' },
        { test: !(/(.)\1{2,}/.test(password)), text: 'No repeated characters' }
    ];
    
    const ul = document.createElement('ul');
    ul.style.margin = '5px 0';
    ul.style.fontSize = '12px';
    
    requirements.forEach(req => {
        const li = document.createElement('li');
        li.textContent = req.text;
        li.style.color = req.test ? '#28a745' : '#dc3545';
        li.style.fontWeight = req.test ? 'normal' : 'bold';
        ul.appendChild(li);
    });
    
    container.appendChild(ul);
}

/**
 * Show validation errors
 */
function showValidationErrors(errors, container) {
    container.innerHTML = '';
    
    if (errors.length === 0) return;
    
    const errorDiv = document.createElement('div');
    errorDiv.style.color = '#dc3545';
    errorDiv.style.fontSize = '12px';
    errorDiv.style.marginTop = '5px';
    
    const ul = document.createElement('ul');
    errors.forEach(error => {
        const li = document.createElement('li');
        li.textContent = error;
        ul.appendChild(li);
    });
    
    errorDiv.appendChild(ul);
    container.appendChild(errorDiv);
}
