/**
 * Client-side form validation helpers
 * Provides immediate feedback to users without revealing security validation rules
 */

document.addEventListener('DOMContentLoaded', function() {
    // Username validation
    const usernameInputs = document.querySelectorAll('input[name="username"]');
    usernameInputs.forEach(input => {
        input.addEventListener('input', function() {
            const value = this.value;
            const feedback = getValidationFeedback(this);
            
            if (value.length > 50) {
                showFieldError(this, 'Username is too long');
            } else if (value.length > 0 && !/^[a-zA-Z0-9._-]+$/.test(value)) {
                showFieldError(this, 'Username can only contain letters, numbers, dots, underscores, and dashes');
            } else {
                clearFieldError(this);
            }
        });
    });
    
    // Full name validation
    const fullNameInputs = document.querySelectorAll('input[name="fullName"]');
    fullNameInputs.forEach(input => {
        input.addEventListener('input', function() {
            const value = this.value;
            
            if (value.length > 100) {
                showFieldError(this, 'Full name is too long');
            } else {
                clearFieldError(this);
            }
        });
    });
    
    // Security answer validation
    const securityAnswerInputs = document.querySelectorAll('input[name="answer"], textarea[name="answer"]');
    securityAnswerInputs.forEach(input => {
        input.addEventListener('input', function() {
            const value = this.value;
            
            if (value.length > 500) {
                showFieldError(this, 'Security answer is too long');
            } else {
                clearFieldError(this);
            }
        });
    });
    
    // Password validation - just length check for client-side
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    passwordInputs.forEach(input => {
        input.addEventListener('input', function() {
            const value = this.value;
            
            if (value.length > 200) {
                showFieldError(this, 'Password is too long');
            } else {
                clearFieldError(this);
            }
        });
    });
});

function showFieldError(input, message) {
    input.classList.add('form-field-error');
    
    // Remove existing error message
    const existingError = input.parentNode.querySelector('.field-error-message');
    if (existingError) {
        existingError.remove();
    }
    
    // Add new error message
    const errorDiv = document.createElement('div');
    errorDiv.className = 'field-error-message';
    errorDiv.style.color = '#cc0000';
    errorDiv.style.fontSize = '0.9em';
    errorDiv.style.marginTop = '0.25em';
    errorDiv.textContent = message;
    
    input.parentNode.appendChild(errorDiv);
}

function clearFieldError(input) {
    input.classList.remove('form-field-error');
    
    const errorMessage = input.parentNode.querySelector('.field-error-message');
    if (errorMessage) {
        errorMessage.remove();
    }
}

function getValidationFeedback(input) {
    // This function could be expanded to provide real-time positive feedback
    // without revealing validation rules to potential attackers
    return null;
}
