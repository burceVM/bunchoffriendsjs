# Security & User Messages Documentation

## User-Facing Error Messages

This document outlines the secure and user-friendly error messages implemented in the authentication and authorization middleware.

### Authentication Failures
**Scenario**: User is not logged in or session is invalid
- **Redirect**: `/?auth=required`
- **Frontend Message**: Should display "Please log in to access this resource"

### Authorization Failures

#### Role-Based Access Control
**Scenario**: User lacks required role
- **Status**: 403 Forbidden
- **Response**: 
```json
{
    "error": "Access Denied",
    "message": "You do not have the required role to access this resource. Please contact an administrator if you believe this is an error."
}
```

#### Permission-Based Access Control
**Scenario**: User lacks specific permission
- **Status**: 403 Forbidden
- **Response**:
```json
{
    "error": "Access Denied", 
    "message": "You do not have the required permission to perform this action. Please contact an administrator if you believe this is an error."
}
```

#### Resource Access Control
**Scenario**: User cannot access specific resource (not owner, lacks elevated permissions)
- **Status**: 403 Forbidden
- **Response**:
```json
{
    "error": "Access Denied",
    "message": "You can only access your own resources or you need elevated permissions. Please contact an administrator if you believe this is an error."
}
```

#### Admin-Only Access
**Scenario**: Non-admin user tries to access admin-only resource
- **Status**: 403 Forbidden
- **Response**:
```json
{
    "error": "Access Denied",
    "message": "Administrator access required. Please contact an administrator if you believe this is an error."
}
```

#### Moderator/Admin Access
**Scenario**: User without moderator or admin role tries to access protected resource
- **Status**: 403 Forbidden
- **Response**:
```json
{
    "error": "Access Denied",
    "message": "Moderator or administrator access required. Please contact an administrator if you believe this is an error."
}
```

## Security Features

### Information Disclosure Prevention
- Error messages do not reveal specific validation rules
- No enumeration of valid usernames, roles, or permissions
- Generic messages prevent attackers from understanding system internals

### Consistent User Experience
- All authorization failures return structured JSON responses
- Consistent error format across all middleware functions
- Clear guidance for users on next steps

### Administrative Logging
- Detailed security events are logged for administrators
- User-facing messages remain generic while logs contain specifics
- Access denial attempts are tracked for security monitoring

## Frontend Integration

### Handling Authentication Redirects
```javascript
// Check URL parameters for auth requirement
const urlParams = new URLSearchParams(window.location.search);
if (urlParams.get('auth') === 'required') {
    showMessage('Please log in to access this resource');
}
```

### Handling Authorization Errors
```javascript
// Handle 403 responses
if (response.status === 403) {
    const errorData = await response.json();
    showErrorDialog(errorData.error, errorData.message);
}
```

## Best Practices

1. **Always provide clear next steps** - Tell users to contact administrators
2. **Be consistent** - Use the same error format across the application
3. **Be helpful but not revealing** - Give enough info to help legitimate users, not enough to help attackers
4. **Log everything** - Maintain detailed logs for security monitoring while keeping user messages generic
