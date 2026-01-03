# AuthBarn

**Version:** 0.2.8  
**Creator:** Darell Barnes  
**Email:** darellbarnes450@gmail.com 
**License:** MIT

---

## Description

AuthBarn is a lightweight Python authentication system with user management and role-based permissions. It uses JWT tokens for stateless authentication, bcrypt for secure password hashing, and MySQL for reliable data persistence. Designed for standalone use or integration into larger applications, particularly web frameworks like Flask.

---

## Key Features

- 🔐 **JWT Authentication** - Stateless token-based authentication with optional expiration
- 🔒 **Secure Password Hashing** - Uses bcrypt with salt for password storage
- 👥 **Role-Based Access Control** - Flexible permission system with custom roles
- 🗄️ **MySQL Backend** - Reliable database storage with thread-safe connections
- 📝 **Logging System** - Separate logs for general system activity and user actions
- 🛠️ **Developer Mode** - Enhanced debugging with detailed exceptions
- 🌐 **Web-Ready** - Returns structured JSON responses perfect for APIs

---

## Installation

```bash
pip install AuthBarn
```

### Dependencies

AuthBarn automatically installs:
- `bcrypt` - Password hashing
- `PyJWT` - JWT token generation and validation
- `mysql-connector-python` - MySQL database connectivity
- `python-dotenv` - Environment variable management

---

## Quick Start

### 1. Database Setup

First, create a MySQL database:

```sql
CREATE DATABASE your_database_name;
```

### 2. Configuration

Create a configuration file or set up environment variables:

```python
from authbarn import write_credentials_to_env

# One-time setup - creates .env file with credentials
write_credentials_to_env(
    host="127.0.0.1",
    port=3306,
    user="your_mysql_user",
    password="your_mysql_password",
    database_name="your_database_name"
)
```

This creates a `.env` file with your database credentials and a secure secret key.

**Alternative:** Manually create a `.env` file:

```env
AUTHBARN_SECRET_KEY=your_generated_secret_key_here
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=your_mysql_user
DB_PASSWORD=your_mysql_password
DB_NAME=your_database_name
```

### 3. Initialize AuthBarn

```python
from authbarn import Action

# Initialize with logging disabled (production)
auth = Action(enable_logging=False, dev_mode=False)

# Or with logging and dev mode (development)
auth = Action(enable_logging=True, dev_mode=True)
```

---

## Core Concepts

### Terminology

- **Permission** - Actions that can be performed (e.g., "add_user", "view_userinfo")
- **Role** - Groups of permissions (e.g., "Admin", "User", custom roles)
- **Token** - JWT token returned after login/register, used for authentication
- **Developer Mode** - When enabled, raises exceptions instead of returning error dictionaries

### Return Values

AuthBarn methods return dictionaries for easy integration with web frameworks:

**Success:**
```python
{"state": True, "token": "eyJhbG..."} # or other success data
```

**Failure:**
```python
{"state": False, "message": "Error description"}
```

**Developer Mode:** Raises exceptions instead of returning error dictionaries.

---

## Usage Guide

### User Registration

Register a new user with default "User" role:

```python
result = auth.register("john_doe", "secure_password123")

if result["state"]:
    token = result["Token"]  # Note: capital T
    print(f"Registration successful! Token: {token}")
else:
    print(f"Error: {result['message']}")
```

### User Login

Authenticate and receive a JWT token:

```python
result = auth.login("john_doe", "secure_password123")

if result["state"]:
    token = result["token"]  # Note: lowercase t
    print(f"Login successful! Token: {token}")
    # Store token for subsequent requests
else:
    print(f"Error: {result['message']}")
```

### Token-Based Operations

Most operations require a valid token for authorization:

```python
# Get token from login
result = auth.login("admin", "admin_password")
admin_token = result["token"]

# Use token for protected operations
result = auth.add_user("jane_doe", "password123", "User", token=admin_token)
```

---

## Role Management

### View Permission Configuration

Roles and their permissions are stored in `authbarn/data/permission.json`:

```json
{
    "Admin": [
        "add_role",
        "remove_role", 
        "add_user",
        "remove_user",
        "view_userinfo"
    ],
    "User": []
}
```

### Add a Role

```python
# Add role with single permission
auth.add_role("Manager", "add_user", token=admin_token)

# Add role with multiple permissions
auth.add_role("Editor", ["view_userinfo", "add_user"], token=admin_token)

# Add empty role (no permissions)
auth.add_role("Guest", [], token=admin_token)
```

### Remove a Role

```python
result = auth.remove_role("Guest", token=admin_token)
```

### Manually Edit Permissions

Edit `authbarn/data/permission.json` directly to add permissions to roles:

```json
{
    "Admin": ["add_user", "remove_user", "view_userinfo"],
    "Manager": ["add_user", "view_userinfo"],
    "User": []
}
```

---

## User Management

### Add User (Requires Permission)

```python
# Add user with default "User" role
result = auth.add_user("new_user", "password123", token=admin_token)

# Add user with custom role
result = auth.add_user("manager_user", "password123", "Manager", token=admin_token)
```

### Bulk Add Users

```python
usernames = ["user1", "user2", "user3"]
passwords = ["pass1", "pass2", "pass3"]

result = auth.add_bulk_user(
    username=usernames,
    password=passwords,
    role="User",
    token=admin_token
)
```

### Remove User

```python
result = auth.remove_user("john_doe", token=admin_token)
```

### View User Information

```python
# View specific user
user_info = auth.view_userinfo("john_doe", token=admin_token)
print(user_info)  # {"Username": "john_doe", "Role": "User"}

# View all users
all_users = auth.view_userinfo("all", token=admin_token)
# Returns list of tuples: [("user1", "User"), ("admin", "Admin"), ...]
```

### Reset Password

```python
result = auth.reset_password("john_doe", "new_secure_password")

if result["state"]:
    print("Password reset successful")
```

**Security Note:** Implement additional authentication (security questions, email verification) before allowing password resets in production.

---

## Advanced Features

### Custom Permission Decorator

Use the `require_permission` decorator to protect functions:

```python
@auth.require_permission("Admin")
def admin_only_function(token):
    return "This function requires Admin role"

# Usage
try:
    result = admin_only_function(token=admin_token)
    print(result)
except PermissionDenied:
    print("Access denied!")
```

### Verify Permissions Manually

```python
has_permission = auth.verifypermissions("add_user", token=user_token)

if has_permission:
    # User has the permission
    result = auth.add_user(...)
else:
    print("User lacks required permission")
```

### Custom Logging

Log custom events to the user log file:

```python
auth = Action(enable_logging=True, dev_mode=False)

# Log levels: "info", "warning", "critical"
auth.log("info", "User performed custom action")
auth.log("warning", "Suspicious activity detected")
auth.log("critical", "System alert")
```

---

## Configuration Options

### Initialization Parameters

```python
auth = Action(
    enable_logging=False,  # Enable/disable logging to files
    dev_mode=False         # Enable exceptions vs error dictionaries
)
```

- **`enable_logging`** (bool, default: False)
  - `True`: Logs all actions to `authbarn/logfiles/general_logs.log`
  - `False`: Logging disabled

- **`dev_mode`** (bool, default: False)
  - `True`: Raises exceptions for easier debugging
  - `False`: Returns error dictionaries (production-ready)

### Log Levels

- **`info`** - General informational messages
- **`warning`** - Warning messages for non-critical issues
- **`critical`** - Critical errors requiring attention

---

## File Structure

```
authbarn/
│
├── data/
│   └── permission.json          # Role-permission mappings
│
├── logfiles/
│   ├── general_logs.log         # System activity logs
│   └── user_logs.log            # Custom user logs
│
├── authbarn.py                  # Main authentication logic
├── config.py                    # Configuration and database setup
├── logger.py                    # Logging configuration
└── .env                         # Environment variables (git-ignored)
```

---

## Integration Examples

### Flask API Example

```python
from flask import Flask, request, jsonify
from authbarn import Action

app = Flask(__name__)
auth = Action(enable_logging=True, dev_mode=False)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    result = auth.register(data['username'], data['password'])
    return jsonify(result)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    result = auth.login(data['username'], data['password'])
    return jsonify(result)

@app.route('/users', methods=['POST'])
def add_user():
    data = request.json
    token = request.headers.get('Authorization')
    result = auth.add_user(
        data['username'], 
        data['password'], 
        data.get('role', 'User'),
        token=token
    )
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
```

### FastAPI Example

```python
from fastapi import FastAPI, Header
from authbarn import Action
from pydantic import BaseModel

app = FastAPI()
auth = Action(enable_logging=True, dev_mode=False)

class UserCreate(BaseModel):
    username: str
    password: str

@app.post("/register")
def register(user: UserCreate):
    result = auth.register(user.username, user.password)
    return result

@app.post("/login")
def login(user: UserCreate):
    result = auth.login(user.username, user.password)
    return result

@app.post("/users")
def add_user(user: UserCreate, role: str = "User", authorization: str = Header(None)):
    result = auth.add_user(user.username, user.password, role, token=authorization)
    return result
```

---

## Security Best Practices

### Production Deployment

1. **Always disable developer mode:**
   ```python
   auth = Action(enable_logging=True, dev_mode=False)
   ```

2. **Never commit `.env` file:**
   - Ensure `.env` is in `.gitignore`
   - Use environment variables on production servers

3. **Use strong secret keys:**
   - AuthBarn auto-generates secure keys with `write_credentials_to_env()`
   - Never reuse secret keys across environments

4. **Implement rate limiting:**
   - Add rate limiting to prevent brute-force attacks on login endpoints

5. **Use HTTPS:**
   - Always transmit tokens over HTTPS in production

6. **Token security:**
   - Store tokens securely on the client (httpOnly cookies for web)
   - Implement token refresh for long-lived sessions
   - Consider adding token expiration (modify `generate_token()` to include `exp` claim)

### Password Requirements

Consider implementing in your application:
- Minimum 8 characters
- Mix of uppercase, lowercase, numbers, and symbols
- Password strength checking
- Password history (prevent reuse)

---

## Troubleshooting

### Common Issues

**"AUTHBARN_SECRET_KEY not found"**
```python
# Solution: Run the setup function first
from authbarn import write_credentials_to_env
write_credentials_to_env("localhost", 3306, "user", "pass", "dbname")
```

**"credentials must be [host, port, user, password, database]"**
```
# Solution: Check your .env file has all required fields
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=your_database
```

**Import Error: "No module named 'authbarn'"**
```bash
# Solution: Install with correct capitalization
pip install AuthBarn
```

**MySQL Connection Error**
```bash
# Ensure MySQL is running
sudo systemctl start mysql  # Linux
# or
mysql.server start  # macOS
```

---

## API Reference

### Authentication Class

#### `register(name, password)`
Register a new user with "User" role.

**Returns:** `{"state": True/False, "Token": "jwt_token", "message": "..."}`

#### `login(username, password)`
Authenticate user and return JWT token.

**Returns:** `{"state": True/False, "token": "jwt_token", "message": "..."}`

#### `reset_password(username, new_password)`
Reset user's password.

**Returns:** `{"state": True/False, "message": "..."}`

#### `generate_token(username, role)`
Generate JWT token for user. Used internally but can be called directly.

**Returns:** `str` - JWT token

### Action Class (extends Authentication)

#### `add_role(new_role, permissions, token=None)`
Add a new role with specified permissions.

**Parameters:**
- `new_role` (str): Role name
- `permissions` (str/list): Permission(s) to assign
- `token` (str): JWT token for authorization

#### `remove_role(role_to_remove, token=None)`
Remove a role from the system.

#### `add_user(username, password, role="User", token=None)`
Add a user with specified role.

#### `add_bulk_user(username=[], password=[], role="User", token=None)`
Add multiple users at once.

#### `remove_user(username, token=None)`
Remove a user from the system.

#### `view_userinfo(toview, token=None)`
View user information. Use "all" to view all users.

**Returns:** Dictionary with user info or list of all users

#### `verifypermissions(perm, token=None)`
Check if token has specific permission.

**Returns:** `True/False`

#### `log(level, message)`
Log custom message to user log file.

**Parameters:**
- `level` (str): "info", "warning", or "critical"
- `message` (str): Log message

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## Changelog

### Version 0.2.8
- Migrated from JSON to MySQL database
- Added JWT token-based authentication
- Implemented role-based permission system
- Added environment variable configuration
- Improved thread safety with connection management
- Added bulk user operations
- Enhanced error handling and logging

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Support

For issues, questions, or contributions:
- **Email:** darellbarnes450@gmail.com
- **GitHub:** [https://github.com/Barndalion/AuthBarn](https://github.com/Barndalion/AuthBarn)

---

**AuthBarn - Secure and Lightweight Authentication for Your Python Applications!** 🔐