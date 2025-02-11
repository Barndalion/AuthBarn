# AuthBarn

## Creator: Darell Barnes  
## Version: 1.0.0

### Description
AuthBarn is a lightweight Python authentication system with user management and role-based permissions. It is designed for standalone use or integration into larger applications.

---

## **Terminology**
Several key terms are used frequently in this document:

- **Permission**: Executable functions within the module. Users can define custom permissions by binding functions to roles.
- **Roles**: Defined system roles (e.g., Admin, User, or a custom role). Roles determine the available permissions for a user.
- **User**: The individual installing and managing this module.
- **External User**: The individuals using your script once this module is integrated.

---

## **Features**

- **Logging**: Maintains two log files—general logs (tracks all module actions) and user logs (tracks user actions). Users can log custom actions/messages. Logging can be enabled or disabled.
- **Hashing**: Utilizes `hashlib`'s PBKDF2-HMAC to securely store user passwords as random hex strings.
- **Permission Management**: Allows adding/removing roles, adding/removing permissions, and executing custom functions.
- **Developer Mode**: Grants full access to all methods/functions. It is recommended to disable this mode when managing external users.

---

## **Installation**
```python
pip install authbarn
```
## **Configuration Settings**
to set up logging mode import authentication from authbarn then set logging to true
```python
from authbarn import Authentication
instance2 = Authentication(enable_logging = True)
instance2 = Authentication(enable_logging = False)
```

```python
from AuthBarn import Action
instance = Action()
```

---

## **Usage Guide**

### **Developer Mode**
Developer mode allows unrestricted access to all methods without requiring authentication. It should be enabled only during debugging and disabled afterward.

```python
instance.set_dev_mode(True)  # Enable developer mode
instance.set_dev_mode(False) # Disable developer mode
```

### **Register a User**
Registers a new user. By default, the assigned role is `User`.

```python
instance.register(username, password)
```

### **Login**
Authenticates external user credentials. Credentials are auto-saved to a JSON file.

```python
instance.login(username, password)
```

### **Add User**
Allows an Admin to add a user and specify a role.

```python
instance.add_user(username, password, usertype)
```

To assign a **custom role**, use:

```python
instance.add_user(username, password, ("custom", "Custom Role"))
```
*Note: The specified role is automatically added to the permissions file with an empty permission list.*

### **Adding Roles**
Define custom roles using the `add_role` method.

```python
instance.add_role("hello", "permission")
```
*Note: If no permission is specified, the role is created with an empty permission list.*

### **Remove User**
Only Admins (or users in Developer Mode) can remove users.

```python
instance.remove_user("username")
```

### **Assign Custom Permissions**
Custom permissions allow users to define and bind functions to roles.

```python
def hello():
    print("hello")

instance.custom_permission(hello)  # Store the function
instance.bind("Admin", "hello")   # Bind the function to the Admin role
```

You can also bind module methods to roles:

```python
instance.bind("User", "add_user")  # Now 'User' role can use the add_user method
```

Execute a bound function:

```python
instance.execute("hello")
```

### **Reset Password**
Resets a user's password. It is recommended to add additional authentication (e.g., security questions) for security purposes.

```python
instance.reset_password("username", "new_password")
```

### **View User Information**
Returns user details as a dictionary.

```python
user_info = instance.view_userinfo("darell")
print(user_info)
```
## **Logging Custom Messages**
Allows the user to log custom messages in the user logs.

```python
instance.log("level","Message")
```

---

## **Notes**
- Always disable **Developer Mode** in production environments.
- Ensure appropriate authentication before resetting passwords.
- Regularly review role-based permissions for security.
- The log levels are info, warning and critical

---
## **Structural Overview**
│── data/
│   ├── permission.json      # Stores roles and permissions
│   ├── userdata.json        # Stores user credentials
│
│── logfiles/
│   ├── general_logs.log     # Logs general system activity
│   ├── user_logs.log        # Logs user activity
│
│── authbarn.py              # Main authentication and Management logic
│── config.py                # Auto creates necessary files once the user runs this module in a script
│── logger.py                # logs script wide actions to general_logs and user actions to user_logs
│── README.md                # Documentation
**AuthBarn - Secure and Lightweight Authentication for Your Python Applications!** 