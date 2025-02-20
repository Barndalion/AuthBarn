# AuthBarn

## Creator: Darell Barnes  
## Version: 0.1.7
## Email: barndalion@gmail.com

### Description
AuthBarn is a lightweight Python authentication system with user management and role-based permissions. It is designed for standalone use or integration into larger applications.

---
### Update Notes
- made the module able to integrate with flask by making each method return true if execution was successful but a dictionary with state: false and message:error message if execution failed

- Added a duplicate method to duplicate the log files to the hosting direcory of this module(will explain furhter below)

- Added function calls so you can import individual methods that you want to use in your hosting script

- Fixed register function and made integration with flask better 

- removed test code at the bottom of the module
## **Terminology**
Several key terms are used frequently in this document:

- **Permission**: Executable functions within the module. Users can define custom permissions by binding functions to roles.
- **Roles**: Defined system roles (e.g., Admin, User, or a custom role). Roles determine the available permissions for a user.
- **User**: The individual installing and managing this module.
- **External User**: The individuals using your script once this module is integrated.
- **Hosting Script**: The script which you import the module to.


---

## **Features**

- **Logging**: Maintains two log files—general logs (tracks all module actions) and user logs (tracks user actions). Users can log custom actions/messages. Logging can be enabled or disabled.
- **Hashing**: Utilizes `hashlib`'s PBKDF2-HMAC to securely store user passwords as random hex strings.
- **Permission Management**: Allows adding/removing roles, adding/removing permissions, and executing custom functions.
- **Developer Mode**: Grants full access to all methods/functions and also enables exception mode. It is recommended to disable this mode if implementing in production. 

---

## **Installation**
Run this Command in terminal: pip install --index-url https://testpypi.org/simple/AuthBarn

For now the module is on test pypi for testing before being actually released

## **Configuration Settings**
To set up the module Attach the Action class to a instance, and enable logging and _dev_mode (_dev_mode should be enabled if you're scripting and disabled when releaseing for external users)

Setting Up the Module
```python
import AuthBarn
instance = Action()
```
Configuring Settings
```python
from AuthBarn import Action
instance = Action(enable_logging = True,_dev_mode = True) #by default both are set to false
```

---

## **Usage Guide**

### **Register a User**
Registers a new user. By default, the assigned role is `User`.

```python
instance.register(username, password) #the username is hashed and stored as a hash value with a salt for security
```

### **Login**
Authenticates external user credentials. Credentials are auto-saved to a JSON file.

```python
instance.login(username, password) #hashes the password entered and compare it with the stored hash password of that user
```

### **Add User**
Allows an Admin or any role with this permission to add a user and specify a role.

```python
instance.add_user(username, password, usertype)
```

Adding A custom Role **custom role**
This adds 
```python
instance.add_user(username, password, ("custom", "Custom Role"))
```
*Note: The specified role is automatically added to the permissions file with an empty permission list.*
*Note: Also remember to specify its permissions by binding them to the role and if you want to execute this permission you can do it dynamically with the execute method*

### **Adding Roles**
Define custom roles using the `add_role` method.

```python
instance.add_role("hello", "permission")
```
*Note: If no permission is specified, the role is created with an empty permission list.*

### **Remove User**
Removes a specified user from Storage

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
## **Messages and Returns**
This Module was modified to work better in web development with the Aid of flask, therefore I modified the return values. 
The returned value if execution is successful is True and if false is a dictionary in the format

```python
# return Messages are only Given if _dev_mode is disabled otherwise Exceptions will be raised to make debugging easier 

if instance.login(username,password) == True:
    print("Successful")
else:
    print(instance.login(username,password)["message"]) #this prints the error message that occured
```
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
