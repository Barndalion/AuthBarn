Module Name: AuthBarn
Creator: Darell Barnes
Version: 1.0.0

Description: A lightweight Python authentication system with user management and role-based permissions,
designed for standalone use or integration into larger applications.

NB/ in this document several terms are used often. 
    Permission: These are functions that are executable, the methods within this module are considered permissions
    and the user can define custom permisions by binding it to a role

    Roles: These are the roles defined in the system like Admin, User or a custom one you make(the user), they
    encompass the Permissions for avaikabke for a user with the role

FEATURES

Logging: There are 2 log files the general logs and user logs. The General log tracks all actions done with the modeule,
and the user log tracks actions done by the user. user of this module can log custom acions/messages within the user
log file. logging is able to be enabled and disabled

Hashing: The Module uses Haslib's PBKDF2-HMAC to securely store user passwords as a random hex string

Permission Management: user is able to add roles, remove role, add permissions, remove permissions and execute custom functions

Developer Mode: once enabled user has access to all methods/functions. best to disable if you plan to manage external
users of your script with this modeule

INSTALLATION
##

USAGE GUIDE
importing:

from AuthBarn import Action
instance = Action()

Developer Mode: 
By default the Developer Mode is enabled

instance.set_dev_mode(False)

Register:
Used to Add new users by default the role assigned when register is used is "User"

instance.register(username,password)

Login:
Allows a User to use the softwhere once the credentials are authenticated

instance.login(username,password)

Add User:
Only Admins can use this command(unless Developer Mode is enabled)

instance.add_user(username,password,usertype)
instance.add_user(username,password,("custom","Custom role))

Remove User:
Only Admins can use this command(unless Developer Mode is enabled)

instance.remove_user("username")

Assign Custom Permission:
Only Admins can use this command(unless Developer Mode is enabled)


