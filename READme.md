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

    user: this is you, the installer of this script

    external user: the persons who use YOUR script once this module is integrated

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

*Developer Mode:* 
**developer mode allows you the user to access all methods without having to authenticate via login or register, if developer mod is not enabled you will be unable to use any of the functions its good practice to enable it at the top of your script then disable it once finiched with your script(this is assuming you try to debug while running the program otherwise only Admins can access the methods)**
*enabling dveloper mode*
instance.set_dev_mode(True)

*Register:*
**Used to Add new users by default the role assigned when register is used is "User"**
instance.register(username,password)

*Login:*
**This authenticates external user credentials which are auto saved to a json file**
instance.login(username,password)

*Add User:*
**This adds a user, it is different since only those with the admin role can access it and they are able to specify the user role (usertype)**
instance.add_user(username,password,usertype)

**if you want to add a custom role to the user you can use this format, Note| the role specified as custom role is automatically added to the permissions file as a role which is empty and you can add permissions to this role with the custom permissions explanation below**
instance.add_user(username,password,("custom","Custom role))

*Adding Roles*
**alternatively you can add custom role using the add role method**
instance.add_role("hello","permission")**you dont have to specify a permission it will just save the role with an empty list of permissions, if you do assign a permission only assign one**

*Remove role*
**removes a specified user, eg this will remove the admin role**
Remove User:
Only Admins can use this command(unless Developer Mode is enabled)

instance.remove_user("username")

*Assign Custom Permission:*
        **the custom permission is a function used to assign a user specified function ehich you want to assign to a role example below**

        def hello():
            print("hello")
        **stores the hello function as a method for selective execution by a specified role**
        instance.custom_permission(hello)

        **this binds the hello function to the Admin role**
        instance.bind("Admin","hello")

        **Note bind can be used to bind module methods to roles as well like this:**
        instance.bind("user","add_user") **now users can use add_user method**

        instance.execute("hello")
        **this executes the custom function this is important because you the user can specify custom functions you want external users to be able to do (manage them)**

*Reset Password:*
**this resets the password to a specified password, it is NOT adviced to use this on its you should add an extra authentication to get like a pass key or answer to a question to ensure security of your script REMEMBER THIS MODULE IS JUST A FRAMEWORK**
instance.reset_password("username", "new password")

*view user information*
**this returns the user information as a dictionary, tip: store it in a variable eg,**
user_info = instance.view_userinfo("darell")
