import json
import os
import bcrypt
import jwt
from .logger import user_logger,general_logger
from .config import *
from contextlib import closing
import time
from functools import wraps
class Undefined(Exception):
    pass
class UsernameNotFound(Exception):
    pass
class IncorrectPassword(Exception):
    pass
class NotFound(Exception):
    pass
class AlreadyExist(Exception):
    pass
class PermissionDenied(Exception):
    pass

def load_json(filepath):
    """Loads JSON data from a file.

    Args:
        filepath (str): The path to the JSON file.

    Returns:
        dict: The loaded JSON data.
    """
    with open(filepath, 'r') as f:
        return json.load(f)
default = {"Admin":[]}
ensure_json_exists(PERMISSION_FILE,default)

class Authentication():
    def __init__(self,enable_logging=False, dev_mode=False):
        self.dev_mode = dev_mode
        self.enable_logging = enable_logging
        self.credentials = get_credentials_from_env()
        if not self.credentials or len(self.credentials) != 5:
            raise ValueError("credentials must be [host, port, user, password, database]")
        # setup_db1(credentials=self.credentials)

    def log(self,level,message):
        """
        The Log function is used to log any message to a user log file within the module
        
        Args:

            level: There are 3 levels, info, warning and critical
            message: this is a string custom message you can add

        Example:
            test.log("info","This will be logged in user_logs")
        """
        if self.enable_logging:
            if level.lower() == "info":
                user_logger.info(message)
            elif level.lower() == "warning":
                user_logger.warning(message) 
            elif level.lower() == "critical":
                user_logger.critical(message)

    def hashed_password(self,password):
        """
        An internal function used to hash a password before storing in a database

        Args:

            password: This should be a string 
        """
        password = str(password)
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return hashed.decode('utf-8')

    def verify_password(self,enter_password, stored_password):
        """
        An internal function used to compare a hashed password to a new password

        Args:

            enter_password (str): The password that you are trying to compare, unhashed, should be a string
            stored_password (bytes): a hashed password that is being compared to, should already be hashed
        """
        if isinstance(stored_password,str):
            stored_password = stored_password.encode('utf-8')
        return bcrypt.checkpw(enter_password.encode(),stored_password)
    
    def generate_token(self,username,role,extend=(24 * 3600)):
        """Generates a Token which has the Username, Role, Permission, Session (in that order)
        
        Args:
            username (str): the username of the user
            role (str): his assigned role typically stored at position [2] when stored in the database
        
        Notes:

            Session is in the format of Unix UTC
        """
        defined_permissions = load_json(PERMISSION_FILE)
        permission = defined_permissions[role]
        payload = {
            "Username":username,
            "Role":role,
            "Permission": permission,
            "Session": int(time.time()) + extend
        }
        token = jwt.encode(payload,SECRET_KEY,algorithm="HS256")
        return token
   
    def login(self,username,password,extend=(24 * 3600)):
        """Logs in a user with username and password.

        Args:
            username (str): The username of the user.
            password (str): The password of the user.

        Returns:
            dict: A dictionary with 'state' (bool) and either 'token' or 'message'.
        """
        with closing(connect_db(self.credentials[0],self.credentials[1],self.credentials[2],self.credentials[3],self.credentials[4])) as conn:
            cursor = conn.cursor()
    
            cursor.execute("SELECT * FROM data WHERE username = %s",(username,))
            data = cursor.fetchone()
            
            if data is None:
                general_logger.warning("Username not found")
                if self.dev_mode:
                    raise UsernameNotFound("Username not Found")
                else:
                    return {"state":False, "message":"Username not found"}
            
            stored_password = data[1]
            if self.verify_password(password,stored_password):
                general_logger.info("Login Successful")
                token = self.generate_token(data[0],data[2],extend)
                return {"state":True,"token":token}
            else:
                general_logger.critical("Incorrect Username or Password!")
                if self.dev_mode == True:
                    raise IncorrectPassword("Incorrect Username or Password!")            
                else:
                    return {"state":False,"message":"Incorrect Username or Password!"}
        
    def register(self,name,password,role="User"):
        """Registers a new user.

        Args:
            name (str): The username for the new user.
            password (str): The password for the new user.

        Returns:
            dict: A dictionary with 'state' (bool) and 'Token' or 'message'.
        """
        with closing(connect_db(self.credentials[0],self.credentials[1],self.credentials[2],self.credentials[3],self.credentials[4])) as conn:
            cursor  = conn.cursor()
            
            cursor.execute("SELECT * FROM data WHERE username = %s",(name,))
            data = cursor.fetchone()
            if data != None:
                general_logger.warning("Name Already Exists")
                if self.dev_mode == True:
                    raise AlreadyExist("Name Already Exists")
                else:  
                    return {"state":False,"message":"Name Already Exists"}
            
            hashing_password = self.hashed_password(password)
            general_logger.info("Successfully Registered")
            cursor.execute("INSERT INTO data (username,password,role) VALUES (%s,%s,%s)",(name,hashing_password,role))
            conn.commit()

            token = self.generate_token(name,role)
            return {"state":True,"Token":token}

    def reset_password(self,username,new_password):
        """Resets the password for a user.

        Args:
            username (str): The username of the user.
            new_password (str): The new password.

        Returns:
            dict: A dictionary with 'state' (bool) and 'message'.
        """
        with closing(connect_db(self.credentials[0],self.credentials[1],self.credentials[2],self.credentials[3],self.credentials[4])) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT username FROM data")
            names = {name[0] for name in cursor.fetchall()}
            if username not in names:
                general_logger.warning("Username Not Found")
                if self.dev_mode == True:
                    raise NotFound(f"Username {username} Not Found")
                else:              
                    return {"state":False,"message":"Username Not Found"}
            
            cursor.execute("SELECT * FROM data WHERE username = %s",(username,))
            userdata = cursor.fetchone()
            old_password = userdata[1]      
            
            if self.verify_password(new_password,old_password):
                general_logger.warning("New Password Cant Be The Same As Old Password")
                if self.dev_mode == True:
                    raise AlreadyExist("New Password Cant Be The Same As Old Password")
                else:
                    return {"state":False,"message":"New Password Cant Be The Same As Old Password"}
                
            password = self.hashed_password(new_password)
            cursor.execute("UPDATE data SET password = %s WHERE username = %s",(password,username))
            general_logger.info("Password Reset Successful")
            conn.commit()
            
            return {"state":True,"message":"Reset Password Successful"}

class Action(Authentication):
    def __init__(self,enable_logging=False,dev_mode=False,):
        super().__init__(enable_logging,dev_mode)
        
    def add_role(self,new_role, permissions,token = None):
        """Adds a new role with permissions.

        Args:
            new_role (str): The name of the new role.
            permissions (str): The permissions for the role.
            token (bytes): Token must be passed in production mode 

        Returns:
            dict: A dictionary with 'state' (bool) and 'message'.
        """
        if self.dev_mode == False:
            perm = "add_role"
            if not self.verifypermissions(perm,token):
                return {"state":False,"message":f"Permission Denied"}
            
        defined_permissions = load_json(PERMISSION_FILE)

        if new_role not in defined_permissions:
            if isinstance(permissions,list):
                defined_permissions[new_role] = permissions
            else:
                defined_permissions[new_role] = [permissions if permissions else []]
            general_logger.info(f"Added Role: {new_role}")
            Action.save_json(PERMISSION_FILE,defined_permissions)
            return {"state":True,"message":f"Added Role: {new_role}"}
        elif self.dev_mode == True:
            general_logger.warning("Role Already Exists")
            raise AlreadyExist(f"{new_role} Already Exist")
        else:
            general_logger.warning("Role Already Exists")
            return {"state":False,"message":"Role Already Exist"}
       
    def remove_role(self,role_to_remove,token=None):
        """Removes a role.

        Args:
            role_to_remove (str): The role to remove.
            token (bytes): Token must be passed in production mode 

        Returns:
            dict: A dictionary with 'state' (bool) and 'message'.
        """
        defined_permissions = load_json(PERMISSION_FILE)    

        if self.dev_mode == False:
            perm = "remove_role"
            if not self.verifypermissions(perm,token):
                return {"state":False,"message":f"Permission Denied"}
            
        if role_to_remove in defined_permissions:
            defined_permissions.pop(role_to_remove)
            general_logger.info(f"Removed Role: {role_to_remove}")
            Action.save_json(PERMISSION_FILE,defined_permissions)
            return {"state":True,"message":f"Removed Role: {role_to_remove}"}
        elif self.dev_mode == True:
            general_logger.info(f"No Role Called: {role_to_remove}")
            raise UsernameNotFound(f"No Role Called {role_to_remove}")
        else:
            general_logger.info(f"No Role Called: {role_to_remove}")
            return {"state":False,"message":f"No Role Called {role_to_remove}"}
      
    def add_user(self,username,password,role="User",token=None):
        """Adds a new user.

        Args:
            username (str): The username.
            password (str): The password.
            role (str): The role, default 'User'.
            token (bytes): Token must be passed in production mode 

        Returns:
            dict: A dictionary with 'state' and 'message'.
        """
        
        if not self.dev_mode:
            perm = "add_user"
            if not self.verifypermissions(perm,token):
                return {"state":False,"message":"Permission Denied"}
            
        with closing(connect_db(self.credentials[0],self.credentials[1],self.credentials[2],self.credentials[3],self.credentials[4])) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM data WHERE username = %s",(username,))
            data = cursor.fetchall()

            names = [name[0] for name in data]

            if username in names:
                if self.dev_mode:
                    raise AlreadyExist("User already exists")
                else:
                    return {"state":False,"message":"User already exists"}
            
            cursor.execute("INSERT INTO data (username,password,role) VALUES (%s,%s,%s)",(username,self.hashed_password(password),role))
            conn.commit()
            return {"state":True,"message":f"Successfully added {username}"}
        
    def add_bulk_user(self,username=[],password=[],role="User",token=None):
        """Adds multiple users in bulk.

        Args:
            username (list): List of usernames.
            password (list): List of passwords.
            role (str): The role for all users, default 'User'.
            token (bytes): Token must be passed in production mode 

        Returns:
            dict: A dictionary with 'state' and 'message'.
        """
        if not self.dev_mode:
            perm = "add_user"
            if not self.verifypermissions(perm,token):
                return {"state":False,"message":"Permission Denied"}
            
        if len(username) != len(password):
            if not self.dev_mode:
                return {"state":True,"message":"Length of Username and Length of password lists must be the same"}
            else:
                raise(IndexError("Length of Username and Length of password lists must be the same"))
        
        for nam,pas in zip(username,password):
            with closing(connect_db(self.credentials[0],self.credentials[1],self.credentials[2],self.credentials[3],self.credentials[4])) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM data")
                data = [names[0] for names in cursor.fetchall()]

                if nam in data:
                    if self.dev_mode:
                        raise AlreadyExist("User already exists")
                    else:
                        return {"state":False,"message":"User already exists"}

                cursor.execute("INSERT INTO data (username,password,role) VALUES (%s,%s,%s)",(nam,self.hashed_password(pas),role))
                conn.commit()
        return {"state":True,"message":"Successfully Added Bulk of Users"}


    def remove_user(self,remove_ans,token=None):
        """Removes a user.

        Args:
            remove_ans (str): The username to remove.
            token (bytes): Token must be passed in production mode 

        Returns:
            dict: A dictionary with 'state' and 'message'.
        """
        if self.dev_mode == False:
            perm = "remove_user"
            if not self.verifypermissions(perm,token):
                return {"state":False,"message":f"Permission Denied"}
            
        with closing(connect_db(self.credentials[0],self.credentials[1],self.credentials[2],self.credentials[3],self.credentials[4])) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM data WHERE username = %s",(remove_ans,))
            data = cursor.fetchone()
 
            if data is not None:
                cursor.execute("DELETE FROM data WHERE username = %s",(remove_ans,))
                conn.commit()
                general_logger.info(f"{remove_ans} Removed Successfully")
                return {"state":True,"message":f"REMOVED RECORD NAMED {remove_ans}"}
            else:
                general_logger.warning(f"NO RECORDS NAMED {remove_ans}")
                if self.dev_mode:
                    raise UsernameNotFound(f"Username {remove_ans} Not Found")
                else:
                    return {"state":False,"message":f"NO RECORDS NAMED {remove_ans}"}
                
    @staticmethod
    def save_json(filepath,data):
        """Internal function that saves data to a JSON file.

        Args:
            filepath (str): The path to the file.
            data (dict): The data to save.
        """
        with open(filepath, 'w') as f:
            json.dump(data,f, indent=4)
    
    def view_user_info(self,toview,token=None):
        """Views user information.

        Args:
            toview (str): The username to view, or 'all'.
            token (bytes): Token must be passed in production mode 

        Returns:
            dict or list: User info or list of users.
        """
        name = {"Username":"admin"}
        if self.dev_mode ==  False:
            name = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            perm = "view_userinfo"
            if not self.verifypermissions(perm,token):
                return {"state":False,"message":f"Permission Denied"}
            
        with closing(connect_db(self.credentials[0],self.credentials[1],self.credentials[2],self.credentials[3],self.credentials[4])) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT Username FROM data")
            userdata = cursor.fetchall()
            names = [names[0] for names in userdata]

            if toview not in names:
                general_logger.warning(f"Function Call: view_userinfo, No User Called {toview} Found")
                if self.dev_mode == True:
                    raise UsernameNotFound("Username Name Not Found")
                else:
                    return f"{toview} Does Not Exist!"

            elif toview in names:
                general_logger.info(f"{name['Username']} requested to view {toview}")
                cursor.execute("SELECT * FROM data WHERE username = %s",(toview,))
                data = cursor.fetchone()
                namedata = {"Username":data[0],"Role":data[2]}
                return namedata

            elif toview.lower() == "all":
                general_logger.info(f"{name['Username']} requested to view all users")
                cursor.execute("SELECT username, role FROM data")
                allusers = cursor.fetchall()
                return allusers             
        
    def verifypermissions(self, perm, token=None):
        """Verifies if a permission is granted.

        Args:
            perm (str): The permission to check.
            token (bytes): Token must be passed in production mode 

        Returns:
            bool: True if permitted.
        """
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            allowed_permissions = decoded["Permission"]
            if perm in allowed_permissions:
                general_logger.info(f"Permission '{perm}' verified for user")
                return True
            else:
                general_logger.warning(f"Permission '{perm}' denied")
                if self.dev_mode:
                    raise PermissionDenied(f"Permission '{perm}' not granted")
                return False
        except jwt.InvalidTokenError as e:
            general_logger.error(f"Invalid token: {e}")
            if self.dev_mode:
                raise
            return False
        
    @staticmethod
    def require_permission(role):
        """Decorator to require a specific role.

        Args:
            role (str): The required role.

        Returns:
            function: The decorated function.
        """
        def wrapper(func):
            @wraps(func)
            def inner(*args, **kwargs):
                from flask import request
                token = request.cookies.get("access_token")
                if not token:
                    raise(PermissionDenied("Token Does Not Exist"))
                decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

                if role != decoded.get("Role"):
                    raise PermissionDenied("Permission Denied")

                return func(*args, **kwargs)
            return inner
        return wrapper