import json
import os
import hashlib
from .logger import user_logger,general_logger
from .config import PERMISSION_FILE,USERDATA_FILE

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
with open(PERMISSION_FILE,'r') as file:
   defined_permissions = json.load(file)
with open(USERDATA_FILE,'r') as userfile:
   userdata = json.load(userfile)

class Authentication():
    def __init__(self,enable_logging=True):
       self.username = None
       self.password = None
       self.role = "Admin"
       self.allowed = []
       self.enable_logging = enable_logging

    def log(self,level,message):
        if self.enable_logging:
            if level == "info":
                user_logger.info(message)
            elif level == "warning":
                user_logger.warning(message)
            elif level == "critical":
                user_logger.critical(message)

    def hashed_password(self,password,salt=None):
        if salt == None:
            salt = os.urandom(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt.hex() + ":" + hashed.hex()    

    def verify_password(self,stored_password, enter_password):
        salt,stored_hash = stored_password.split(':') 
        salt = bytes.fromhex(salt)    
        new_hash = hashlib.pbkdf2_hmac('sha256', enter_password.encode(), salt, 100000)
        print(enter_password)
        print(f"stored hash: {stored_hash}")
        print(f"new hash: {new_hash.hex()}")
        return new_hash.hex() == stored_hash
        
    def login(self,username,password):
        if username in userdata:
             stored_password = userdata[username][0]
             if self.verify_password(stored_password,password):
                  self.username = username 
                  self.role = userdata[username][1] 
                  self.allowed = defined_permissions[self.role]
                  self.log("info","Login Successful")
             else:
                self.log("critical", "Incorrect Username or Password!")
                raise IncorrectPassword("Incorrect Password")
        else:
            self.log("warning","Username Not Found")
            raise UsernameNotFound(f"{username} Not Found")
        
    def register(self,name,password):
        self.role = "User"
        if name in userdata:
            raise NameError(f"{name} Already Exists")
        Action._dev_mode = True
        new_password = self.hashed_password(password)
        self.add_user(name,new_password,self.role)  
        Action._dev_mode = False
        self.username = name
        self.password = new_password 
        self.log("info", f"{name} Successfully Registered!!") 

    def reset_password(self,username,new_password):
        if username not in userdata:
            user_logger.warning("Username Not Found")
            raise NotFound(f"Username {username} Not Found")
        if new_password == userdata[username][0]:
            user_logger.warning("New Password Cant Be The Same As Old Password")
            raise AlreadyExist("New Password Cant Be The Same As Old Password")
        new_password = self.hashed_password(new_password)
        userdata[username][0] = new_password
        user_logger.info("Successfully Reset Password!!")
        Action.save_json(USERDATA_FILE,userdata)

class Action(Authentication):
    _dev_mode = False
    def __init__(self):
        self.custom_function = [perm for permissions in defined_permissions.values() for perm in permissions]
        super().__init__()
        
    def set_dev_mode(self,Enabled:bool):
        Action._dev_mode = Enabled
        status = "Enabled" if Enabled else "Disabled"
        general_logger.info(f"Admin Set Status to {status}")

    def add_role(self,new_role, permissions):
        if not Action._dev_mode:
            perm = "add_role"
            self.verifypermissions(perm)

        if new_role in defined_permissions:
            raise AlreadyExist(f"{new_role} Already Exist")
        else:
            defined_permissions[new_role] = permissions if permissions else []

        Action.save_json(PERMISSION_FILE,defined_permissions)

    def remove_role(self,role_to_remove):
        if not Action._dev_mode:
            perm = "remove_role"
            self.verifypermissions(perm)
        if role_to_remove not in defined_permissions:
            raise UsernameNotFound(f"No Role Called {role_to_remove}")
        defined_permissions.pop(role_to_remove)
        Action.save_json(PERMISSION_FILE,defined_permissions)
        
    def add_user(self,username,password,usertype):
        if not Action._dev_mode:
            perm = "add_user"
            self.verifypermissions(perm)
        if isinstance(username, list) and isinstance(password, list):
            if len(username) != len(password):
                raise ValueError("Lists for bulk user creation must be of the same length.")
        
            for user, pwd in zip(username, password):
                self.add_user(user, pwd,usertype)  

            return
                
        if isinstance(usertype,tuple) :
            if usertype[0].lower()=='custom':
                defined_permissions[usertype[1]] = []
                usertypeid = usertype[1]
                Action.save_json(PERMISSION_FILE,defined_permissions)
                general_logger.info(f"{usertype[1]} Successfully Added as a Role")
            else:
                raise ValueError("Invalid tuple format. Use ('custom', 'RoleName').")
        elif usertype in ["Admin","User"]:
            usertypeid = usertype.capitalize()
        else:
            raise Undefined(f"{usertype} is not a defined Role")
        
        if ':' not in password:
            password = self.hashed_password(password)
            general_logger.info(f"Admin Added {username} Successfully")
       
        userdata[username] = [password, usertypeid]
        Action.save_json(USERDATA_FILE,userdata)

    def remove_user(self,remove_ans):
        if not Action._dev_mode:
            perm = "remove_user"
            self.verifypermissions(perm)
        if remove_ans in userdata:
            userdata.pop(remove_ans)
            Action.save_json(USERDATA_FILE, userdata)
            general_logger("info",f"{remove_ans} Removed Successfully")
        else:
            general_logger.warning(f"NO RECORDS NAMED {remove_ans}")
    @staticmethod
    def save_json(filepath,data):
        with open(filepath, 'w') as f:
            json.dump(data,f, indent=4)
    
    def view_userinfo(self,toview):
        if not Action._dev_mode:
            perm = "view_userinfo"
            self.verifypermissions(perm)
        if toview not in userdata and toview.lower() != "all":
            return f"{toview} Does Not Exist!"
        if toview in userdata:
            general_logger.info(f"{self.username} requested to view {toview}")
            return {toview:userdata[toview]}
        elif toview.lower() == "all":
            general_logger.info(f"{self.username} requested to view all users")
            return userdata
        else:
            return f"{toview} Does Not Exist!"
        
    def verifypermissions(self,tryperm):
        if tryperm in self.allowed:
               return
        else:
            self.log("info", f"Permission Not Allowed For {self.role}")
    
    def custom_permission(self,permnission_name):
        if not Action._dev_mode:
            perm = "custom_permission"
            self.verifypermissions(perm)

        if permnission_name in self.custom_function:
            self.log("warning", "Permission already exists")
            return 
        if not callable(globals().get(permnission_name)):
            raise NameError(f"No Function Defined as {permnission_name} in This Script")
        else:
            self.custom_function.append(permnission_name)
            self.log("info", f"Successfully Added {permnission_name} as a custom permission")

    def bind(self,add_to,permname):
        if not Action._dev_mode:
            perm = "bind"
            self.verifypermissions(perm)

        if permname in self.custom_function:
            if add_to in defined_permissions:
                if permname not in defined_permissions[add_to]:
                        defined_permissions[add_to].append(permname)
                        self.save_json(PERMISSION_FILE, defined_permissions)
                        self.log("info", f"Permission '{permname}' added to role '{add_to}'.")
            else:
                self.log("warning", f"{add_to} is not a defined role")
            
    def execute(self,permission_name):
        if not Action._dev_mode:
            perm = "execute"
            self.verifypermissions(perm)
        if permission_name in self.custom_function:
            func = globals().get(permission_name)

            if callable(func):
                func()
                general_logger.info(f"successfully Executed {permission_name}")
            else:
                self.log("warning", f"{permission_name} is not a function")
        else:
            raise NotFound(f"No Function Saved As {permission_name}")
        
instance = Action()
instance.set_dev_mode(True)
instance.bind("User","add_user")