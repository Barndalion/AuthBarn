import json
import os
import hashlib
import jwt
import sqlite3 
from logger import user_logger,general_logger
from config import PERMISSION_FILE,USERDATA_FILE,SECRET_KEY,connect_db,ensure_json_exists,setup_db1

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
    with open(filepath, 'r') as f:
        return json.load(f)
default = {"Admin:[]"}
ensure_json_exists(PERMISSION_FILE,default)
setup_db1()


class Authentication():
    def __init__(self,enable_logging=False, _dev_mode=False):
       self._dev_mode = _dev_mode
       self.enable_logging = enable_logging
       self.token = None

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
        return new_hash.hex() == stored_hash
    
    def generate_token(self,username,role):
        defined_permissions = load_json(PERMISSION_FILE)
        secret_key = SECRET_KEY
        permission = defined_permissions[role]
        payload = {
            "Username":username,
            "Role":role,
            "Permission": permission
        }
        token = jwt.encode(payload,secret_key,algorithm="HS256")
        return token
   
    def login(self,username,password):
        conn = connect_db()
        cursor = conn.cursor()
        conn.row_factory = sqlite3.Row
        
        cursor.execute("SELECT * FROM data WHERE username = ?",(username,))
        data = cursor.fetchone()
        conn.close()

        if data is None:
             if self._dev_mode:
                 raise UsernameNotFound("Username not Found")
             else:
                 general_logger.warning("Username not found")
                 return {"state":False, "message":"Username not found"}
        
        stored_password = data[2]
        if self.verify_password(stored_password,password):
              general_logger.info("Login Successful")
              role = data[3]
              token = self.generate_token(data[1],role)
              self.token = token
              return {"state":True,"token":token}
        elif self._dev_mode == True:
            general_logger.critical("Incorrect Username or Password!")
            raise IncorrectPassword("Incorrect Password")
        else:
             general_logger.critical("Incorrect Username or Password!")
             return {"state":False,"message":"Incorrect Username or Password!"}
        
    def register(self,name,password):
        conn = connect_db()
        cursor  = conn.cursor()
        conn.row_factory = sqlite3.Row
        
        cursor.execute("SELECT * FROM data WHERE username = ?",(name,))
        data = cursor.fetchone()
        if data != None:
            if self._dev_mode == True:
                raise AlreadyExist("Name Already Exists")
            else:
                general_logger.warning("Name Already Exists")
                return {"state":False,"message":"Name Already Exists"}
        
        hashing_password = self.hashed_password(password)
            
        cursor.execute("INSERT INTO data (username,password,role) VALUES (?,?,?)",(name,hashing_password,"User"))
        conn.commit()
        conn.close()
        return True

    def reset_password(self,username,new_password):
        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT username FROM data")
        data = cursor.fetchall()
        names = {name[0] for name in data}
        if username not in names:
            if self._dev_mode == True:
                general_logger.warning("Username Not Found")
                raise NotFound(f"Username {username} Not Found")
            else:
                general_logger.warning("Username Not Found")
                return {"state":False,"message":"Username Not Found"}
        
        cursor.execute("SELECT * FROM data WHERE username = ?",(username,))
        userdata = cursor.fetchone()
        hash,old_password = userdata[2].split(":")
        print(hash)
        print(old_password)
        password = self.hashed_password(new_password)
        passhash,password2 = password.split(":")
                
        if password2 == old_password:
            
            if self._dev_mode == True:
                general_logger.warning("New Password Cant Be The Same As Old Password")
                raise AlreadyExist("New Password Cant Be The Same As Old Password")
            else:
                general_logger.warning("New Password Cant Be The Same As Old Password")
                return {"state":False,"message":"New Password Cant Be The Same As Old Password"}
            
        
        print(new_password)
        cursor.execute("UPDATE data SET password = ? WHERE username = ?",(new_password,username))
        conn.commit()
        conn.close()
        return True

class Action(Authentication):
    def __init__(self,enable_logging=False,_dev_mode=False):
        defined_permissions = load_json(USERDATA_FILE)
        super().__init__(enable_logging,_dev_mode)
        
        self.custom_function = [perm for permissions in defined_permissions.values() for perm in permissions]
        
    def add_role(self,new_role, permissions):
        defined_permissions = load_json(PERMISSION_FILE)
        if not self._dev_mode:
            perm = "add_role"
            self.verifypermissions(perm)

        if new_role not in defined_permissions:
            defined_permissions[new_role] = permissions if permissions else []
            general_logger.info(f"Added Role: {new_role}")
            Action.save_json(PERMISSION_FILE,defined_permissions)
            return True
        elif self._dev_mode == True:
            general_logger.warning("Role Already Exists")
            raise AlreadyExist(f"{new_role} Already Exist")
        else:
            general_logger.warning("Role Already Exists")
            return {"state":False,"message":"Role Already Exist"}
       
    def remove_role(self,role_to_remove):
        defined_permissions = load_json(PERMISSION_FILE)    
        if not self._dev_mode:
            perm = "remove_role"
            self.verifypermissions(perm)
        if role_to_remove in defined_permissions:
            defined_permissions.pop(role_to_remove)
            general_logger.info(f"Removed Role: {role_to_remove}")
            Action.save_json(PERMISSION_FILE,defined_permissions)
            return True
        elif self._dev_mode == True:
            general_logger.info(f"No Role Called: {role_to_remove}")
            raise UsernameNotFound(f"No Role Called {role_to_remove}")
        else:
            general_logger.info(f"No Role Called: {role_to_remove}")
            return {"state":False,"message":f"No Role Called {role_to_remove}"}
      
    def add_user(self,username,password,usertype):
        defined_permissions = load_json(PERMISSION_FILE)    
        if not self._dev_mode:
            perm = "add_user"
            self.verifypermissions(perm)

        if isinstance(username, list) and isinstance(password, list):
            if len(username) != len(password):
                if self._dev_mode == True:
                    raise Undefined("Lists for bulk user creation must be of the same length.")
                else:
                    return {"state":False,"message":"Lists for bulk user creation must be of the same length."}
        
            for user, pwd in zip(username, password):
                self.add_user(user, pwd,usertype)  
            return {"state":True,"message":"Successfully Added List Of Users"}
                
        if isinstance(usertype,tuple):
            if usertype[0].lower()=='custom':
                    defined_permissions[usertype[1]] = []
                    usertypeid = usertype[1]
                    Action.save_json(PERMISSION_FILE,defined_permissions)
                    general_logger.info(f"{usertype[1]} Successfully Added as a Role")
            else:
                if self._dev_mode == True:
                    raise ValueError("Invalid tuple format. Use ('custom', 'RoleName').")
                else:
                    return {"state":False,"message":"Invalid tuple format. Use ('custom', 'RoleName')."}
                
        elif usertype in ["Admin","User"]:
                general_logger.info(f"{usertype} Successfully Added User")
                usertypeid = usertype.capitalize()
        else:
            if self._dev_mode == True:
                raise Undefined(f"{usertype} is not a defined Role")
            else:
                return {"state":False,"message":f"{usertype} is not a defined Role"}
        
        if ':' not in password:
            password = self.hashed_password(password)
            general_logger.info(f"Admin Added {username} Successfully")
        userdata = load_json(USERDATA_FILE)
       
        userdata[username] = [password, usertypeid]
        Action.save_json(USERDATA_FILE,userdata)

    def remove_user(self,remove_ans):
        userdata = load_json(USERDATA_FILE)
        if not self._dev_mode:
            perm = "remove_user"
            self.verifypermissions(perm)
        if remove_ans in userdata:
            userdata.pop(remove_ans)
            Action.save_json(USERDATA_FILE, userdata)
            general_logger.info(f"{remove_ans} Removed Successfully")
            return True
        else:
            if self._dev_mode == True:
                general_logger.warning(f"NO RECORDS NAMED {remove_ans}")
                raise UsernameNotFound(f"Username {remove_ans} Not Found")
            else:
                general_logger.warning(f"NO RECORDS NAMED {remove_ans}")
                return {"state":False,"message":f"NO RECORDS NAMED {remove_ans}"}
    @staticmethod
    def save_json(filepath,data):
        with open(filepath, 'w') as f:
            json.dump(data,f, indent=4)
    
    def view_userinfo(self,toview):
        userdata = load_json(USERDATA_FILE)
        if not self._dev_mode:
            perm = "view_userinfo"
            self.verifypermissions(perm)
        if toview not in userdata and toview.lower() != "all":
            return {"state":False,"message":f"{toview} Does Not Exist!"}
        if toview in userdata:
            general_logger.info(f"{self.token["Username"]} requested to view {toview}")
            return {toview:userdata[toview]}
        elif toview.lower() == "all":
            general_logger.info(f"{self.token["Username"]} requested to view all users")
            return userdata
        else:
            if self._dev_mode == True:
                general_logger.warning(f"Function Call: view_userinfo, No User Called {toview} Found")
                raise UsernameNotFound("Username Name Not Found")
            else:
                general_logger.warning(f"Function Call: view_userinfo, No User Called {toview} Found")
                return f"{toview} Does Not Exist!"
        
    def verifypermissions(self,perm):
        decoded = jwt.decode(self.token, "e4f8b13c7a2e4a9db6d8e5f8b7c2a1d4f3e6c8b9a0d7e5f6c3b2a1f4e7d9c6b8", algorithms=["HS256"])
        allowed_permissions = decoded.get("Permission",[])
        if perm in allowed_permissions:
               return
        else:
            if self._dev_mode == True:
                general_logger.info(f"Permission Not Allowed For {self.role}")
                raise PermissionDenied("info", f"Permission Not Allowed For {self.role}")
            else:
                general_logger.info(f"Permission Not Allowed For {self.role}")
                return {"state":False,"message":f"Permission Not Allowed For {self.role}"}
    
    def custom_permission(self,permnission_name):
        if not self._dev_mode:
            perm = "custom_permission"
            self.verifypermissions(perm)

        if not callable(permnission_name):
            if self._dev_mode == True:
                general_logger.warning(f"{permnission_name} Not Found Please Define Function")
                raise NotFound(f"{permnission_name}  Not Found Please Define Function")
            else:
                return {"state":False,"Message":f"{permnission_name}  Not Found Please Define Function"}
            
        func_name = permnission_name.__name__

        if func_name not in self.custom_function:
            self.custom_function.append(permnission_name)
            general_logger.info(f"Successfully Added {permnission_name} as a custom permission")
            return True
        elif self._dev_mode == True:
            general_logger.warning("Permission already exists")
            raise AlreadyExist(f"{func_name} Already Exist")
        else:
            return {"state":False,"message":"Permission Already Exist"}

    def bind(self,add_to,permname):
        defined_permissions = load_json(PERMISSION_FILE)
        if not self._dev_mode:
            perm = "bind"
            self.verifypermissions(perm)

        if permname in self.custom_function:
            if add_to in defined_permissions:
                if permname not in defined_permissions[add_to]:
                        defined_permissions[add_to].append(permname)
                        self.save_json(PERMISSION_FILE, defined_permissions)
                        general_logger.info(f"Permission '{permname}' added to role '{add_to}'.")
                        return True
            else:
                general_logger.warning(f"{add_to} is not a defined role")
                return {"state":False,"message":f"{add_to} is not a defined role"}
        else:
            return {"state":False,"message":f"{permname}is not a custom function, please add it to custom functions"}
            
    def execute(self,permission_name):
        if not self._dev_mode:
            perm = "execute"
            self.verifypermissions(perm)
        if permission_name not in self.custom_function:
            if self._dev_mode == True:
                general_logger.warning(f"{permission_name} is not a function")
                raise NotFound("Function Not Found")
            else: 
                general_logger.warning(f"{permission_name} is not a function")
                return {"state":False,"message":"Function Not Found"}
        else:
            func = globals().get(permission_name)
            general_logger.info(f"successfully Executed {permission_name}")
            func()
            return True
print(Authentication(_dev_mode=True).reset_password("darell", "1234"))