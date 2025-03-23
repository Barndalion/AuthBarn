import json
import os
import threading
import bcrypt
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
default = {"Admin":[]}
ensure_json_exists(PERMISSION_FILE,default)
setup_db1()


class Authentication():
    def __init__(self,enable_logging=False, _dev_mode=False):
       self._dev_mode = _dev_mode
       self.enable_logging = enable_logging
       self.local_data = threading.local()

    def log(self,level,message):
        if self.enable_logging:
            if level == "info":
                user_logger.info(message)
            elif level == "warning":
                user_logger.warning(message) 
            elif level == "critical":
                user_logger.critical(message)

    def hashed_password(self,password):
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt)

    def verify_password(self,enter_password, stored_password):
        return bcrypt.checkpw(enter_password.encode(),stored_password)
    
    def generate_token(self,username,role):
        defined_permissions = load_json(PERMISSION_FILE)
        permission = defined_permissions[role]
        payload = {
            "Username":username,
            "Role":role,
            "Permission": permission
        }
        token = jwt.encode(payload,SECRET_KEY,algorithm="HS256")
        return token
   
    def login(self,username,password):
        with connect_db() as conn:
            cursor = conn.cursor()
    
            cursor.execute("SELECT * FROM data WHERE username = ?",(username,))
            data = cursor.fetchone()
            

            if data is None:
                general_logger.warning("Username not found")
                if self._dev_mode:
                    raise UsernameNotFound("Username not Found")
                else:
                    return {"state":False, "message":"Username not found"}
            
            stored_password = data[2]
            if self.verify_password(password,stored_password):
                general_logger.info("Login Successful")
                role = data[3]
                token = self.generate_token(data[1],role)
                self.local_data.token = token
                return {"state":True,"token":token}
            else:
                general_logger.critical("Incorrect Username or Password!")
                if self._dev_mode == True:
                    raise IncorrectPassword("Incorrect Username or Password!")            
                else:
                    return {"state":False,"message":"Incorrect Username or Password!"}
        
    def register(self,name,password):
        with connect_db() as conn:
            cursor  = conn.cursor()
            
            cursor.execute("SELECT * FROM data WHERE username = ?",(name,))
            data = cursor.fetchone()
            if data != None:
                general_logger.warning("Name Already Exists")
                if self._dev_mode == True:
                    raise AlreadyExist("Name Already Exists")
                else:  
                    return {"state":False,"message":"Name Already Exists"}
            
            hashing_password = self.hashed_password(password)
            general_logger.info("Successfully Registered")
            cursor.execute("INSERT INTO data (username,password,role) VALUES (?,?,?)",(name,hashing_password,"User"))
            conn.commit()
            return True

    def reset_password(self,username,new_password):
        with connect_db() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT username FROM data")
            data = cursor.fetchall()
            names = {name[0] for name in data}
            if username not in names:
                general_logger.warning("Username Not Found")
                if self._dev_mode == True:
                    raise NotFound(f"Username {username} Not Found")
                else:              
                    return {"state":False,"message":"Username Not Found"}
            
            cursor.execute("SELECT * FROM data WHERE username = ?",(username,))
            userdata = cursor.fetchone()
            old_password = userdata[2].encode()       
            
            if self.verify_password(new_password,old_password):
                general_logger.warning("New Password Cant Be The Same As Old Password")
                if self._dev_mode == True:
                    raise AlreadyExist("New Password Cant Be The Same As Old Password")
                else:
                    return {"state":False,"message":"New Password Cant Be The Same As Old Password"}
                
            password = self.hashed_password(new_password)
            cursor.execute("UPDATE data SET password = ? WHERE username = ?",(password,username))
            general_logger.info("Password Reset Successful")
            conn.commit()
            
            return True

class Action(Authentication):
    def __init__(self,enable_logging=False,_dev_mode=False):
        super().__init__(enable_logging,_dev_mode) 
        
    def add_role(self,new_role, permissions):
        if self._dev_mode:
            perm = "add_role"
            general_logger.info(f"Permission: {perm}")
            if self.verifypermissions(perm) == False:
                general_logger.warning(f"Permission Denied")
                return {"state":False,"message":f"Permission Denied"}
            
        defined_permissions = load_json(PERMISSION_FILE)

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

        if self._dev_mode:
            perm = "remove_role"
            general_logger.info(f"Permission: {perm}")
            if self.verifypermissions(perm) == False:
                general_logger.warning(f"Permission Denied")
                return {"state":False,"message":f"Permission Denied"}
            
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
      
    def add_user(self,username,password,usertype="User"):
        defined_permissions = load_json(PERMISSION_FILE)

        if self._dev_mode:
            perm = "add_user"
            general_logger.info(f"Permission: {perm}")
            if self.verifypermissions(perm) == False:
                general_logger.warning(f"Permission Denied")
                return {"state":False,"message":f"Permission Denied"}
            
        with connect_db() as conn:
            cursor = conn.cursor()
            usertypeid = usertype

            cursor.execute("SELECT username FROM data")
            names = {name for name in cursor.fetchall()}
         
            if username in names:
                general_logger.warning(f"{username} Already Exists")
                if self._dev_mode == True:
                    raise AlreadyExist(f"{username} Already Exists")
                else:
                    return {"state":False,"message":f"{username} Already Exists"}

            if isinstance(username, list) and isinstance(password, list):
                if len(username) != len(password):
                    general_logger.warning("Lists for bulk user creation must be of the same length.")
                    if self._dev_mode:
                        raise Undefined("Lists for bulk user creation must be of the same length.")
                    else:
                        return {"state":False,"message":"Lists for bulk user creation must be of the same length."}
            
                for user, pwd in zip(username, password):
                    if user in names:
                        general_logger.warning(f"{user} Already Exists")
                        continue
                    hashed_pwd = self.hashed_password(pwd)
                    cursor.execute("INSERT INTO data (username,password,role) VALUES (?,?,?)",(user,hashed_pwd,usertype))
                conn.commit()
                general_logger.info(f"Successfully Added Users")
                return {"state":True,"message":"Successfully Added List Of Users"}
            
            if username in names:
                general_logger.warning(f"{username} Already Exists")
                if self._dev_mode == True:
                    raise AlreadyExist(f"{username} Already Exists")
                else:
                    return {"state":False,"message":f"{username} Already Exists"}
                    
            if isinstance(usertype,tuple):
                if usertype[0].lower()=='custom':
                        defined_permissions[usertype[1]] = []
                        cursor.execute("INSERT INTO data (username,password,role) VALUES (?,?,?)",(username,password,usertypeid))
                        conn.commit()
                        Action.save_json(PERMISSION_FILE,defined_permissions)
                        general_logger.info(f"{usertype[1]} Successfully Added as a Role")
                        return {"state":True,"message":f"Successfully Added User {username} With Role {usertype[1]}"}
                else:
                    if self._dev_mode == True:
                        general_logger.warning("Invalid tuple format. Use ('custom', 'RoleName').") 
                        raise ValueError("Invalid tuple format. Use ('custom', 'RoleName').")
                    else:
                        return {"state":False,"message":"Invalid tuple format. Use ('custom', 'RoleName')."}
                    
            if usertype not in defined_permissions:
                if self._dev_mode == True:
                    general_logger.warning(f"Role {usertype} is not defined.")  
                    raise Undefined(f"Role {usertype} is not defined.")
                else:
                    return {"state":False,"message":f"Role {usertype} is not defined."}
        
            hashed_password = self.hashed_password(password)
            cursor.execute("INSERT INTO data (username,password,role) VALUES (?,?,?)",(username,hashed_password,usertypeid))
            conn.commit()
            general_logger.info(f"Successfully Added User {username}")
            return {"state":True,"message":f"Successfully Added User {username}"}
        

    def remove_user(self,remove_ans):
        if self._dev_mode:
            perm = "remove_user"
            general_logger.info(f"Permission: {perm}")
            if self.verifypermissions(perm) == False:
                general_logger.warning(f"Permission Denied")
                return {"state":False,"message":f"Permission Denied"}
            
        with connect_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM data WHERE username = ?",(remove_ans,))
            data = cursor.fetchone()
            if data is not None:
                cursor.execute("DELETE FROM data WHERE username = ?",(remove_ans,))
                conn.commit()
                
                general_logger.info(f"{remove_ans} Removed Successfully")
                return True
            else:
                general_logger.warning(f"NO RECORDS NAMED {remove_ans}")
                if self._dev_mode == True:
                    raise UsernameNotFound(f"Username {remove_ans} Not Found")
                else:
                    return {"state":False,"message":f"NO RECORDS NAMED {remove_ans}"}
    @staticmethod
    def save_json(filepath,data):
        with open(filepath, 'w') as f:
            json.dump(data,f, indent=4)
    
    def view_userinfo(self,toview):
        if self._dev_mode:
            perm = "view_userinfo"
            general_logger.info(f"Permission: {perm}")
            if self.verifypermissions(perm) == False:
                general_logger.warning(f"Permission Denied")
                return {"state":False,"message":f"Permission Denied"}
            
        name = jwt.decode(self.local_data.token, SECRET_KEY, algorithms=["HS256"])
        with connect_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT Username FROM data")
            userdata = cursor.fetchall()

            names = {names[0] for names in userdata}

            if not self._dev_mode:
                perm = "view_userinfo"
                self.verifypermissions(perm)

            if toview not in names and toview.lower() != "all":
                general_logger.warning(f"{toview} Does Not Exist!")
                return {"state":False,"message":f"{toview} Does Not Exist!"}
            if toview in names:
                general_logger.info(f"{name['Username']} requested to view {toview}")
                cursor.execute("SELECT * FROM data WHERE username = ?",(toview,))
                data = cursor.fetchone()
                namedata = {"Username":data[1],"Password":data[2],"Role":data[3]}
                return namedata
            elif toview.lower() == "all":
                general_logger.info(f"{name['Username']} requested to view all users")
                cursor.execute("SELECT username, role FROM data")
                allusers = cursor.fetchall()
                return allusers
            else:
                general_logger.warning(f"Function Call: view_userinfo, No User Called {toview} Found")
                if self._dev_mode == True:
                    raise UsernameNotFound("Username Name Not Found")
                else:
                    return f"{toview} Does Not Exist!"
        
    def verifypermissions(self,perm):
        decoded = jwt.decode(self.local_data.token, SECRET_KEY, algorithms=["HS256"])
        allowed_permissions = decoded["Permission"]
        if perm in allowed_permissions:
            return True
        else:
            return False

    def bind(self,add_to,permission_name):
        defined_permissions = load_json(PERMISSION_FILE)
        
        if not self._dev_mode:
            perm = "bind"
            self.verifypermissions(perm)

        permission_func = globals().get(permission_name)
        if not callable(permission_func):
            if self._dev_mode == True:
                general_logger.warning(f"{permission_name} Not Found Please Define Function")
                raise NotFound(f"{permission_name}  Not Found Please Define Function")
            else:
                general_logger.warning(f"{permission_name} Not Found Please Define Function")
                return {"state":False,"Message":f"{permission_name}  Not Found Please Define Function"}
            
        if add_to not in defined_permissions:
            if self._dev_mode == True:
                general_logger.warning(f"Role {add_to} Not Found")
                raise NotFound(f"Role {add_to} Not Found")
            else:
                general_logger.warning(f"Role {add_to} Not Found")
                return {"state":False,"message":f"Role {add_to} Not Found"} 


        if permission_name not in defined_permissions[add_to]:
            defined_permissions[add_to].append(permission_name)
            self.save_json(PERMISSION_FILE, defined_permissions)
            general_logger.info(f"Permission '{permission_name}' added to role '{add_to}'.")
            return True
        else: 
            general_logger.warning(f"Permission {permission_name} Already Exists")
            if self._dev_mode == True:
                raise AlreadyExist(f"Permission {permission_name} Already Exists")
            else:
                return {"state":False,"message":f"Permission {permission_name} Already Exists"}
            
    def execute(self,permission_name):
        if not self._dev_mode:
            perm = "execute"
            self.verifypermissions(perm)

        defined_permissions = load_json(PERMISSION_FILE)
        permissions = [perm for perms in defined_permissions.values() for perm in perms]
        if permission_name not in permissions:
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