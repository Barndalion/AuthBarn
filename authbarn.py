import json
from logger import user_logger,admin_logger,newlogger
from config import PERMISSION_FILE,USERDATA_FILE

class undefined(Exception):
    pass

with open(PERMISSION_FILE,'r') as file:
   defined_permissions = json.load(file)
with open(USERDATA_FILE,'r') as userfile:
   userdata = json.load(userfile)

class Authentication():
    def __init__(self):
       self.username = None
       self.password = None
       self.allowed = []
        
    def login(self,username,password):
        if username in userdata and password == userdata[username][0]:
                  self.username = username 
                  self.role = userdata[username][1] 
                  self.allowed = defined_permissions[self.role]
                  return True
        else:
                newlogger.critical("Incorrect Username or Password!")
                return False
        
    def register(self,name,password):
        self.role = "User"
        Action._dev_mode = True
        self.add_user(name,password,self.role)  
        Action._dev_mode = False
        self.username = name
        self.password = password 
        user_logger.info(f"{name} Successfully Registered!!")                     

class Action(Authentication):
    _dev_mode = False
    def __init__(self):
        self.custom_function = []
        super().__init__()
        
    @staticmethod
    def set_dev_mode(Enabled:bool):
        Action._dev_mode = Enabled
        status = "Enabled" if Enabled else "Disabled"
        admin_logger.info(f"Admin Set Status to {status}") 

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
                usertypeid = usertype[1]
            else:
                raise ValueError("Invalid tuple format. Use ('custom', 'RoleName').")
        elif usertype in ["Admin","User"]:
            usertypeid = usertype.capitalize()
        else:
            raise undefined(f"{usertype} is not a defined Role")
    
        userdata[username] = [password, usertypeid]
        Action.save_json(USERDATA_FILE,userdata)
        admin_logger.info(f"{username} Added Successfully")

    def remove_user(self,remove_ans):
        if not Action._dev_mode:
            perm = "remove_user"
            self.verifypermissions(perm)
        if remove_ans in userdata:
            userdata.pop(remove_ans)
            Action.save_json(USERDATA_FILE, userdata)
            admin_logger.info(f"{remove_ans} Removed Successfully")
        else:
            admin_logger.warning(f"NO RECORDS NAMED {remove_ans}")
    @staticmethod
    def save_json(filepath,data):
        with open(filepath, 'w') as f:
            json.dump(data,f, indent=4)
    
    def view_userinfo(self,toview):
        if not Action._dev_mode:
            perm = "view_userinfo"
            self.verifypermissions(perm)
        if toview in userdata:
            admin_logger.info(f"{self.username} requested to view {toview}")
            return {toview:userdata[toview]}
        elif toview.lower() == "all":
            admin_logger.info(f"{self.username} requested to view all users")
            return userdata
        else:
            return f"{toview} Does Not Exist!"
        
    def verifypermissions(self,tryperm):
        if tryperm in self.allowed:
               return
        else:
            newlogger.info(f"Permission Not Allowed For {self.role}")
    
    def custom_permission(self,permnission_name):
        if not Action._dev_mode:
            perm = "custom_permission"
            self.verifypermissions(perm)

        if permnission_name in self.custom_function:
            newlogger.warning("Permission already exists")
            return 
        if not callable(globals().get(permnission_name)):
            raise NameError(f"No Function Defined as {permnission_name} in This Script")
        else:
            self.custom_function.append(permnission_name)
            newlogger.info(f"Successfully Added {permnission_name} as a custom permission")

    def bind(self,add_to,permname):
        if not Action._dev_mode:
            perm = "bind"
            self.verifypermissions(perm)

        if permname in self.custom_function:
            if add_to in defined_permissions:
                if permname not in defined_permissions[add_to]:
                        defined_permissions[add_to].append(permname)
                        self.save_json(PERMISSION_FILE, defined_permissions)
                        newlogger.info(f"Permission '{permname}' added to role '{add_to}'.")
            else:
                newlogger.warning(f"{add_to}is not a defined role")
            
    def execute(self,permission_name):
        if not Action._dev_mode:
            perm = "execute"
            self.verifypermissions(perm)
        if permission_name in self.custom_function and permission_name in self.allowed:
            func = globals().get(permission_name)

            if callable(func):
                func()
            else:
                newlogger.warning(f"{permission_name} is not a function")
        else:
            raise NameError(f"No Function Saved As {permission_name}")
        
auth = Action()
auth.set_dev_mode(True)

users = ["darell","lionel","ann"]
passwords = ["lii22","1234","123456789"]

auth.add_user(users,passwords,"User")
name = auth.view_userinfo("dar")