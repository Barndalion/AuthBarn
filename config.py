import os
import json
#getting directory of this script wherevever it is
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
#setting directory of userdata and file
USERDATA_DIR = os.path.join(BASE_DIR,"data")
LOG_DIR = os.path.join(BASE_DIR,"logfiles")
#making folders
os.makedirs(USERDATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR,exist_ok=True)
#making files
PERMISSION_FILE = os.path.join(USERDATA_DIR,"permission.json")
USERDATA_FILE = os.path.join(USERDATA_DIR,"userdata.json")
GENERAL_INFO_FILE = os.path.join(LOG_DIR,"general_logs.log")
USERS_LOG_FILE = os.path.join(LOG_DIR,"user_logs.log")
ADMIN_LOG_FILE = os.path.join(LOG_DIR,"admin_logs.log")
#function to test if files exist at path
def ensure_json_exist(filepath,default_data):
    if not os.path.exists(filepath):
        with open(filepath,"w") as f:
            json.dump(default_data, f,indent=4)

ensure_json_exist(USERDATA_FILE,{})
ensure_json_exist(PERMISSION_FILE,{"admin":[],"User":[]})