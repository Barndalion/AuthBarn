import os
import sqlite3
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
USERDATA_FILE = os.path.join(USERDATA_DIR,"userdata.db")
GENERAL_INFO_FILE = os.path.join(LOG_DIR,"general_logs.log")
USERS_LOG_FILE = os.path.join(LOG_DIR,"user_logs.log")
#function to test if files exist at path
def connect_db():
    return sqlite3.connect(USERDATA_FILE)

def setup_db1():

    with connect_db() as con:
        cursor = con.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS data("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT NOT NULL,"
        "password TEXT NOT NULL,"
        "role TEXT NOT NULL)")
        con.commit()
    

def ensure_json_exists(filepath,default):
    if not os.path.exists(filepath):
        with open("permission.json","w") as f:
            json.dump(default,f,indent=4)


#secret key
SECRET_KEY = "e4f8b13c7a2e4a9db6d8e5f8b7c2a1d4f3e6c8b9a0d7e5f6c3b2a1f4e7d9c6b8"