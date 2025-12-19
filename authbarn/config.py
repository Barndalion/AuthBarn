import os
import sqlite3
import json
from dotenv import load_dotenv
import mysql.connector
from contextlib import closing
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


def connect_db(host, port, user, password, database):
    return mysql.connector.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database
    )

def setup_db1(credentials=[]):
    with closing(connect_db(credentials[0],credentials[1],credentials[2],credentials[3],credentials[4])) as con:
        cursor = con.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS data (
                username VARCHAR(255) PRIMARY KEY,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL
            )
        """)
        con.commit()

def ensure_json_exists(filepath,default):
    if not os.path.exists(filepath):
        with open(filepath,"w") as f:
            json.dump(default,f,indent=4)


# Load .env file from the same directory as this config
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

SECRET_KEY = os.getenv("AUTHBARN_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("AUTHBARN_SECRET_KEY env var not set")



credentials = ["127.0.0.1",3306,"root","Lionel12$","test"]
# with closing(connect_db(credentials[0],credentials[1],credentials[2],credentials[3],credentials[4])) as conn:
#             cursor = conn.cursor()
#             cursor.execute("INSERT INTO data (username,password,role) VALUE (%s,%s,%s)",("Darell",1234,"User"))
#             conn.commit()
