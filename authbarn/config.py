import os
import json
from dotenv import load_dotenv
import mysql.connector
from contextlib import closing
import secrets
from pathlib import Path
#getting directory of this script wherevever it is
BASE_DIR = Path(__file__).resolve().parent
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
ENV_PATH = BASE_DIR / ".env"

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
def write_credentials_to_env(host,port,user,password,database_name):
    with open(ENV_PATH,"w") as f:
        num_bytes = 32
        secret_key = secrets.token_hex(num_bytes)
        f.write(f"AUTHBARN_SECRET_KEY={secret_key}\nDB_HOST={host}\nDB_PORT={port}\nDB_USER={user}\nDB_PASSWORD={password}\nDB_NAME={database_name}")

def get_credentials_from_env():
    """Load DB credentials from environment variables."""
    return [
        os.getenv("DB_HOST", "127.0.0.1"),
        int(os.getenv("DB_PORT", 3306)),
        os.getenv("DB_USER"),
        os.getenv("DB_PASSWORD"),
        os.getenv("DB_NAME")
    ]

SECRET_KEY = os.getenv("AUTHBARN_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "AUTHBARN_SECRET_KEY not found in environment variables. "
        "Please run write_credentials_to_env() or create a .env file."
    )