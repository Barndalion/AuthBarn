import logging
from config import GENERAL_INFO_FILE,ADMIN_LOG_FILE,USERS_LOG_FILE
logging.basicConfig(level=logging.DEBUG, filename= GENERAL_INFO_FILE,filemode='a',format="%(asctime)s - %(levelname)s - %(message)s")

newlogger = logging.getLogger

admin_logger = logging.getLogger("admin_logs")
loghandler = logging.FileHandler(ADMIN_LOG_FILE)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
loghandler.setFormatter(formatter)
admin_logger.addHandler(loghandler)

user_logger = logging.getLogger("user_logs")
user_loghandler = logging.FileHandler(USERS_LOG_FILE)
user_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
user_loghandler.setFormatter(user_formatter)
user_logger.addHandler(user_loghandler)