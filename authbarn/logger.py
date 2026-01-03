import logging
from logging.handlers import RotatingFileHandler
from .config import GENERAL_INFO_FILE, USERS_LOG_FILE

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
formatter = logging.Formatter(LOG_FORMAT)

# -------- General logger --------
general_logger = logging.getLogger("authbarn.general")
general_logger.setLevel(logging.INFO)

general_handler = RotatingFileHandler(
    GENERAL_INFO_FILE,
    maxBytes=10 * 1024 * 1024,   # 5 MB
    backupCount=5              # keep last 5 files
)
general_handler.setFormatter(formatter)
general_logger.addHandler(general_handler)
general_logger.propagate = False

# -------- User logger --------
user_logger = logging.getLogger("authbarn.user")
user_logger.setLevel(logging.INFO)

user_handler = RotatingFileHandler(
    USERS_LOG_FILE,
    maxBytes=10 * 1024 * 1024,
    backupCount=5
)
user_handler.setFormatter(formatter)
user_logger.addHandler(user_handler)
user_logger.propagate = False