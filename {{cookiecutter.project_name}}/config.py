from pathlib import Path
from zoneinfo import ZoneInfo


# ----------------------------------------------------------
#
#                           CONFIG
#
# ----------------------------------------------------------


BASE_DIR = Path(__file__).parent.resolve()

DATABASE_URL = (
    "postgresql+psycopg://postgres:postgis@127.0.0.1/{{ cookiecutter.database_name }}"
)

AES_KEY = "<< aes_key >>"
AES_IV = "<< aes_iv >>"

SECRET_KEY = "<< secret_key >>"

TIMEZONE = ZoneInfo("Asia/Shanghai")

DEVELOP = True


# ----------------------------------------------------------
#
#                          STORAGE
#
# ----------------------------------------------------------


STORAGE_DIR = BASE_DIR.joinpath("../storage").resolve()
STORAGE_EXPIRED = 30 * 60


# ----------------------------------------------------------
#
#                           REDIS
#
# ----------------------------------------------------------


REDIS_CACHE_EXPIRED = 5 * 60
REDIS_NAME = "{{ cookiecutter.redis_name }}"
REDIS_URL = "redis://127.0.0.1:6379"
