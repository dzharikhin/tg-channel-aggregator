import os
import pathlib

api_id = os.getenv("API_ID")
api_hash = os.getenv("API_HASH")
bot_token = os.getenv("BOT_TOKEN")
data_path = pathlib.Path("data")
qr_login_wait_seconds = 30
dialog_list_limit = 100
