import os
import pathlib

api_id = os.getenv("API_ID")
api_hash = os.getenv("API_HASH")
bot_token = os.getenv("BOT_TOKEN")
data_path = pathlib.Path("data")
qr_login_wait_seconds = 60
user_client_check_period_seconds = 30
dialog_list_page_size = 10

owner_user_id = int(os.getenv("OWNER_USER_ID", "0"))
