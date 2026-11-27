"""Settings come from the environment; nothing secret is stored in the repository."""
import os

SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
PAYMENT_API_KEY = os.environ.get("PAYMENT_API_KEY")
DEBUG = os.environ.get("FLASK_DEBUG") == "1"
HOST = os.environ.get("APP_HOST", "127.0.0.1")
