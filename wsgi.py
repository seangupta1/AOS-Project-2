import sys
import os

# Add the app's directory to the Python path
sys.path.insert(0, '/var/www/nas_app')

# Import the 'app' object from our app.py file
from app import app

# This is the entry point Gunicorn will use
application = app