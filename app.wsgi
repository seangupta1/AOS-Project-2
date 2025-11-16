#!/usr/bin/python
import sys
import logging

# Optional: log errors to Apache error log
logging.basicConfig(stream=sys.stderr)

# Add your project directory to the sys.path
sys.path.insert(0, '/var/www/html/app')

# Import the Flask app
from app import app as application  # 'app' is your Flask instance in app.py
