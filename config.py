"""Runtime configuration for the link shortener."""

import os

# Flask settings
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-this-in-production')
DEBUG = os.environ.get('FLASK_DEBUG', '').lower() in {'1', 'true', 'yes'}
FORCE_HTTPS = os.environ.get('FORCE_HTTPS', '').lower() in {'1', 'true', 'yes'}

# Database settings
DATABASE_NAME = os.environ.get('DATABASE_NAME', 'links.db')

# Default admin user
DEFAULT_ADMIN_USERNAME = os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin')
DEFAULT_ADMIN_PASSWORD = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'admin')

# Server settings
HOST = os.environ.get('HOST', '0.0.0.0')
PORT = int(os.environ.get('PORT', '5000'))
