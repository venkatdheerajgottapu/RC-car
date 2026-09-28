# config.py
# ------------------------------------
# This file holds all configurations
# like Secret Key, Database connection
# details, Email settings, Razorpay keys etc.
# ------------------------------------

SECRET_KEY = "your_secret_key_here"   # used for sessions

import os

# SQLite Database Configuration
# The database is stored locally in the project folder.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "smartcart.db")

# Email SMTP Settings
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'venkatdheerajgottapu@gmail.com'
MAIL_PASSWORD = 'czdm itqb gyha afwj'   # Gmail App Password

#===================RaZerpay=========
RAZORPAY_KEY_ID = "rzp_test_TcBFv9vujqInxt" # rzp_test_TLeM6Ox9b7K9Dp
RAZORPAY_KEY_SECRET = "OR8lpMjQqxP201Xk4L85qRzN" #dU4b4haEuqjJU1pc61pvF0UE

