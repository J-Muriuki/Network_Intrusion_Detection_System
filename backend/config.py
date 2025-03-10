import os
import mysql.connector

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "#Jamesisaguru254",
    "database": "nids_auth_db"
}

SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your_jwt_secret")

# Initialize MySQL connection
#try:
   # db = mysql.connector.connect(
      #  host=DB_CONFIG["host"],
        #user=DB_CONFIG["user"],
       # password=DB_CONFIG["password"],
        #database=DB_CONFIG["database"]
   # )
    #cursor = db.cursor(dictionary=True)  # Use dictionary cursor for easy handling of results
    #print("✅ Database connection established")
#except mysql.connector.Error as err:
    #print(f"❌ Database connection failed: {err}")
   # db = None
    #cursor = None
