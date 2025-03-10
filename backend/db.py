# backend/db.py
import mysql.connector
from backend.config import DB_CONFIG

# Make a single connection & cursor available to routes
# Or you can do connection pooling, etc.
try:
    db = mysql.connector.connect(**DB_CONFIG)
    cursor = db.cursor()
    print("✅ Database connection established")
except mysql.connector.Error as e:
    print(f"❌ Database connection failed: {e}")
    raise SystemExit(1)  # Stop if DB fails

# Optionally create tables here or in app.py:
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role ENUM('admin','user') NOT NULL
)
""")
db.commit()
