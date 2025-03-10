# backend/app.py
import os
import sys
import pandas as pd
from flask import Flask, jsonify
from flask_cors import CORS
from .socketio_config import socketio
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager

from .config import SECRET_KEY, JWT_SECRET_KEY
from .db import db, cursor  # So we can do any final DB steps if needed

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})




socketio.init_app(app, cors_allowed_origins="*")

app.config["SECRET_KEY"] = SECRET_KEY
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Import your routes
from .routes.auth import auth_bp
from .routes.capture import capture_bp
from .routes.logs import logs_bp
from .routes.settings import settings_bp
from .routes.protected import protected_bp


# Register them
app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(capture_bp, url_prefix="/api")
app.register_blueprint(logs_bp, url_prefix="/api")
app.register_blueprint(settings_bp, url_prefix="/api")
app.register_blueprint(protected_bp,  url_prefix="/api/protected")


LOG_FILE = "C:/Users/EFAC/PycharmProjects/NIDS/logs/traffic_log.csv"

def emit_packet_count():
    """Emit the current packet count in real-time."""
    if os.path.exists(LOG_FILE):
        df = pd.read_csv(LOG_FILE)
        socketio.emit("packet_count", {"count": len(df)})

def log_traffic(traffic_data):
    """Log network traffic and emit real-time updates."""
    traffic_data.to_csv(LOG_FILE, mode="a", header=not os.path.exists(LOG_FILE), index=False)
    socketio.emit("packet_count", {"count": len(traffic_data)})


if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=True, allow_unsafe_werkzeug=True)
