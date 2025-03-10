from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins="*")  # Define socketio WITHOUT app binding
