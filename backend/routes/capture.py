import threading
from flask import Blueprint, jsonify
from backend.socketio_config import socketio  # ✅ Import socketio correctly
from modules.packet_capture import start_sniffing

capture_bp = Blueprint("capture", __name__)
capture_lock = threading.Lock()
capturing = False
capture_thread = None

@capture_bp.route("capture/start", methods=["POST"])
def start_capture():
    global capturing, capture_thread
    try:
        if capturing:
            return jsonify({"error": "Capture already running"}), 400

        capturing = True

        if socketio is not None:  # ✅ Fix for 'NoneType' error
            socketio.emit("capture_status", {"capturing": True})
        capture_thread = threading.Thread(target=start_sniffing, daemon=True)
        capture_thread.start()

        return jsonify({"message": "Packet capture started"})
    except Exception as e:
        print(f"❌ Error in start_capture: {e}")
        return jsonify({"error": "Internal server error"}), 500

@capture_bp.route("capture/stop", methods=["POST"])
def stop_capture():
    with capture_lock:
        if not capturing:
            return jsonify({"error": "No active capture"}), 400

        stop_capture_internal()
        return jsonify({"message": "Packet capture stopped"}), 200

def stop_capture_internal():
    global capturing, capture_thread

    if capture_thread is not None:
        print("🛑 Stopping packet capture thread...")
        capturing = False  # ✅ Make sure this is reset

        socketio.emit("capture_status", {"capturing": False})

        capture_thread.join()
        capture_thread = None  # ✅ Ensure capture thread is cleared
