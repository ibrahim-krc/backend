import os
import uuid
import json
import bcrypt, random
import base64
import sqlite3
from datetime import datetime, timedelta, date
from flask import (
    Flask,
    request,
    jsonify,
    session,
    g,
    copy_current_request_context,
    abort,
)
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from authlib.integrations.flask_client import OAuth
from jose import jwt, JWTError
from dotenv import load_dotenv
from threading import Lock
from collections import defaultdict
import time
import threading

# Load environment variables
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# Flask app setup
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET", "your-jwt-secret-key-here")
CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

# JWT config
JWT_SECRET = app.config["SECRET_KEY"]
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24 * 7

# OAuth setup
oauth = OAuth(app)
oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# SQLite3 setup
DATABASE = os.path.join(os.path.dirname(__file__), "yurtchat.db")


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


sayilar = {"bir": 1, "iki": 2, "üç": 3, "dört": 4, "beş": 5}


@app.route("/rastgele", methods=["GET"])
def rastgele_sayi():
    key = random.choice(list(sayilar.keys()))
    return jsonify({"anahtar": key, "sayi": sayilar[key]})


def init_db():
    with app.app_context():
        db = get_db()
        with open(os.path.join(os.path.dirname(__file__), "schema.sql"), "r") as f:
            db.executescript(f.read())
        db.execute(
            """
        CREATE TABLE IF NOT EXISTS message_views (
            message_id TEXT,
            user_id TEXT,
            seen_at TEXT,
            PRIMARY KEY (message_id, user_id),
            FOREIGN KEY (message_id) REFERENCES messages(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
        )
        db.execute(
            """
        CREATE TABLE IF NOT EXISTS banned_ips (
            ip TEXT PRIMARY KEY,
            banned_at TEXT
        );
        """
        )
        db.execute(
            """
        CREATE TABLE IF NOT EXISTS banned_users (
            user_id TEXT PRIMARY KEY,
            banned_at TEXT
        );
        """
        )
        db.commit()


# Utility functions
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def create_token(user_id: str) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


def get_current_user():
    auth_header = request.headers.get("Authorization", None)
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    payload = decode_token(token)
    if not payload:
        return None
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (payload["user_id"],)
    ).fetchone()
    return user


def get_current_user_socketio():
    # Socket.IO bağlantısında JWT'yi auth ile al
    from flask import request

    token = None
    if hasattr(request, "args") and "token" in request.args:
        token = request.args.get("token")
    elif (
        hasattr(request, "namespace")
        and hasattr(request.namespace, "auth")
        and request.namespace.auth
    ):
        token = request.namespace.auth.get("token")
    elif hasattr(request, "environ") and "HTTP_AUTHORIZATION" in request.environ:
        # fallback
        auth_header = request.environ["HTTP_AUTHORIZATION"]
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
    elif hasattr(request, "sid"):
        # Flask-SocketIO v5+ ile auth parametresi
        token = request.args.get("token")
    # Flask-SocketIO v5+ ile handshake sırasında auth parametresi
    if (
        not token
        and hasattr(request, "namespace")
        and hasattr(request.namespace, "socketio_auth")
    ):
        token = request.namespace.socketio_auth.get("token")
    if not token and hasattr(request, "auth") and request.auth:
        token = request.auth.get("token")
    if not token:
        # Yeni Flask-SocketIO ile handshake sırasında auth parametresi
        if hasattr(request, "args") and "auth" in request.args:
            try:
                auth = json.loads(request.args["auth"])
                token = auth.get("token")
            except Exception:
                pass
    if not token:
        # Flask-SocketIO v5+ handshake
        token = request.args.get("token")
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (payload["user_id"],)
    ).fetchone()
    return user


def get_client_ip():
    # X-Forwarded-For varsa ilk IP'yi al, yoksa remote_addr
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    if hasattr(request, "remote_addr"):
        return request.remote_addr
    # SocketIO için
    if hasattr(request, "environ") and "REMOTE_ADDR" in request.environ:
        return request.environ["REMOTE_ADDR"]
    return None


def is_banned(user_id=None, ip=None):
    db = get_db()
    if user_id:
        banned = db.execute(
            "SELECT 1 FROM banned_users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if banned:
            return True
    if ip:
        banned = db.execute("SELECT 1 FROM banned_ips WHERE ip = ?", (ip,)).fetchone()
        if banned:
            return True
    return False


# Girişte ve mesaj gönderirken ban kontrolü
@app.before_request
def check_ban():
    ip = get_client_ip()
    user = get_current_user()
    # Önce IP ban kontrolü
    if is_banned(ip=ip):
        abort(403, "IP adresiniz engellenmiş.")
    # Sonra kullanıcı ban kontrolü
    if user and is_banned(user_id=user["id"]):
        abort(403, "Kullanıcı engellenmiş.")


# --- ROUTES ---
# Register
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.json
    db = get_db()
    if db.execute("SELECT * FROM users WHERE email = ?", (data["email"],)).fetchone():
        return jsonify({"error": "Bu mail zaten kayıtlı."}), 400
    if db.execute(
        "SELECT * FROM users WHERE username = ?", (data["username"],)
    ).fetchone():
        return jsonify({"error": "Bu kullanıcı adı zaten alınmış."}), 400
    user_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO users (id, email, username, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
        (
            user_id,
            data["email"],
            data["username"],
            hash_password(data["password"]),
            now,
        ),
    )
    db.commit()
    token = create_token(user_id)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(
        {
            "token": token,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "username": user["username"],
                "profile_picture": user["profile_picture"],
                "created_at": user["created_at"],
            },
        }
    )


# Login
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE email = ?", (data["email"],)
    ).fetchone()
    if not user or not verify_password(data["password"], user["password_hash"]):
        return jsonify({"error": "Geçersiz kimlik bilgileri."}), 401
    token = create_token(user["id"])
    return jsonify(
        {
            "token": token,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "username": user["username"],
                "profile_picture": user["profile_picture"],
                "created_at": user["created_at"],
            },
        }
    )


# Google OAuth
@app.route("/api/auth/google")
def google_login():
    redirect_uri = request.host_url.rstrip("/") + "/api/auth/google/callback"
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/api/auth/google/callback")
def google_callback():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)
    db = get_db()
    existing_user = db.execute(
        "SELECT * FROM users WHERE google_id = ?", (user_info["sub"],)
    ).fetchone()
    if existing_user:
        user_id = existing_user["id"]
    else:
        username = user_info.get("name") or user_info["email"].split("@")[0]
        base_username = username
        counter = 1
        while db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone():
            username = f"{base_username}_{counter}"
            counter += 1
        user_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        db.execute(
            "INSERT INTO users (id, email, username, google_id, profile_picture, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                user_id,
                user_info["email"],
                username,
                user_info["sub"],
                user_info.get("picture"),
                now,
            ),
        )
        db.commit()
    token = create_token(user_id)
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(
        {
            "token": token,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "username": user["username"],
                "profile_picture": user["profile_picture"],
                "created_at": user["created_at"],
            },
        }
    )


# Get current user
@app.route("/api/users/me")
def get_me():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(
        {
            "id": user["id"],
            "email": user["email"],
            "username": user["username"],
            "profile_picture": user["profile_picture"],
            "created_at": user["created_at"],
        }
    )


# Update profile picture
@app.route("/api/users/me/profile-picture", methods=["PUT"])
def update_profile_picture():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    db = get_db()
    db.execute(
        "UPDATE users SET profile_picture = ? WHERE id = ?",
        (data["image_base64"], user["id"]),
    )
    db.commit()
    return jsonify({"message": "Profile picture updated successfully"})


# Block user
@app.route("/api/users/block", methods=["POST"])
def block_user():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO blocked_users (user_id, blocked_id) VALUES (?, ?)",
        (user["id"], data["user_id"]),
    )
    db.commit()
    return jsonify({"message": "User blocked successfully"})


# Unblock user
@app.route("/api/users/block/<user_id>", methods=["DELETE"])
def unblock_user(user_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    db.execute(
        "DELETE FROM blocked_users WHERE user_id = ? AND blocked_id = ?",
        (user["id"], user_id),
    )
    db.commit()
    return jsonify({"message": "User unblocked successfully"})


# Create confession
# Günde 3 itiraf hakkı ve gece sıfırlama
CONFESSION_LIMIT = 3
user_confession_count = defaultdict(lambda: {"date": None, "count": 0})


def reset_confession_counts():
    while True:
        now = datetime.now()
        next_midnight = datetime.combine(now.date(), datetime.min.time()) + timedelta(
            days=1
        )
        seconds_until_midnight = (next_midnight - now).total_seconds()
        time.sleep(seconds_until_midnight)
        for v in user_confession_count.values():
            v["date"] = None
            v["count"] = 0


threading.Thread(target=reset_confession_counts, daemon=True).start()


@app.route("/api/confessions", methods=["POST"])
def create_confession():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    today = date.today()
    info = user_confession_count[user["id"]]
    if info["date"] != today:
        info["date"] = today
        info["count"] = 0
    if info["count"] >= CONFESSION_LIMIT:
        return (
            jsonify(
                {"error": "Günlük itiraf hakkınızı doldurdunuz. Yarın tekrar deneyin."}
            ),
            429,
        )
    info["count"] += 1

    data = request.json
    confession_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    author_id = user["id"] if not data.get("is_anonymous", True) else None
    author_username = user["username"] if not data.get("is_anonymous", True) else None
    db = get_db()
    db.execute(
        "INSERT INTO confessions (id, content, is_anonymous, author_id, author_username, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            confession_id,
            data["content"],
            int(data.get("is_anonymous", True)),
            author_id,
            author_username,
            now,
        ),
    )
    db.commit()
    return jsonify(
        {
            "id": confession_id,
            "content": data["content"],
            "is_anonymous": data.get("is_anonymous", True),
            "author_id": author_id,
            "author_username": author_username,
            "created_at": now,
        }
    )


# Get confessions
@app.route("/api/confessions")
def get_confessions():
    limit = int(request.args.get("limit", 50))
    skip = int(request.args.get("skip", 0))
    db = get_db()
    confessions = db.execute(
        "SELECT * FROM confessions ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, skip),
    ).fetchall()
    return jsonify(
        [
            {
                "id": c["id"],
                "content": c["content"],
                "is_anonymous": bool(c["is_anonymous"]),
                "author_id": c["author_id"],
                "author_username": c["author_username"],
                "created_at": c["created_at"],
            }
            for c in confessions
        ]
    )


# Send message
# Mesaj spam koruması
MESSAGE_LIMIT = 10
MESSAGE_WINDOW = 10
BAN_DURATION = 30 * 60  # 30 dakika

user_message_times = defaultdict(list)  # user_id: [timestamp, ...]
user_ban_until = {}  # user_id: ban bitiş zamanı (timestamp)


@app.route("/api/messages", methods=["POST"])
def send_message():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    now_ts = int(time.time())
    uid = user["id"]
    ip = get_client_ip()

    # Ban kontrolü
    if is_banned(ip=ip):
        return jsonify({"error": "IP adresiniz engellenmiş."}), 403
    if uid in user_ban_until and now_ts < user_ban_until[uid]:
        remaining = user_ban_until[uid] - now_ts
        return (
            jsonify(
                {
                    "error": f"Çok fazla mesaj gönderdiniz. {remaining//60} dakika sonra tekrar deneyin."
                }
            ),
            429,
        )

    # Mesaj limiti kontrolü
    times = user_message_times[uid]
    times = [t for t in times if now_ts - t < MESSAGE_WINDOW]
    times.append(now_ts)
    user_message_times[uid] = times
    if len(times) > MESSAGE_LIMIT:
        user_ban_until[uid] = now_ts + BAN_DURATION
        return (
            jsonify(
                {
                    "error": "Çok fazla mesaj gönderdiniz. 30 dakika boyunca mesaj gönderemezsiniz."
                }
            ),
            429,
        )

    data = request.json
    message_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    db = get_db()
    (
        db.execute("ALTER TABLE messages ADD COLUMN ip TEXT")
        if "ip"
        not in [col[1] for col in db.execute("PRAGMA table_info(messages)").fetchall()]
        else None
    )
    db.execute(
        "INSERT INTO messages (id, content, sender_id, sender_username, receiver_id, image_base64, created_at, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            message_id,
            data["content"],
            user["id"],
            user["username"],
            data.get("receiver_id"),
            data.get("image_base64"),
            now,
            ip,
        ),
    )
    db.commit()
    message = {
        "id": message_id,
        "content": data["content"],
        "sender_id": user["id"],
        "sender_username": user["username"],
        "sender_profile_picture": user["profile_picture"],
        "receiver_id": data.get("receiver_id"),
        "image_base64": data.get("image_base64"),
        "created_at": now,
        "sender_ip": ip,
    }
    # WebSocket broadcast
    if data.get("receiver_id"):
        socketio.emit("private_message", message, room=data["receiver_id"])
    else:
        socketio.emit("general_message", message, to=None)
    return jsonify(message)


# Get general messages
@app.route("/api/messages/general")
def get_general_messages():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    limit = int(request.args.get("limit", 50))
    skip = int(request.args.get("skip", 0))
    db = get_db()
    messages = db.execute(
        "SELECT m.*, u.profile_picture as sender_profile_picture FROM messages m LEFT JOIN users u ON m.sender_id = u.id WHERE m.receiver_id IS NULL ORDER BY m.created_at DESC LIMIT ? OFFSET ?",
        (limit, skip),
    ).fetchall()
    return jsonify(
        [
            {
                "id": m["id"],
                "content": m["content"],
                "sender_id": m["sender_id"],
                "sender_username": m["sender_username"],
                "sender_profile_picture": m["sender_profile_picture"],
                "receiver_id": m["receiver_id"],
                "image_base64": m["image_base64"],
                "created_at": m["created_at"],
            }
            for m in messages
        ]
    )


# Get private messages
@app.route("/api/messages/private/<user_id>")
def get_private_messages(user_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    limit = int(request.args.get("limit", 50))
    skip = int(request.args.get("skip", 0))
    db = get_db()
    messages = db.execute(
        "SELECT * FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (user["id"], user_id, user_id, user["id"], limit, skip),
    ).fetchall()
    return jsonify(
        [
            {
                "id": m["id"],
                "content": m["content"],
                "sender_id": m["sender_id"],
                "sender_username": m["sender_username"],
                "sender_profile_picture": m["sender_profile_picture"],
                "receiver_id": m["receiver_id"],
                "image_base64": m["image_base64"],
                "created_at": m["created_at"],
            }
            for m in messages
        ]
    )


# Get users
@app.route("/api/users")
def get_users():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    users = db.execute("SELECT * FROM users WHERE id != ?", (user["id"],)).fetchall()
    return jsonify(
        [
            {
                "id": u["id"],
                "email": u["email"],
                "username": u["username"],
                "profile_picture": u["profile_picture"],
                "created_at": u["created_at"],
            }
            for u in users
        ]
    )


# --- SOCKET.IO ---
online_users = set()
online_users_lock = Lock()
sid_to_user = {}
user_sid_count = defaultdict(int)


def broadcast_online_users():
    with online_users_lock:
        db = get_db()
        users = []
        for uid in online_users:
            user = db.execute(
                "SELECT id, username, profile_picture FROM users WHERE id = ?", (uid,)
            ).fetchone()
            if user:
                users.append(
                    {
                        "id": user["id"],
                        "username": user["username"],
                        "profile_picture": user["profile_picture"],
                    }
                )
        socketio.emit("online_users", users, to=None)  # broadcast için to=None


@socketio.on("connect")
def handle_connect(auth=None):
    ip = get_client_ip()
    if is_banned(ip=ip):
        return False
    user = None
    if auth and "token" in auth:
        token = auth["token"]
        payload = decode_token(token)
        if payload:
            db = get_db()
            user = db.execute(
                "SELECT * FROM users WHERE id = ?", (payload["user_id"],)
            ).fetchone()
    if not user:
        user = get_current_user_socketio()
    if user and is_banned(user_id=user["id"]):
        return False
    if user:
        join_room(user["id"])
        sid_to_user[request.sid] = user["id"]
        with online_users_lock:
            user_sid_count[user["id"]] += 1
            online_users.add(user["id"])
        broadcast_online_users()
    else:
        return False


@socketio.on("disconnect")
def handle_disconnect():
    sid = request.sid
    user_id = sid_to_user.pop(sid, None)
    if user_id:
        leave_room(user_id)
        with online_users_lock:
            user_sid_count[user_id] -= 1
            if user_sid_count[user_id] <= 0:
                online_users.discard(user_id)
                user_sid_count[user_id] = 0
        broadcast_online_users()


@socketio.on("typing")
def handle_typing(data):
    print(f"User {data['user_id']} is typing")
    user = get_current_user_socketio()
    if user:
        socketio.emit(
            "user_typing",
            {"user_id": user["id"], "username": user["username"]},
            to=None,
        )


# Engelleme işlemi (Socket.IO event)
ADMIN_BLOCK_KEY = os.environ.get("ADMIN_BLOCK_KEY", "supersecretkey")


@socketio.on("block_user_and_ip")
def handle_block_user_and_ip(data):
    key = data.get("key")
    target_user_id = data.get("user_id")
    target_ip = data.get("ip")
    db = get_db()
    now = datetime.utcnow().isoformat()
    # Eğer kullanıcı id verildiyse, o kullanıcının ip'sini de engelle
    if target_user_id and not target_ip:
        user_row = db.execute(
            "SELECT id FROM users WHERE id = ?", (target_user_id,)
        ).fetchone()
        if user_row:
            # Son mesajlardan ip bulmaya çalış
            ip_row = db.execute(
                "SELECT ip FROM messages WHERE sender_id = ? AND ip IS NOT NULL ORDER BY created_at DESC LIMIT 1",
                (target_user_id,),
            ).fetchone()
            if ip_row and ip_row["ip"]:
                target_ip = ip_row["ip"]
    if key != ADMIN_BLOCK_KEY:
        emit("block_result", {"success": False, "error": "Anahtar hatalı."})
        return
    if target_user_id:
        db.execute(
            "INSERT OR IGNORE INTO banned_users (user_id, banned_at) VALUES (?, ?)",
            (target_user_id, now),
        )
    if target_ip:
        db.execute(
            "INSERT OR IGNORE INTO banned_ips (ip, banned_at) VALUES (?, ?)",
            (target_ip, now),
        )
    db.commit()
    emit("block_result", {"success": True})


# Mesaj silme işlemi (Socket.IO event)
@socketio.on("delete_message_admin")
def handle_delete_message_admin(data):
    key = data.get("key")
    message_id = data.get("message_id")
    if key != ADMIN_BLOCK_KEY:
        emit("delete_message_result", {"success": False, "error": "Anahtar hatalı."})
        return
    db = get_db()
    db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    db.execute("DELETE FROM message_views WHERE message_id = ?", (message_id,))
    db.commit()
    emit("delete_message_result", {"success": True, "message_id": message_id})


# Mesaj görenler listesini REST API ile de döndür (isteğe bağlı)
@app.route("/api/messages/<message_id>/viewers")
def get_message_viewers(message_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    viewers = db.execute(
        "SELECT u.id, u.username FROM message_views mv JOIN users u ON mv.user_id = u.id WHERE mv.message_id = ?",
        (message_id,),
    ).fetchall()
    return jsonify([{"id": v["id"], "username": v["username"]} for v in viewers])


if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        init_db()
    socketio.run(app, host="0.0.0.0", port=8080)
