#!/usr/bin/env python3
"""
Ghost Projects Chat - single-file Flask + Socket.IO application.
Optimized for Vercel deployment with local SQLite database.
UI bugs fixed and enhanced.
"""

import os
import json
import secrets
import logging
from datetime import datetime, timezone
from functools import wraps
from flask import (
    Flask, request, redirect, url_for, send_from_directory, render_template_string,
    jsonify, flash, abort, session as flask_session
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from flask_socketio import SocketIO, join_room, leave_room
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text as sa_text

# Optional libs
try:
    import markdown
    def render_md(s):
        return markdown.markdown(s or "", extensions=["fenced_code", "codehilite"])
except Exception:
    def render_md(s):
        return "<pre>{}</pre>".format((s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))

try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

try:
    import bleach
    def sanitize_html(html):
        base_tags = getattr(bleach.sanitizer, "ALLOWED_TAGS", getattr(bleach, "ALLOWED_TAGS", []))
        allowed = set(base_tags) | {"pre","code","img"}
        return bleach.clean(html or "", tags=list(allowed),
                            attributes={"a":["href","title","rel","target"], "img":["src","alt","loading"]},
                            strip=True)
except Exception:
    def sanitize_html(html):
        return html or ""

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ghost_chat")

# Configuration - Use /tmp for Vercel compatibility
BASE_DIR = "/tmp" if os.environ.get("VERCEL") else os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "chat.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
STICKER_FOLDER = os.path.join(BASE_DIR, "stickers")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STICKER_FOLDER, exist_ok=True)

ALLOWED_IMAGE_EXT = {"png","jpg","jpeg","gif","webp"}
ALLOWED_VIDEO_EXT = {"mp4","webm","ogg","mov"}
MAX_FILE_SIZE = 25 * 1024 * 1024   # 25 MB
MAX_FILES_PER_MESSAGE = 5
THUMB_MAX_SIZE = (1024, 1024)
LONG_MESSAGE_LIMIT = 300  # chars; over this, server writes a .txt file and attaches it
DEFAULT_AVATAR = "https://i.ibb.co/3mwVTQw9/x.jpg"

# ✅ Generate SECRET_KEY internally if not provided
SECRET_KEY = secrets.token_hex(32)

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", f"sqlite:///{DB_PATH}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["STICKER_FOLDER"] = STICKER_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 6 * MAX_FILE_SIZE
app.logger.setLevel(logging.DEBUG)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# For Vercel, we need to use threading for Socket.IO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---------------------------
# Models
# ---------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    display_name = db.Column(db.String(120))
    avatar = db.Column(db.String(256))
    bio = db.Column(db.Text)
    session_version = db.Column(db.Integer, default=0)
    last_seen = db.Column(db.DateTime)
    show_online = db.Column(db.Boolean, default=True)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    name = db.Column(db.String(120), nullable=False)
    room_key = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def check_password(self, pw):
        if not self.password_hash:
            return pw in (None, "", "")
        return check_password_hash(self.password_hash, pw or "")

class RoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("room.id"), index=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    text = db.Column(db.Text)
    rendered = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), index=True)
    reply_to = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=True)
    edited = db.Column(db.Boolean, default=False)
    edited_at = db.Column(db.DateTime)
    pinned = db.Column(db.Boolean, default=False)
    pinned_at = db.Column(db.DateTime)
    chat_id = db.Column(db.Integer, nullable=False, default=1, server_default=sa_text("1"))
    attachments = db.Column(db.Text, nullable=True)  # json list of {"filename","type"}
    reactions = db.Column(db.Text, nullable=True)
    read_by = db.Column(db.Text, nullable=True)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    text = db.Column(db.Text)
    link = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    seen = db.Column(db.Boolean, default=False)

# ---------------------------
# Helpers & stickers
# ---------------------------
def init_stickers():
    samples = {
        "sticker-smile.svg": "<svg xmlns='http://www.w3.org/2000/svg' width='200' height='200'><rect width='200' height='200' rx='20' fill='#ffd54f'/><circle cx='100' cy='90' r='50' fill='#fff59d'/><circle cx='80' cy='80' r='8' fill='#000'/><circle cx='120' cy='80' r='8' fill='#000'/><path d='M70 120 Q100 150 130 120' stroke='#000' stroke-width='6' fill='none' stroke-linecap='round'/></svg>",
        "sticker-heart.svg": "<svg xmlns='http://www.w3.org/2000/svg' width='200' height='200'><rect width='200' height='200' rx='20' fill='#f8bbd0'/><path d='M100 150 L80 130 C30 90 60 40 100 70 C140 40 170 90 120 130 Z' fill='#e91e63'/></svg>",
    }
    for name, svg in samples.items():
        path = os.path.join(STICKER_FOLDER, name)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(svg)

init_stickers()

def allowed_extension(filename):
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_IMAGE_EXT or ext in ALLOWED_VIDEO_EXT

def kind_from_ext(filename):
    ext = filename.rsplit(".", 1)[1].lower()
    if ext in ALLOWED_IMAGE_EXT: return "image"
    if ext in ALLOWED_VIDEO_EXT: return "video"
    return "file"

def url_upload(fn):
    if not fn: return ""
    try:
        return url_for("uploaded_file", filename=fn)
    except Exception:
        return ""

def url_sticker(fn):
    try:
        return url_for("sticker_file", filename=fn)
    except Exception:
        return ""

def url_static_asset(fn):
    if fn == "default-avatar.png":
        return DEFAULT_AVATAR
    try:
        return url_for("static_asset", path=fn)
    except Exception:
        return ""

def user_to_dict(u):
    if not u:
        return {"id": None, "username":"system","display_name":"System","avatar": DEFAULT_AVATAR}
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name or u.username,
        "avatar": url_upload(u.avatar) if u.avatar else DEFAULT_AVATAR,
        "bio": u.bio or "",
        "last_seen": u.last_seen.isoformat() if u.last_seen else None
    }

# ---------------------------
# Migration helper
# ---------------------------
def ensure_message_columns():
    conn = None
    try:
        conn = db.engine.connect()
        logger.info("Running migration check: PRAGMA table_info(message)")
        res = conn.execute(sa_text("PRAGMA table_info(message)")).fetchall()
        existing_cols = [r[1] for r in res]
        logger.debug("Message columns: %s", existing_cols)
        to_add = []
        if "attachments" not in existing_cols: to_add.append(("attachments","TEXT","''"))
        if "reactions" not in existing_cols: to_add.append(("reactions","TEXT","'{}'"))
        if "read_by" not in existing_cols: to_add.append(("read_by","TEXT","'[]'"))
        if "chat_id" not in existing_cols: to_add.append(("chat_id","INTEGER","1"))
        if "edited" not in existing_cols: to_add.append(("edited","BOOLEAN","0"))
        if "edited_at" not in existing_cols: to_add.append(("edited_at","DATETIME","NULL"))
        for name, typ, default in to_add:
            try:
                sql = f"ALTER TABLE message ADD COLUMN {name} {typ} DEFAULT {default}"
                logger.info("MIGRATE: %s", sql)
                conn.execute(sa_text(sql))
            except Exception:
                logger.exception("Failed to add column %s", name)
    except Exception:
        logger.exception("Migration check failed")
    finally:
        if conn: conn.close()

# ---------------------------
# Flask-Login
# ---------------------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

@app.before_request
def ensure_room_in_session():
    if getattr(current_user, "is_authenticated", False):
        if flask_session.get("room_id") is None:
            flask_session["room_id"] = 1

# ---------------------------
# Presence / sid_room mapping
# ---------------------------
online_user_sids = {}
sid_user = {}
sid_room = {}  # sid -> room_id

def mark_online(uid, sid):
    online_user_sids.setdefault(uid, set()).add(sid)
    sid_user[sid] = uid
    u = db.session.get(User, uid)
    if u:
        u.last_seen = datetime.now(timezone.utc)
        db.session.commit()

def mark_offline(sid):
    uid = sid_user.pop(sid, None)
    if uid:
        s = online_user_sids.get(uid)
        if s:
            s.discard(sid)
            if not s:
                online_user_sids.pop(uid, None)
                u = db.session.get(User, uid)
                if u:
                    u.last_seen = datetime.now(timezone.utc)
                    db.session.commit()
    sid_room.pop(sid, None)

def push_notification(user_id, payload):
    try:
        n = Notification(user_id=user_id, text=payload.get("text",""), link=payload.get("link",""))
        db.session.add(n); db.session.commit()
        sids = online_user_sids.get(user_id, set())
        for sid in sids:
            socketio.emit("notification", {"id": n.id, "text": n.text, "link": n.link, "created_at": n.created_at.isoformat()}, room=sid)
    except Exception:
        logger.exception("Failed to push notification to user %s", user_id)

# ---------------------------
# CSP header (development)
# ---------------------------
@app.after_request
def add_csp_headers(response):
    csp = (
        "default-src 'self' https: data:; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "connect-src 'self' ws: wss: https:; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    )
    response.headers.setdefault("Content-Security-Policy", csp)
    return response

# ---------------------------
# Static routes
# ---------------------------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/stickers/<path:filename>")
def sticker_file(filename):
    return send_from_directory(app.config["STICKER_FOLDER"], filename)

@app.route("/static/<path:path>")
def static_asset(path):
    if path == "default-avatar.png":
        return redirect(DEFAULT_AVATAR)
    abort(404)

# ---------------------------
# HTML templates (LOGIN/REGISTER/MAIN)
# ---------------------------
LOGIN_HTML = """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ghost Projects — Sign in</title>
<style>
:root{--bg:#071027;--card:#0f1724;--accent:#7c3aed;--muted:#94a3b8;--text:#e6eef8}
*{box-sizing:border-box;font-family:Inter,system-ui,Arial}
body{margin:0;background:linear-gradient(180deg,#071027,#041328);min-height:100vh;display:flex;align-items:center;justify-content:center;color:var(--text)}
.card{width:92%;max-width:420px;background:var(--card);padding:22px;border-radius:14px;box-shadow:0 12px 40px rgba(0,0,0,0.6)}
h2{margin:0 0 10px;font-size:20px}
input, textarea{width:100%;padding:12px;border-radius:10px;border:1px solid rgba(255,255,255,0.04);background:transparent;color:var(--text);margin:8px 0}
button{width:100%;padding:12px;border-radius:10px;border:none;background:var(--accent);color:white;font-weight:700}
.small{font-size:13px;color:var(--muted);text-align:center;margin-top:10px}
a{color:var(--accent)}
.flash{color:#ffd8a8;margin-bottom:8px}
</style></head><body>
<div class="card">
  <h2>Ghost Projects — Sign in</h2>
  {% with messages = get_flashed_messages() %}
    {% if messages %}<div class="flash">{{ messages[0] }}</div>{% endif %}
  {% endwith %}
  <form method="post" action="{{ url_for('login') }}">
    <input name="username" placeholder="username" autofocus />
    <input name="password" type="password" placeholder="password" />
    <label style="display:block;margin:6px 0"><input type="checkbox" name="remember"> Remember me</label>
    <button>Sign in</button>
  </form>
  <div class="small">New? <a href="{{ url_for('register') }}">Create account</a></div>
</div>
</body></html>"""

REGISTER_HTML = """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ghost Projects — Register</title>
<style>
:root{--card:#fff;--accent:#00b894;--muted:#5b6b7a}
*{box-sizing:border-box;font-family:Inter,system-ui,Arial}
body{margin:0;background:linear-gradient(180deg,#f0f6ff,#eaf2ff);min-height:100vh;display:flex;align-items:center;justify-content:center;color:#071027}
.card{width:92%;max-width:420px;background:var(--card);padding:22px;border-radius:12px;box-shadow:0 12px 40px rgba(0,0,0,0.06)}
h2{margin:0 0 10px}
input{width:100%;padding:12px;border-radius:10px;border:1px solid #e6eef8;background:#fbfdff;margin:8px 0}
button{width:100%;padding:12px;border-radius:10px;border:none;background:var(--accent);color:white;font-weight:700}
.small{font-size:13px;color:var(--muted);text-align:center;margin-top:10px}
.note{font-size:12px;color:#334155;margin-top:6px}
</style></head><body>
<div class="card">
  <h2>Create account</h2>
  <form method="post" action="{{ url_for('register') }}">
    <input name="username" placeholder="username" required>
    <input name="display_name" placeholder="Display name (Please enter your telegram profile name)">
    <div class="note">Please enter your Telegram profile name in the display name field so people can find you.</div>
    <input name="password" type="password" placeholder="password" required>
    <button>Create account</button>
  </form>
  <div class="small">Have an account? <a href="{{ url_for('login') }}">Sign in</a></div>
</div>
</body></html>"""

NOTFOUND_HTML = """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>404</title></head><body style="font-family:Inter,Arial;padding:24px;background:#f7fafc;color:#0b1220">
<h1>404 — Not found</h1><p>The requested URL was not found on the server.</p><p><a href="{{ url_for('index') }}">Home</a></p></body></html>"""

MAIN_HTML = """<!doctype html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Ghost Projects Chat</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#041328; --card:#0f1724; --accent:#7c3aed; --muted:#94a3b8; --text:#e6eef8;
  --panel:#0b1220; --glass: rgba(255,255,255,0.03);
}
*{box-sizing:border-box;font-family:Inter,system-ui,Arial}
html,body{height:100%;margin:0;background:linear-gradient(180deg,#071027,#041328);color:var(--text)}
.app{display:flex;flex-direction:column;height:100vh;max-height:100vh}
.header{display:flex;align-items:center;gap:12px;padding:12px;border-bottom:1px solid rgba(255,255,255,0.03)}
.avatar{width:48px;height:48px;border-radius:12px;overflow:hidden}
.avatar img{width:100%;height:100%;object-fit:cover}
.title{font-weight:700}
.presence{font-size:13px;color:var(--muted)}
.hamburger{width:44px;height:44px;background:var(--glass);border-radius:10px;display:flex;align-items:center;justify-content:center;cursor:pointer}
.rooms-panel{position:fixed;left:12px;top:72px;background:var(--panel);padding:8px;border-radius:10px;max-width:320px;display:none;z-index:999;box-shadow:0 10px 30px rgba(0,0,0,0.6)}
.rooms-panel .room{padding:8px;border-radius:8px;cursor:pointer}
.rooms-panel .room.active{background:rgba(255,255,255,0.02);font-weight:700}
.messages{flex:1;overflow:auto;padding:12px 12px 170px 12px;-webkit-overflow-scrolling:touch;scroll-behavior:smooth}
.msg{max-width:84%;padding:12px;border-radius:12px;margin-bottom:10px;background:linear-gradient(180deg,#081427,#061225);box-shadow:0 6px 18px rgba(0,0,0,0.5);position:relative}
.msg.me{align-self:flex-end;background:linear-gradient(90deg,var(--accent),#5b21b6);color:white}
.meta{font-size:12px;color:var(--muted);margin-bottom:6px}
.attach{margin-top:8px;display:flex;gap:8px;flex-wrap:wrap}
.attach img, .attach video{max-width:180px;border-radius:10px;object-fit:cover;max-height:260px}
.reactions{display:flex;gap:6px;margin-top:6px}
.react-pill{background:rgba(255,255,255,0.04);padding:4px 8px;border-radius:999px;font-size:13px}
.msg .actions{position:absolute;right:8px;top:8px;opacity:0;transition:opacity .15s}
.msg:hover .actions{opacity:1}
.bottom{position:fixed;left:0;right:0;bottom:0;padding:10px;background:linear-gradient(180deg, rgba(0,0,0,0.35), rgba(0,0,0,0.0));display:flex;justify-content:center;z-index:50}
.inputbar{width:100%;max-width:960px;padding:8px;background:var(--card);border-radius:14px;display:flex;gap:8px;align-items:center;box-shadow:0 8px 30px rgba(0,0,0,0.6);margin:0 12px 12px}
.icon{width:46px;height:46px;border-radius:12px;background:var(--glass);display:flex;align-items:center;justify-content:center;border:none;color:var(--text);font-size:20px;cursor:pointer}
.textarea{flex:1;border:none;background:transparent;color:var(--text);outline:none;padding:6px 8px;border-radius:10px;min-height:44px;max-height:120px;resize:none}
.send{padding:10px 14px;border-radius:12px;border:none;background:linear-gradient(90deg,var(--accent),#5b21b6);color:white;font-weight:700;cursor:pointer}
.preview-row{position:fixed;left:12px;right:12px;bottom:84px;display:flex;gap:8px;overflow:auto;padding:8px}
.preview-thumb{width:84px;height:84px;border-radius:10px;object-fit:cover}
.toast{position:fixed;left:50%;transform:translateX(-50%);bottom:180px;background:rgba(0,0,0,0.8);color:#fff;padding:10px 14px;border-radius:10px;z-index:9999;opacity:0;transition:all .3s}
.toast.show{opacity:1;bottom:200px}
.notif-center{position:fixed;right:12px;top:72px;background:var(--panel);padding:10px;border-radius:12px;max-width:360px;display:none;z-index:999;box-shadow:0 10px 40px rgba(0,0,0,0.6)}
.settings-modal{position:fixed;right:12px;bottom:84px;background:var(--panel);padding:12px;border-radius:12px;max-width:420px;display:none;z-index:999;box-shadow:0 10px 40px rgba(0,0,0,0.6)}
.settings-modal h3{margin:6px 0}
.settings-row{display:flex;gap:8px;align-items:center;margin:8px 0}
.settings-row input, .settings-row textarea{flex:1;padding:8px;border-radius:8px;border:1px solid rgba(255,255,255,0.04);background:transparent;color:var(--text)}
.room-item{padding:8px;border-radius:8px;background:rgba(255,255,255,0.02);margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.small-muted{font-size:12px;color:var(--muted)}
.copy-btn{padding:8px 10px;border-radius:8px;border:none;background:rgba(255,255,255,0.03);color:var(--text);cursor:pointer}
.full-btn{width:100%;padding:12px;border-radius:10px;border:none;background:var(--accent);color:#fff;font-weight:700;cursor:pointer}
.reply-banner{position:fixed;left:12px;right:12px;bottom:140px;background:var(--panel);padding:8px 12px;border-radius:10px;display:flex;justify-content:space-between;align-items:center;z-index:50}
@media (max-width:540px){
  .settings-modal{left:8px;right:8px;max-width:calc(100% - 16px);bottom:120px}
  .settings-row{flex-direction:column;align-items:stretch}
  .copy-btn, .full-btn{width:100%}
  .reply-banner{left:8px;right:8px}
}
</style>
</head><body>
<div class="app">
  <div class="header">
    <div class="hamburger" id="btn_hamburger" title="Rooms">☰</div>
    <div class="avatar"><img id="my_avatar" src="{{ user['avatar'] }}"></div>
    <div>
      <div class="title" id="chat_title">{{ current_room_name }}</div>
      <div class="presence" id="presence">Connected</div>
    </div>
    <div style="flex:1"></div>
    <div style="display:flex;gap:8px">
      <button id="btn_notif" class="icon" title="Notifications">🔔</button>
      <button id="btn_settings" class="icon" title="Settings">⚙️</button>
      <a href="/logout" class="icon" title="Logout">⤴️</a>
    </div>
  </div>
  <div id="rooms_panel" class="rooms-panel"></div>
  <div id="messages" class="messages" role="log" aria-live="polite"></div>
  <div id="preview" class="preview-row"></div>
  <div class="bottom">
    <div class="inputbar" role="form" aria-label="Send message">
      <button id="btn_file" class="icon" title="Attach">📎</button>
      <button id="btn_sticker" class="icon" title="Stickers">😊</button>
      <textarea id="input" class="textarea" placeholder="Message"></textarea>
      <button id="btn_send" class="send">Send</button>
    </div>
  </div>
  <div id="toast" class="toast"></div>
  <div id="notif_center" class="notif-center"></div>
  <div id="settings_modal" class="settings-modal"></div>
</div>
<input id="file_input" type="file" accept="image/*,video/*" multiple style="display:none">
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.1/socket.io.min.js"></script>
<script>
const MAX_FILES = {{ max_files }};
const IMAGE_EXTS = {{ image_exts|tojson }};
const VIDEO_EXTS = {{ video_exts|tojson }};
const MAX_FILE_SIZE = {{ max_file_size }};
const INITIAL_ROOM_ID = {{ room_id }};
// Injected user info
const MY_USERNAME = {{ user['username']|tojson }};
const MY_ID = {{ user['id'] if user and user.get('id') is not none else 'null' }};
let socket;
let selected = []; // {file, preview, type, uploadedName}
const messagesEl = document.getElementById("messages");
const inputEl = document.getElementById("input");
const fileInput = document.getElementById("file_input");
const previewEl = document.getElementById("preview");
const toast = document.getElementById("toast");
const notifCenter = document.getElementById("notif_center");
const roomsPanel = document.getElementById("rooms_panel");
const settingsModal = document.getElementById("settings_modal");
const chatTitle = document.getElementById("chat_title");
let currentRoomId = INITIAL_ROOM_ID;
let replyTo = null;

function showToast(msg, timeout=2500){
  toast.textContent = msg;
  toast.classList.add("show");
  setTimeout(()=> toast.classList.remove("show"), timeout);
}

function init(){
  // prefer websocket, fallback to polling
  socket = io({transports:["websocket","polling"], upgrade:true});
  socket.on("connect", ()=> {
    console.log("socket connected");
    try { socket.emit("switch_room", {room_id: currentRoomId}); } catch(e){}
  });
  socket.on("connect_error", (err)=> console.warn("socket connect error", err));
  socket.on("new_message", onNewMessageEvent);
  socket.on("reaction", onReactionEvent);
  socket.on("edit", onEditEvent);
  socket.on("delete", onDeleteEvent);
  socket.on("pinned", onPinnedEvent);
  socket.on("presence", d=> updatePresence(d));
  socket.on("notification", n=> showToast(n.text || "Notification"));
  socket.on("typing", d=> showTyping(d));
  socket.on("read_receipt", d=> {});
  loadMessages();
  loadRooms();
  document.getElementById("btn_send").addEventListener("click", sendMessage);
  document.getElementById("btn_file").addEventListener("click", ()=> fileInput.click());
  fileInput.addEventListener("change", handleFiles);
  document.getElementById("btn_sticker").addEventListener("click", toggleStickers);
  document.getElementById("btn_notif").addEventListener("click", showNotifCenter);
  document.getElementById("btn_settings").addEventListener("click", toggleSettings);
  document.getElementById("btn_hamburger").addEventListener("click", toggleRoomsPanel);
  inputEl.addEventListener("input", ()=> {
    try { socket.emit("typing", {is_typing: true}); } catch(e){}
    clearTimeout(window._typingTimer);
    window._typingTimer = setTimeout(()=> { try { socket.emit("typing", {is_typing: false}); } catch(e){} }, 1000);
  });
  window.addEventListener("resize", ()=> messagesEl.scrollTop = messagesEl.scrollHeight);
  messagesEl.addEventListener("click", handleMessageClick);
  addSwipeListeners();
}

async function loadRooms(){
  const r = await fetch("/api/rooms");
  const j = await r.json();
  roomsPanel.innerHTML = "";
  j.rooms.forEach(room=>{
    const el = document.createElement("div"); el.className="room"; el.textContent = room.name; el.dataset.id = room.id;
    if(room.id == j.current) el.classList.add("active");
    el.onclick = ()=> switchRoom(room.id);
    roomsPanel.appendChild(el);
  });
  currentRoomId = j.current;
}

async function switchRoom(rid){
  const r = await fetch("/api/switch_room", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({room_id: rid})});
  const j = await r.json();
  if(!j.ok) { showToast(j.error || "Cannot switch"); return; }
  currentRoomId = rid;
  roomsPanel.querySelectorAll(".room").forEach(el=> el.classList.toggle("active", el.dataset.id == rid));
  try { socket.emit("switch_room", {room_id: rid}); } catch(e){}
  await loadMessages();
  const m = await fetch("/api/messages?limit=1");
  const mj = await m.json();
  if(mj.room) chatTitle.textContent = mj.room.name;
  showToast("Switched room");
}

function toggleRoomsPanel(){
  roomsPanel.style.display = roomsPanel.style.display === "block" ? "none" : "block";
}

function updatePresence(data) {
  const p = document.getElementById("presence");
  if (data.online) {
    p.textContent = "Online";
  } else {
    p.textContent = "Offline";
  }
}

function toggleSettings(){
  if(settingsModal.style.display === "block"){ settingsModal.style.display = "none"; return; }
  settingsModal.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h3>Settings</h3>
      <button id="close_settings" class="copy-btn">✕</button>
    </div>
    <div style="margin-top:8px;">
      <strong>Profile</strong>
      <div style="margin-top:8px">
        <div class="settings-row">
          <img id="settings_avatar_preview" src="{{ user['avatar'] }}" style="width:64px;height:64px;border-radius:12px;object-fit:cover">
          <div style="flex:1">
            <input id="settings_display" placeholder="Display name (Please enter your telegram profile name)" value="{{ user['display_name'] or user['username'] }}">
            <input id="settings_username" placeholder="Username" value="{{ user['username'] }}">
            <textarea id="settings_bio" placeholder="Bio" rows="2">{{ user['bio'] or '' }}</textarea>
            <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
              <input id="settings_avatar_file" type="file" accept="image/*" style="display:none">
              <button id="btn_change_avatar" class="copy-btn">Change avatar</button>
              <button id="btn_save_profile" class="full-btn">Save profile</button>
            </div>
          </div>
        </div>
      </div>
      <hr style="border:none;border-top:1px solid rgba(255,255,255,0.04);margin:12px 0">
      <strong>Create room</strong>
      <div style="margin-top:8px" id="create_room_box">
        <div class="settings-row">
          <input id="create_room_name" placeholder="Room name">
          <input id="create_room_password" placeholder="Optional password">
        </div>
        <div style="margin-top:8px">
          <button id="btn_create_room" class="full-btn">Create room</button>
        </div>
        <div class="small-muted" style="margin-top:8px">After create you'll see the room key (copied to clipboard). Share it to let others join.</div>
      </div>
      <hr style="border:none;border-top:1px solid rgba(255,255,255,0.04);margin:12px 0">
      <strong>Join room</strong>
      <div style="margin-top:8px" id="join_room_box">
        <div class="settings-row">
          <input id="join_room_key" placeholder="Room key">
          <input id="join_room_password" placeholder="Room password (if any)">
        </div>
        <div style="margin-top:8px">
          <button id="btn_join_room" class="full-btn">Join room</button>
        </div>
      </div>
      <hr style="border:none;border-top:1px solid rgba(255,255,255,0.04);margin:12px 0">
      <strong>My rooms</strong>
      <div id="my_rooms_list" style="margin-top:8px;max-height:220px;overflow:auto"></div>
      <div style="margin-top:12px;display:flex;gap:8px">
        <button id="btn_cancel_settings" class="copy-btn">Cancel</button>
      </div>
    </div>
  `;
  settingsModal.style.display = "block";
  document.getElementById("close_settings").onclick = ()=> settingsModal.style.display = "none";
  document.getElementById("btn_cancel_settings").onclick = ()=> settingsModal.style.display = "none";
  document.getElementById("btn_change_avatar").onclick = ()=> document.getElementById("settings_avatar_file").click();
  document.getElementById("settings_avatar_file").addEventListener("change", handleAvatarFile);
  document.getElementById("btn_save_profile").onclick = saveProfile;
  document.getElementById("btn_create_room").onclick = createRoomFromSettings;
  document.getElementById("btn_join_room").onclick = joinRoomFromSettings;
  loadSettingsRooms();
}

function handleAvatarFile(ev){
  const f = ev.target.files && ev.target.files[0];
  if(!f) return;
  if(f.size > MAX_FILE_SIZE){ showToast("Avatar too large"); return; }
  const preview = document.getElementById("settings_avatar_preview");
  preview.src = URL.createObjectURL(f);
}

async function saveProfile(){
  const display = document.getElementById("settings_display").value.trim();
  const username = document.getElementById("settings_username").value.trim();
  const bio = document.getElementById("settings_bio").value.trim();
  const fileInputEl = document.getElementById("settings_avatar_file");
  const fd = new FormData();
  fd.append("display_name", display);
  fd.append("username", username);
  fd.append("bio", bio);
  if(fileInputEl.files && fileInputEl.files[0]){
    fd.append("avatar", fileInputEl.files[0]);
  }
  const r = await fetch("/api/profile", {method:"POST", body: fd});
  const j = await r.json();
  if(j.ok){
    showToast("Profile saved");
    if(j.profile && j.profile.avatar){
      document.getElementById("my_avatar").src = j.profile.avatar;
    }
  } else {
    showToast(j.error || "Save failed");
  }
}

async function createRoomFromSettings(){
  const name = document.getElementById("create_room_name").value.trim() || (document.getElementById("chat_title").textContent || "");
  const password = document.getElementById("create_room_password").value || "";
  const fd = new FormData();
  fd.append("name", name);
  fd.append("password", password);
  const r = await fetch("/api/room_create", {method:"POST", body: fd});
  const j = await r.json();
  if(!j.ok){ showToast(j.error || "Create failed"); return; }
  showToast("Room created — key copied");
  try { await navigator.clipboard.writeText(j.room.key); } catch(e){}
  const info = `Room: ${j.room.name}\\nKey: ${j.room.key}\\n${j.password ? ("Password: " + j.password) : "No password"}`;
  alert(info);
  loadSettingsRooms();
  loadRooms();
}

async function joinRoomFromSettings(){
  const key = document.getElementById("join_room_key").value.trim();
  const password = document.getElementById("join_room_password").value || "";
  if(!key){ showToast("Enter room key"); return; }
  const fd = new FormData();
  fd.append("room_key", key);
  fd.append("password", password);
  const r = await fetch("/api/room_join", {method:"POST", body: fd});
  const j = await r.json();
  if(!j.ok){ showToast(j.error || "Join failed"); return; }
  showToast("Joined room");
  loadSettingsRooms();
  loadRooms();
}

async function loadSettingsRooms(){
  const r = await fetch("/api/rooms");
  const j = await r.json();
  const el = document.getElementById("my_rooms_list");
  el.innerHTML = "";
  j.rooms.forEach(room=>{
    const div = document.createElement("div"); div.className = "room-item";
    const left = document.createElement("div"); left.style.flex = "1";
    left.innerHTML = `<div style="font-weight:700">${escapeHtml(room.name)}</div><div class="small-muted">id: ${room.id}</div>`;
    const right = document.createElement("div"); right.style.display="flex"; right.style.gap="6px";
    const btnSwitch = document.createElement("button"); btnSwitch.className="copy-btn"; btnSwitch.textContent = "Switch";
    btnSwitch.onclick = ()=> { switchRoom(room.id); settingsModal.style.display = "none"; };
    right.appendChild(btnSwitch);
    if(room.owned){
      const keyBtn = document.createElement("button"); keyBtn.className="copy-btn"; keyBtn.textContent = "Copy key";
      keyBtn.onclick = async ()=> { try { await navigator.clipboard.writeText(room.key); showToast("Key copied"); } catch(e){ showToast("Copy failed"); } };
      right.appendChild(keyBtn);
      const setPwd = document.createElement("button"); setPwd.className="copy-btn"; setPwd.textContent = "Set password";
      setPwd.onclick = async ()=> {
        const pw = prompt("New password (leave blank to clear):");
        if(pw === null) return;
        const fd = new FormData(); fd.append("room_id", room.id); fd.append("password", pw || "");
        const r2 = await fetch("/api/room_set_password", {method:"POST", body: fd});
        const j2 = await r2.json();
        if(!j2.ok) { showToast(j2.error || "Failed"); return; }
        showToast(pw ? "Password set" : "Password cleared");
        if(pw) { alert("Password (copy it now): " + pw); }
        loadSettingsRooms();
      };
      right.appendChild(setPwd);
      const info = document.createElement("div"); info.className="small-muted"; info.style.marginLeft="8px"; info.textContent = `Key: ${room.key} ${room.has_password ? " • password set" : ""}`;
      left.appendChild(info);
    }
    div.appendChild(left); div.appendChild(right);
    el.appendChild(div);
  });
}

function showNotifCenter(){
  if(notifCenter.style.display === "block"){ notifCenter.style.display = "none"; return; }
  fetch("/api/notifications").then(r=>r.json()).then(j=>{
    notifCenter.style.display = "block";
    notifCenter.innerHTML = "<strong>Notifications</strong><hr>";
    j.notifications.forEach(n=>{ const d=document.createElement("div"); d.style.padding="6px"; d.innerHTML = `<small>${new Date(n.created_at).toLocaleString()}</small><div>${escapeHtml(n.text)}</div>`; notifCenter.appendChild(d); });
  });
}

function showTyping(d){
  const p = document.getElementById("presence");
  p.textContent = d.is_typing ? `${d.username} is typing…` : "Online";
}

async function loadMessages(){
  const r = await fetch("/api/messages?limit=200"); const j = await r.json();
  messagesEl.innerHTML = "";
  chatTitle.textContent = j.room ? j.room.name : chatTitle.textContent;
  j.messages.forEach(renderMessage);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function renderMessage(m){
  if(!m || !m.id) return null;
  const el = document.createElement("div");
  const am = (m.sender && m.sender.username === MY_USERNAME);
  el.className = "msg " + (am ? "me" : "");
  el.id = "m"+m.id;
  el.dataset.msgId = m.id;
  const meta = document.createElement("div"); meta.className="meta";
  const displayName = (m.sender && m.sender.display_name) ? m.sender.display_name : (m.sender && m.sender.username) ? m.sender.username : "System";
  meta.innerHTML = `<strong>${escapeHtml(displayName)}</strong> • ${new Date(m.created_at).toLocaleTimeString()}${m.edited? " • edited":""}`;
  el.appendChild(meta);
  if(m.reply_to){
    const rep = document.createElement("div"); rep.style.fontSize="12px"; rep.style.color="var(--muted)";
    rep.textContent = "Replying to message #" + m.reply_to;
    el.appendChild(rep);
  }
  const body = document.createElement("div"); body.className="text"; body.innerHTML = m.rendered || escapeHtml(m.text || "");
  el.appendChild(body);
  if(m.attachments && m.attachments.length){
    const att = document.createElement("div"); att.className="attach";
    m.attachments.forEach(a=>{
      try {
        if(a.type==="image"){
          const img = document.createElement("img"); img.src=a.url; img.loading="lazy"; img.onclick=()=> openPreview(a.url); att.appendChild(img);
        } else if(a.type==="video"){
          const v = document.createElement("video"); v.src=a.url; v.controls=true; v.preload="none"; att.appendChild(v);
        } else if(a.type==="sticker"){
          const img = document.createElement("img"); img.src=a.url; img.style.width="90px"; att.appendChild(img);
        } else if(a.type==="file"){
          const link = document.createElement("a"); link.href = a.url; link.textContent = a.filename || "download.txt"; link.target="_blank"; att.appendChild(link);
        }
      } catch(e){}
    });
    el.appendChild(att);
  }
  const reactionsWrap = document.createElement("div"); reactionsWrap.className="reactions";
  for(const [emoji, users] of Object.entries(m.reactions || {})){
    const pill = document.createElement("div"); pill.className="react-pill"; pill.textContent = `${emoji} ${users.length}`;
    pill.onclick = ()=> react(m.id, emoji);
    reactionsWrap.appendChild(pill);
  }
  el.appendChild(reactionsWrap);
  const actions = document.createElement("div"); actions.className="actions";
  actions.innerHTML = `<button onclick="startReply(${m.id})">↩️</button> <button onclick="react(${m.id},'👍')">👍</button>`;
  if(am){
    actions.innerHTML += ` <button onclick="editMessage(${m.id})">✏️</button> <button onclick="deleteMessage(${m.id})">🗑️</button>`;
  }
  el.appendChild(actions);
  messagesEl.appendChild(el);
  return el;
}

function escapeHtml(s){ return (s||"").replace(/[&<>"']/g, m=> ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

function onNewMessageEvent(payload){
  const chatId = payload.chat_id || (payload.message && payload.message.chat_id);
  if(chatId != null && currentRoomId != null && chatId !== currentRoomId) return;
  const msg = payload.message || payload;
  renderMessage(msg);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function onReactionEvent(d){
  const el = document.getElementById("m"+d.message_id);
  if(!el) return;
  const wrap = el.querySelector(".reactions");
  if(!wrap) return;
  wrap.innerHTML = "";
  for(const [emoji, users] of Object.entries(d.reactions || {})){
    const pill = document.createElement("div"); pill.className="react-pill"; pill.textContent = `${emoji} ${users.length}`;
    pill.onclick = ()=> react(d.message_id, emoji);
    wrap.appendChild(pill);
  }
}

function onEditEvent(d){
  const el = document.getElementById("m"+d.message_id);
  if(!el) return;
  const body = el.querySelector(".text");
  if(body) body.innerHTML = d.rendered || escapeHtml(d.text || "");
  const meta = el.querySelector(".meta");
  if(meta && d.edited){
    if(!meta.innerHTML.includes("• edited")) meta.innerHTML = meta.innerHTML + " • edited";
  }
}

function onDeleteEvent(d){
  const el = document.getElementById("m"+d.message_id);
  if(el) el.remove();
}

function onPinnedEvent(d){
  const el = document.getElementById("m"+d.message_id);
  if(el) el.style.border = "1px solid gold";
}

function handleFiles(ev){
  const files = Array.from(ev.target.files || []);
  if(!files.length) return;
  if(selected.length + files.length > MAX_FILES){ showToast("Max "+MAX_FILES+" files"); return; }
  for(const f of files){
    const ext = f.name.split(".").pop().toLowerCase();
    const type = IMAGE_EXTS.includes(ext) ? "image" : (VIDEO_EXTS.includes(ext) ? "video" : null);
    if(!type){ showToast("Unsupported: "+f.name); continue; }
    if(f.size > MAX_FILE_SIZE){ showToast("Too large: "+f.name); continue; }
    const previewUrl = URL.createObjectURL(f);
    selected.push({file:f, preview:previewUrl, type:type, uploadedName:null});
  }
  updatePreview();
  ev.target.value = "";
}

function updatePreview(){
  previewEl.innerHTML = "";
  if(!selected.length) return;
  selected.forEach((s, idx)=>{
    const wrap = document.createElement("div"); wrap.style.position="relative";
    const thumb = document.createElement(s.type==="image" ? "img" : "video"); thumb.className="preview-thumb"; thumb.src = s.preview;
    if(s.type==="video"){ thumb.muted=true; thumb.autoplay=true; thumb.loop=true; thumb.playsInline=true; }
    wrap.appendChild(thumb);
    const del = document.createElement("button"); del.textContent="✕"; del.style.position="absolute"; del.style.top="6px"; del.style.right="6px"; del.onclick = ()=> { selected.splice(idx,1); updatePreview(); };
    wrap.appendChild(del);
    previewEl.appendChild(wrap);
  });
}

async function sendMessage(){
  if(!navigator.onLine){ showToast("Offline"); return; }
  let text = inputEl.value;
  if(!text && selected.length===0) return;
  const toUpload = selected.filter(s=> !s.uploadedName).map(s=> s.file);
  if(toUpload.length){
    const fd = new FormData();
    toUpload.forEach(f=> fd.append("files", f));
    const r = await fetch("/api/upload_multiple", {method:"POST", body: fd});
    const j = await r.json();
    if(!j.ok){ showToast(j.error || "Upload failed"); return; }
    let idx=0;
    for(let i=0;i<selected.length;i++){
      if(!selected[i].uploadedName){
        selected[i].uploadedName = j.files[idx].filename;
        selected[i].type = j.files[idx].type;
        idx++;
      }
    }
  }
  const attachments = selected.map(s => ({filename: s.uploadedName, type: s.type}));
  try {
    socket.emit("send_message", {text: text, attachments: attachments, reply_to: replyTo || null});
  } catch(e){ console.error(e); }
  inputEl.value = ""; selected = []; updatePreview();
  replyTo = null; renderReplyBanner();
}

async function react(msgId, emoji){
  const r = await fetch(`/api/message/${msgId}/react`, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({emoji:emoji})});
  const j = await r.json();
  if(!j.ok) showToast(j.error || "React failed");
}

function startReply(msgId){
  replyTo = msgId; renderReplyBanner();
  inputEl.focus();
  showToast("Replying to message " + msgId);
}

function renderReplyBanner(){
  const existing = document.querySelector(".reply-banner");
  if(existing) existing.remove();
  if(!replyTo) return;
  const banner = document.createElement("div"); banner.className="reply-banner";
  banner.innerHTML = `<div>Replying to #${replyTo}</div><div><button id="cancel_reply" class="copy-btn">✕</button></div>`;
  document.body.appendChild(banner);
  document.getElementById("cancel_reply").onclick = ()=> { replyTo=null; banner.remove(); };
}

function editMessage(msgId){
  const text = prompt("Edit message");
  if(text === null) return;
  fetch(`/api/message/${msgId}/edit`, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({text:text})}).then(r=>r.json()).then(j=>{ if(!j.ok) showToast(j.error||"Edit failed"); });
}

function deleteMessage(msgId){
  if(!confirm("Delete this message?")) return;
  fetch(`/api/message/${msgId}/delete`, {method:"POST"}).then(r=>r.json()).then(j=>{ if(!j.ok) showToast(j.error||"Delete failed"); });
}

function addSwipeListeners(){
  let startX=0, startY=0, startT=0;
  messagesEl.addEventListener('touchstart', e=> {
    const t = e.touches[0];
    startX = t.clientX; startY = t.clientY; startT = Date.now();
  });
  messagesEl.addEventListener('touchend', e=> {
    const t = e.changedTouches[0];
    const dx = t.clientX - startX, dy = t.clientY - startY, dt = Date.now() - startT;
    if(dx > 80 && Math.abs(dy) < 60 && dt < 600){
      let node = document.elementFromPoint(t.clientX, t.clientY);
      while(node && !node.dataset?.msgId) node = node.parentNode;
      if(node && node.dataset?.msgId){
        startReply(node.dataset.msgId);
      }
    }
  });
}

let lastTap = {id:null, time:0};
function handleMessageClick(e){
  let node = e.target;
  while(node && !node.dataset?.msgId) node = node.parentNode;
  if(!node) return;
  const id = node.dataset.msgId;
  const now = Date.now();
  if(lastTap.id == id && (now - lastTap.time) < 400){
    react(id, "👍");
    lastTap = {id:null, time:0};
  } else {
    lastTap = {id:id, time:now};
  }
}

function toggleStickers(){
  const s = prompt("Sticker: type 'smile' or 'heart' to send");
  if(!s) return;
  let name = null;
  if(s.toLowerCase().includes("smile")) name = "sticker-smile.svg";
  if(s.toLowerCase().includes("heart")) name = "sticker-heart.svg";
  if(!name) { showToast("Unknown sticker"); return; }
  try { socket.emit("send_message", {text:"", attachments:[{filename:name, type:"sticker"}], reply_to: null}); } catch(e){}
}

function openPreview(url){
  const w = window.open("");
  w.document.write(`<html><body style="margin:0;background:#000"><img src="${url}" style="width:100%;height:auto"></body></html>`);
}

window.addEventListener("load", init);
</script>
</body></html>"""

# ---------------------------
# Context injection
# ---------------------------
@app.context_processor
def inject_globals():
    return dict(
        max_files = MAX_FILES_PER_MESSAGE,
        image_exts = list(ALLOWED_IMAGE_EXT),
        video_exts = list(ALLOWED_VIDEO_EXT),
        max_file_size = MAX_FILE_SIZE
    )

# ---------------------------
# Auth routes & APIs
# ---------------------------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        display = request.form.get("display_name") or username
        password = request.form.get("password")
        if not username or not password:
            flash("username and password required")
            return redirect(url_for("register"))
        if User.query.filter_by(username=username).first():
            flash("username taken")
            return redirect(url_for("register"))
        try:
            u = User(username=username, display_name=display)
            u.set_password(password)
            db.session.add(u); db.session.commit()
            # auto-join default room 1
            if not RoomMember.query.filter_by(room_id=1, user_id=u.id).first():
                rm = RoomMember(room_id=1, user_id=u.id); db.session.add(rm); db.session.commit()
            login_user(u, remember=True)
            flask_session["room_id"] = 1
            sys_text = f"👋 {u.display_name or u.username} joined Ghost Projects chat"
            m = Message(sender_id=None, text=sys_text, rendered=render_md(sys_text), reactions=json.dumps({}), read_by=json.dumps([]), attachments=json.dumps([]), chat_id=1)
            db.session.add(m); db.session.commit()
            logger.info("New user registered: %s", username)
            return redirect(url_for("index"))
        except Exception:
            logger.exception("Registration failed")
            flash("Registration failed")
            return redirect(url_for("register"))
    return render_template_string(REGISTER_HTML)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password")
        remember = bool(request.form.get("remember"))
        u = User.query.filter_by(username=username).first()
        if u and u.check_password(password):
            login_user(u, remember=remember)
            if not RoomMember.query.filter_by(room_id=1, user_id=u.id).first():
                rm = RoomMember(room_id=1, user_id=u.id); db.session.add(rm); db.session.commit()
            flask_session["room_id"] = 1
            u.last_seen = datetime.now(timezone.utc); db.session.commit()
            logger.info("User logged in: %s", username)
            return redirect(url_for("index"))
        flash("Invalid credentials")
        return redirect(url_for("login"))
    return render_template_string(LOGIN_HTML)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flask_session.pop("room_id", None)
    return redirect(url_for("login"))

def require_json(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not request.is_json and request.method != "GET":
            return jsonify({"error":"JSON required"}), 400
        return f(*a, **kw)
    return wrapper

@app.route("/api/me")
@login_required
def api_me():
    u = db.session.get(User, current_user.id)
    return jsonify({"user": user_to_dict(u), "room_id": flask_session.get("room_id", 1)})

@app.route("/api/profile", methods=["POST"])
@login_required
def api_profile():
    display = request.form.get("display_name")
    bio = request.form.get("bio")
    username = request.form.get("username")
    u = db.session.get(User, current_user.id)
    if username and username != u.username:
        if User.query.filter_by(username=username).first():
            return jsonify({"error":"username taken"}), 400
        u.username = username
    if display is not None:
        u.display_name = display[:120]
    if bio is not None:
        u.bio = bio[:1000]
    if "avatar" in request.files:
        f = request.files["avatar"]
        if f and f.filename:
            fname = secure_filename(f.filename)
            fname = secrets.token_hex(8) + "-" + fname
            dest = os.path.join(app.config["UPLOAD_FOLDER"], fname)
            try:
                f.save(dest)
                if PIL_AVAILABLE:
                    try:
                        im = Image.open(dest)
                        im.thumbnail(THUMB_MAX_SIZE)
                        im.save(dest, optimize=True, quality=85)
                    except Exception:
                        logger.exception("Avatar resize failed")
                u.avatar = fname
            except Exception:
                logger.exception("Failed to save avatar")
    db.session.commit()
    return jsonify({"ok":True, "profile": user_to_dict(u)})

@app.route("/api/rooms")
@login_required
def api_rooms():
    mids = RoomMember.query.filter_by(user_id=current_user.id).all()
    rooms = []
    for m in mids:
        r = db.session.get(Room, m.room_id)
        if r:
            rooms.append({
                "id": r.id,
                "name": r.name,
                "owned": (r.owner_id == current_user.id),
                "key": (r.room_key if r.owner_id == current_user.id else None),
                "has_password": bool(r.password_hash)
            })
    return jsonify({"rooms": rooms, "current": flask_session.get("room_id",1)})

@app.route("/api/room_create", methods=["POST"])
@login_required
def api_room_create():
    if Room.query.filter_by(owner_id=current_user.id).first():
        return jsonify({"error":"You already created a room"}), 400
    name = (request.form.get("name") or "").strip() or f"{current_user.username}'s room"
    password = request.form.get("password") or ""
    room_key = secrets.token_urlsafe(10)
    room = Room(owner_id=current_user.id, name=name, room_key=room_key)
    if password:
        room.password_hash = generate_password_hash(password)
    db.session.add(room); db.session.commit()
    rm = RoomMember(room_id=room.id, user_id=current_user.id); db.session.add(rm); db.session.commit()
    flask_session["room_id"] = room.id
    return jsonify({"ok":True, "room":{"id":room.id,"name":room.name,"key":room.room_key}, "password": password})

@app.route("/api/room_set_password", methods=["POST"])
@login_required
def api_room_set_password():
    room_id = int(request.form.get("room_id") or 0)
    new_pw = request.form.get("password") or ""
    if not room_id: return jsonify({"error":"room_id required"}), 400
    room = db.session.get(Room, room_id)
    if not room: return jsonify({"error":"no such room"}), 404
    if room.owner_id != current_user.id: return jsonify({"error":"not owner"}), 403
    if new_pw:
        room.password_hash = generate_password_hash(new_pw)
    else:
        room.password_hash = None
    db.session.commit()
    return jsonify({"ok":True, "password": new_pw})

@app.route("/api/room_join", methods=["POST"])
@login_required
def api_room_join():
    room_key = (request.form.get("room_key") or "").strip()
    password = request.form.get("password") or ""
    if not room_key:
        return jsonify({"error":"room_key required"}), 400
    room = Room.query.filter_by(room_key=room_key).first()
    if not room: return jsonify({"error":"no such room"}), 404
    if not room.check_password(password):
        return jsonify({"error":"bad password"}), 403
    if not RoomMember.query.filter_by(room_id=room.id, user_id=current_user.id).first():
        rm = RoomMember(room_id=room.id, user_id=current_user.id); db.session.add(rm); db.session.commit()
    flask_session["room_id"] = room.id
    return jsonify({"ok":True, "room": {"id":room.id, "name":room.name}})

@app.route("/api/switch_room", methods=["POST"])
@login_required
def api_switch_room():
    data = request.get_json() or {}
    rid = int(data.get("room_id") or 1)
    if not RoomMember.query.filter_by(room_id=rid, user_id=current_user.id).first():
        return jsonify({"error":"not a member"}), 403
    flask_session["room_id"] = rid
    return jsonify({"ok":True})

@app.route("/api/upload_multiple", methods=["POST"])
@login_required
def api_upload_multiple():
    files = request.files.getlist("files")
    logger.info("UPLOAD: received %d files from %s", len(files), current_user.username)
    if not files: return jsonify({"error":"no files"}), 400
    if len(files) > MAX_FILES_PER_MESSAGE: return jsonify({"error":"too many files"}), 400
    out=[]
    for f in files:
        if not f or not f.filename: continue
        fname = secure_filename(f.filename)
        if not allowed_extension(fname): return jsonify({"error":f"unsupported: {fname}"}), 400
        f.seek(0, os.SEEK_END); size=f.tell(); f.seek(0)
        if size > MAX_FILE_SIZE: return jsonify({"error":f"file too large: {fname}"}), 400
        saved = secrets.token_hex(8) + "-" + fname
        dest = os.path.join(app.config["UPLOAD_FOLDER"], saved)
        try:
            f.save(dest)
            k = kind_from_ext(fname)
            if k == "image" and PIL_AVAILABLE:
                try:
                    im = Image.open(dest); im.thumbnail(THUMB_MAX_SIZE); im.save(dest, optimize=True, quality=85)
                except Exception:
                    logger.exception("Image thumbnail failed")
            out.append({"filename": saved, "type": k})
            logger.info("UPLOAD saved %s -> %s", fname, saved)
        except Exception:
            logger.exception("Failed to save upload")
            return jsonify({"error":"save failed"}), 500
    return jsonify({"ok":True, "files": out})

@app.route("/api/messages", methods=["GET"])
@login_required
def api_messages():
    limit = int(request.args.get("limit", 200))
    before = request.args.get("before")
    room_id = flask_session.get("room_id", 1)
    q = Message.query.filter_by(chat_id=room_id).order_by(Message.created_at.desc())
    if before:
        try:
            dt = datetime.fromisoformat(before); q = q.filter(Message.created_at < dt)
        except Exception:
            pass
    rows = q.limit(limit).all(); rows.reverse()
    res=[]
    for r in rows:
        sender = db.session.get(User, r.sender_id) if r.sender_id else None
        try: attachments = json.loads(r.attachments) if r.attachments else []
        except: attachments=[]
        try: reactions = json.loads(r.reactions) if r.reactions else {}
        except: reactions={}
        try: read_by = json.loads(r.read_by) if r.read_by else []
        except: read_by=[]
        res.append({
            "id": r.id,
            "sender": user_to_dict(sender) if sender else {"username":"system","display_name":"System","avatar": DEFAULT_AVATAR},
            "text": r.text,
            "rendered": sanitize_html(r.rendered or render_md(r.text)),
            "created_at": r.created_at.isoformat(),
            "reply_to": r.reply_to,
            "edited": r.edited,
            "pinned": r.pinned,
            "attachments": [{"type":a.get("type"), "url": url_upload(a.get("filename")) if a.get("type")!="sticker" else url_sticker(a.get("filename")), "filename": a.get("filename")} for a in attachments],
            "reactions": reactions,
            "read_by": read_by,
            "chat_id": r.chat_id
        })
    room = db.session.get(Room, room_id)
    room_name = room.name if room else "Ghost Projects chat"
    return jsonify({"messages": res, "room": {"id": room_id, "name": room_name}})

@app.route("/api/message/<int:msg_id>/react", methods=["POST"])
@login_required
def api_react(msg_id):
    data = request.get_json() or {}
    emoji = data.get("emoji") or "👍"
    m = db.session.get(Message, msg_id)
    if not m: return jsonify({"error":"no such message"}), 404
    reactions = json.loads(m.reactions) if m.reactions else {}
    li = reactions.get(emoji, [])
    uname = current_user.username
    if uname in li: li.remove(uname)
    else: li.append(uname)
    reactions[emoji] = li
    m.reactions = json.dumps(reactions)
    db.session.commit()
    socketio.emit("reaction", {"message_id": m.id, "reactions": reactions, "chat_id": m.chat_id}, room=f"room_{m.chat_id}")
    return jsonify({"ok":True, "reactions": reactions})

@app.route("/api/message/<int:msg_id>/edit", methods=["POST"])
@login_required
def api_message_edit(msg_id):
    data = request.get_json() or {}
    text = (data.get("text") or "").strip()
    if not text: return jsonify({"error":"text required"}), 400
    m = db.session.get(Message, msg_id)
    if not m: return jsonify({"error":"no such message"}), 404
    if m.sender_id != current_user.id: return jsonify({"error":"not owner"}), 403
    m.text = text; m.rendered = render_md(text); m.edited = True; m.edited_at = datetime.now(timezone.utc)
    db.session.commit()
    socketio.emit("edit", {"message_id": m.id, "text": m.text, "rendered": m.rendered, "edited": True, "chat_id": m.chat_id}, room=f"room_{m.chat_id}")
    return jsonify({"ok":True})

@app.route("/api/message/<int:msg_id>/delete", methods=["POST"])
@login_required
def api_message_delete(msg_id):
    m = db.session.get(Message, msg_id)
    if not m: return jsonify({"error":"no such message"}), 404
    if m.sender_id != current_user.id: return jsonify({"error":"not owner"}), 403
    chat_id = m.chat_id
    db.session.delete(m); db.session.commit()
    socketio.emit("delete", {"message_id": msg_id, "chat_id": chat_id}, room=f"room_{chat_id}")
    return jsonify({"ok":True})

@app.route("/api/notifications")
@login_required
def api_notifications():
    rows = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(50).all()
    out = [{"id": n.id, "text": n.text, "link": n.link, "created_at": n.created_at.isoformat(), "seen": n.seen} for n in rows]
    return jsonify({"notifications": out})

# ---------------------------
# Socket handlers
# ---------------------------
@socketio.on("connect")
def ws_connect():
    if not getattr(current_user, "is_authenticated", False):
        return
    sid = request.sid
    mark_online(current_user.id, sid)
    room_id = flask_session.get("room_id", 1)
    join_room(f"room_{room_id}")
    sid_room[sid] = room_id
    logger.info("Socket connected: user=%s sid=%s room=%s", current_user.username, sid, room_id)
    socketio.emit("presence", {"user": user_to_dict(db.session.get(User, current_user.id)), "online": True}, room=f"room_{room_id}")

@socketio.on("disconnect")
def ws_disconnect():
    sid = request.sid
    mark_offline(sid)

@socketio.on("switch_room")
def ws_switch_room(data):
    try:
        rid = int(data.get("room_id") or flask_session.get("room_id", 1))
    except Exception:
        rid = flask_session.get("room_id", 1)
    sid = request.sid
    old = sid_room.get(sid)
    try:
        if old:
            leave_room(f"room_{old}")
    except Exception:
        pass
    try:
        join_room(f"room_{rid}")
        sid_room[sid] = rid
    except Exception:
        logger.exception("Failed to switch socket room for sid=%s", sid)

@socketio.on("typing")
def ws_typing(data):
    is_typing = bool(data.get("is_typing"))
    sid = request.sid
    room_id = sid_room.get(sid, flask_session.get("room_id", 1))
    socketio.emit("typing", {"username": current_user.username, "is_typing": is_typing}, room=f"room_{room_id}")

@socketio.on("send_message")
def ws_send_message(data):
    text = (data.get("text") or "")
    attachments = data.get("attachments") or []
    reply_to = data.get("reply_to")
    room_id = sid_room.get(request.sid, flask_session.get("room_id", 1))
    if (not text or text.strip() == "") and not attachments:
        return
    # If text too long, save as .txt file and attach
    text_to_store = text
    attached_from_text = None
    if text and len(text) > LONG_MESSAGE_LIMIT:
        try:
            fname = secrets.token_hex(8) + "-longmsg.txt"
            dest = os.path.join(app.config["UPLOAD_FOLDER"], fname)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(text)
            attached_from_text = {"filename": fname, "type": "file"}
            text_to_store = "[Long message attached]"
        except Exception:
            logger.exception("Failed to write long message to file")
    # Validate attachments exist on disk (except stickers)
    valid = []
    for a in attachments:
        fn = a.get("filename"); t = a.get("type")
        if not fn or not t: continue
        if t == "sticker":
            valid.append({"filename": fn, "type": t})
            continue
        if os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], fn)):
            valid.append({"filename": fn, "type": t})
    if attached_from_text:
        valid.append(attached_from_text)
    try:
        m = Message(
            sender_id=current_user.id,
            text=text_to_store,
            rendered=render_md(text_to_store),
            reply_to=reply_to,
            attachments=json.dumps(valid),
            reactions=json.dumps({}),
            read_by=json.dumps([]),
            chat_id=room_id
        )
        db.session.add(m); db.session.commit()
    except Exception:
        logger.exception("Failed to save message")
        return
    payload = {
        "id": m.id,
        "sender": user_to_dict(db.session.get(User, current_user.id)),
        "text": m.text,
        "rendered": sanitize_html(m.rendered),
        "created_at": m.created_at.isoformat(),
        "reply_to": m.reply_to,
        "edited": m.edited,
        "pinned": m.pinned,
        "attachments": [{"type": a["type"], "url": (url_sticker(a["filename"]) if a["type"]=="sticker" else url_upload(a["filename"])), "filename": a["filename"]} for a in valid],
        "reactions": {},
        "read_by": []
    }
    if reply_to:
        orig = db.session.get(Message, reply_to)
        if orig and orig.sender_id and orig.sender_id != current_user.id:
            push_notification(orig.sender_id, {"text": f"{current_user.display_name or current_user.username} replied to your message", "link": "/"})
    socketio.emit("new_message", {"message": payload, "chat_id": room_id}, room=f"room_{room_id}")
    logger.info("Broadcasted message id=%s room=%s", m.id, room_id)

@socketio.on("mark_read")
def ws_mark_read(data):
    ids = data.get("message_ids") or []
    for mid in ids:
        m = db.session.get(Message, mid)
        if m:
            read_by = json.loads(m.read_by) if m.read_by else []
            if current_user.username not in read_by:
                read_by.append(current_user.username)
                m.read_by = json.dumps(read_by)
                db.session.commit()
                socketio.emit("read_receipt", {"message_id": m.id, "username": current_user.username}, room=f"room_{m.chat_id}")

# ---------------------------
# Error handler & index
# ---------------------------
@app.errorhandler(404)
def not_found(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({"error":"not found"}), 404
    return render_template_string(NOTFOUND_HTML), 404

@app.route("/")
@login_required
def index():
    user = user_to_dict(db.session.get(User, current_user.id))
    mids = RoomMember.query.filter_by(user_id=current_user.id).all()
    rooms = []
    for m in mids:
        r = db.session.get(Room, m.room_id)
        if r:
            rooms.append({"id": r.id, "name": r.name})
    current_room = db.session.get(Room, flask_session.get("room_id",1))
    current_room_name = current_room.name if current_room else "Ghost Projects chat"
    return render_template_string(MAIN_HTML, user=user, rooms=rooms, current_room_name=current_room_name, max_files=MAX_FILES_PER_MESSAGE, image_exts=list(ALLOWED_IMAGE_EXT), video_exts=list(ALLOWED_VIDEO_EXT), max_file_size=MAX_FILE_SIZE, room_id=flask_session.get("room_id",1))

# ---------------------------
# Startup: create tables & seed
# ---------------------------
def init_db():
    with app.app_context():
        db.create_all()
        ensure_message_columns()
        if not db.session.get(Room, 1):
            r = Room(id=1, owner_id=None, name="Ghost Projects chat", room_key="global", password_hash=None)
            db.session.add(r); db.session.commit()
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", display_name="Administrator")
            admin.set_password("admin")
            db.session.add(admin); db.session.commit()
            if not RoomMember.query.filter_by(room_id=1, user_id=admin.id).first():
                db.session.add(RoomMember(room_id=1, user_id=admin.id)); db.session.commit()
            sys_msg = Message(sender_id=None, text="Welcome to Ghost Projects chat! Be kind.", rendered=render_md("Welcome to Ghost Projects chat! Be kind."), reactions=json.dumps({}), read_by=json.dumps([]), attachments=json.dumps([]), chat_id=1)
            db.session.add(sys_msg); db.session.commit()
            logger.info("Seeded admin and default message")

# Vercel entry point
def handler(event, context):
    return app(event, context)

if __name__ == "__main__":
    init_db()
    logger.info("Starting Ghost Projects Chat on http://127.0.0.1:5000")
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=True, allow_unsafe_werkzeug=True)
