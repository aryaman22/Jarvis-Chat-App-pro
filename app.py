from flask import Flask, render_template, session, send_from_directory, request, redirect, url_for, jsonify, make_response
from flask_socketio import SocketIO, emit, disconnect, join_room, leave_room
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
import os, uuid, json, datetime, requests, random, re
from werkzeug.utils import secure_filename
from datetime import timezone
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo
import bcrypt
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__app__)

app = Flask(__app__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_very_secret_key_1234567890')
app.config['SESSION_COOKIE_NAME'] = 'jarvis_session'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # False for HTTP in dev
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_COOKIE_DOMAIN'] = None
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=1)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Database configuration
database_url = os.environ.get('DATABASE_URL')
if database_url:
    database_url = database_url.replace('.us-east-2', '-pooler.us-east-2')
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=True)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    creator_username = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class RoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(10), default='user')
    session_id = db.Column(db.String(8), nullable=False)
    model = db.Column(db.String(100), default='mistralai/mistral-7b-instruct')
    socket_id = db.Column(db.String(100))
    joined_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='user')
    timestamp = db.Column(db.DateTime, default=lambda: datetime.datetime.now(tz=ZoneInfo("Asia/Kolkata")))
    file_path = db.Column(db.String(200))
    file_name = db.Column(db.String(200))
    model_used = db.Column(db.String(100))
    reactions = db.Column(db.Text, default='[]')

class ChatLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(20), nullable=False)
    session_id = db.Column(db.String(8), nullable=False)
    user_message = db.Column(db.Text, nullable=False)
    ai_response = db.Column(db.Text, nullable=False)
    model_used = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.datetime.now(tz=ZoneInfo("Asia/Kolkata")))

# Create tables
try:
    with app.app_context():
        # db.drop_all()
        db.create_all()
        logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Database initialization error: {e}")

# In-memory storage
room_users = {}
typing_users = {}

LOG_DIR = "logs"
UPLOAD_DIR = "uploads"
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

OPENROUTER_API_KEY = os.environ.get("API_KEY") or "sk-xxxx"

AVAILABLE_MODELS = {
    "mistralai/mistral-7b-instruct": {"name": "Mistral 7B", "free": True},
    "openai/gpt-3.5-turbo": {"name": "GPT-3.5 Turbo", "free": False},
    "anthropic/claude-3-haiku": {"name": "Claude 3 Haiku", "free": False},
    "google/gemma-7b-it": {"name": "Gemma 7B", "free": True}
}

WELCOME_MESSAGES = [
    "Welcome to {room}, {name}! 🎉",
    "Hey {name}, glad you joined {room}! 😊",
    "Yo {name}, welcome to {room}!",
    "Nice to see you in {room}, {name}!",
    "Welcome {name}! Jarvis is ready in {room} 🤖",
]

HELP_MESSAGE = """
Available commands:
- /clear - Clear chat history (admin only)
- /help - Show this help message
- /kick username - Kick a user from the room (admin only)
- jarvis [message] - Ask Jarvis for a response
- jarvis summarize - Get a chat summary
- jarvis insights - Get chat insights
- @username - Mention a user
"""

SYSTEM_PROMPT = """
You are Jarvis 🤖 — a friendly AI assistant in a group chat.

RULES:
- Only reply when the message includes "jarvis" (case-insensitive) or is sent via the "Ask Jarvis" button.
- Always address the user by name at the start of your response.
- Keep responses concise, friendly, and easy to read.
- Use bullet points (starting with -) and emojis for lists or emphasis.
- If asked for a single item (e.g., "jarvis 1"), provide only one item.
- For summarize/insights, provide a clear, concise summary or analysis of recent chat activity (e.g., key topics, most active users).
- Avoid repeating yourself or over-introducing.

TONE:
- Friendly, approachable, and helpful — like a supportive friend.

FORMAT EXAMPLES:
User: jarvis give ideas to be productive  
Jarvis 🤖:  
Hey [user], here are some productivity ideas:  
- 🧠 Take a short online course to learn a new skill.  
- ✅ Set three priority tasks for the day.  
- 📓 Journal your goals for clarity.

User: jarvis 1  
Jarvis 🤖:  
Hey [user], here's one idea:  
- 🧠 Take a short online course.

User: jarvis summarize  
Jarvis 🤖:  
Hey [user], here's a summary of recent chat:  
- Alice shared a file.  
- Bob mentioned planning a project.  
- You asked for productivity tips.

User: jarvis insights  
Jarvis 🤖:  
Hey [user], here are chat insights:  
- Most active user: Alice (10 messages).  
- Key topics: Project planning, file sharing.  
- Recent activity: 15 messages in the last hour.
"""

@app.route("/")
def index():
    logger.info(f"Index request: Session: {dict(session)}, Cookies: {request.cookies}, Host: {request.host}")
    if 'username' not in session:
        logger.warning("No username in session, redirecting to login")
        return redirect(url_for('login', _external=True))
    try:
        rooms = Room.query.filter_by(is_active=True).all()
        room_list = [
            {
                "name": room.name,
                "description": room.description,
                "creator": room.creator_username,
                "member_count": RoomMember.query.filter_by(room_name=room.name, is_active=True).count(),
                "created_at": room.created_at.isoformat()
            }
            for room in rooms
        ]
        response = make_response(render_template("dashboard.html", username=session['username'], rooms=room_list))
        response.set_cookie('jarvis_session', session.get('session.sid', ''), samesite='Lax', httponly=True, max_age=86400)
        logger.info(f"Rendering dashboard for {session['username']}, Set-Cookie: {response.headers.get('Set-Cookie')}")
        return response
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template("dashboard.html", username=session['username'], rooms=[], error="Failed to load rooms")

@app.route("/login", methods=["GET", "POST"])
def login():
    logger.info(f"Login request: Session before login: {dict(session)}, Cookies: {request.cookies}, Host: {request.host}")
    if request.method == "POST":
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').encode('utf-8')
        
        if not username or not password:
            logger.warning("Login attempt with missing fields")
            return render_template("login.html", error="Please fill all fields")
        
        if len(username) > 20:
            logger.warning(f"Login attempt with username too long: {username}")
            return render_template("login.html", error="Username must be 20 characters or less")
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password, user.password.encode('utf-8')):
            session.clear()
            session['username'] = username
            session.permanent = True
            response = make_response(redirect(url_for('index', _external=True)))
            response.set_cookie('jarvis_session', session.get('session.sid', ''), samesite='Lax', httponly=True, max_age=86400)
            logger.info(f"Login successful for {username}: Session after login: {dict(session)}, Set-Cookie: {response.headers.get('Set-Cookie')}")
            return response
        else:
            logger.warning(f"Login failed for {username}")
            return render_template("login.html", error="Invalid username or password")
    
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    logger.info(f"Register request: Session: {dict(session)}, Cookies: {request.cookies}, Host: {request.host}")
    if request.method == "POST":
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').encode('utf-8')
        confirm_password = request.form.get('confirm_password', '').encode('utf-8')
        
        if not username or not password or not confirm_password:
            logger.warning("Register attempt with missing fields")
            return render_template("register.html", error="Please fill all fields")
        
        if len(username) > 20:
            logger.warning(f"Register attempt with username too long: {username}")
            return render_template("register.html", error="Username must be 20 characters or less")
        
        if password != confirm_password:
            logger.warning("Register attempt with mismatched passwords")
            return render_template("register.html", error="Passwords do not match")
        
        if User.query.filter_by(username=username).first():
            logger.warning(f"Register attempt with existing username: {username}")
            return render_template("register.html", error="Username already exists")
        
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            session.clear()
            session['username'] = username
            session.permanent = True
            response = make_response(redirect(url_for('index', _external=True)))
            response.set_cookie('jarvis_session', session.get('session.sid', ''), samesite='Lax', httponly=True, max_age=86400)
            logger.info(f"Registration successful for {username}: Session: {dict(session)}, Set-Cookie: {response.headers.get('Set-Cookie')}")
            return response
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
            return render_template("register.html", error="Registration failed")
    
    return render_template("register.html")

@app.route("/logout")
def logout():
    logger.info(f"Logout request: Session before logout: {dict(session)}, Cookies: {request.cookies}, Host: {request.host}")
    session.clear()
    logger.info("Session cleared")
    response = make_response(redirect(url_for('login', _external=True)))
    response.set_cookie('jarvis_session', '', expires=0)
    logger.info(f"Logout response: Set-Cookie: {response.headers.get('Set-Cookie')}")
    return response

@app.route("/room/<room_name>")
def room(room_name):
    logger.info(f"Room request for {room_name}: Session: {dict(session)}, Cookies: {request.cookies}, Host: {request.host}")
    if 'username' not in session:
        logger.warning("No username in session, redirecting to login")
        return redirect(url_for('login', _external=True))
    
    room_obj = Room.query.filter_by(name=room_name, is_active=True).first()
    if not room_obj:
        logger.warning(f"Room {room_name} not found or inactive")
        return redirect(url_for('index', _external=True))
    
    return render_template("index.html", room_name=room_name, username=session['username'])

@app.route("/create_room", methods=["POST"])
def create_room():
    logger.info(f"Create room request: Session: {dict(session)}, Cookies: {request.cookies}, Host: {request.host}")
    if 'username' not in session:
        logger.warning("No username in session")
        return jsonify({"success": False, "error": "Not logged in"}), 401
    
    room_name = request.json.get('name', '').strip()
    description = request.json.get('description', '').strip()
    
    if not room_name:
        logger.warning("Create room attempt with missing name")
        return jsonify({"success": False, "error": "Room name is required"}), 400
    
    if len(room_name) > 50:
        logger.warning(f"Create room attempt with name too long: {room_name}")
        return jsonify({"success": False, "error": "Room name must be 50 characters or less"}), 400
    
    if Room.query.filter_by(name=room_name).first():
        logger.warning(f"Create room attempt with existing name: {room_name}")
        return jsonify({"success": False, "error": "Room name already exists"}), 400
    
    new_room = Room(
        name=room_name,
        description=description,
        creator_username=session['username']
    )
    try:
        db.session.add(new_room)
        db.session.commit()
        logger.info(f"Room created: {room_name}")
        return jsonify({"success": True, "room_name": room_name})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create room error: {e}")
        return jsonify({"success": False, "error": "Failed to create room"}), 500

@app.route("/get_rooms")
def get_rooms():
    logger.info(f"Get rooms request: Session: {dict(session)}, Cookies: {request.cookies}, Host: {request.host}")
    if 'username' not in session:
        logger.warning("No username in session")
        return jsonify({"success": False, "error": "Not logged in"}), 401
    
    try:
        rooms = Room.query.filter_by(is_active=True).all()
        room_list = [
            {
                "name": room.name,
                "description": room.description,
                "creator": room.creator_username,
                "member_count": RoomMember.query.filter_by(room_name=room.name, is_active=True).count(),
                "created_at": room.created_at.isoformat()
            }
            for room in rooms
        ]
        logger.info(f"Retrieved {len(room_list)} active rooms")
        return jsonify({"success": True, "rooms": room_list})
    except Exception as e:
        logger.error(f"Get rooms error: {e}")
        return jsonify({"success": False, "error": "Failed to fetch rooms"}), 500

@app.route("/upload", methods=["POST"])
def upload_file():
    logger.info(f"Upload file request: Session: {dict(session)}, Cookies: {request.cookies}, Host: {request.host}")
    if 'file' not in request.files or 'session_id' not in request.form or 'username' not in request.form or 'room_name' not in request.form:
        logger.warning("Upload attempt with missing data")
        return jsonify({"success": False, "error": "Missing file or session data"}), 400

    file = request.files['file']
    session_id = request.form['session_id']
    username = request.form['username']
    room_name = request.form['room_name']

    if file.filename == '':
        logger.warning("Upload attempt with no file selected")
        return jsonify({"success": False, "error": "No file selected"}), 400

    if file and session_id and username and room_name:
        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())[:8]
        file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{filename}")
        file.save(file_path)

        file_msg = Message(
            room_name=room_name,
            username=username,
            content=f"Uploaded file: {filename}",
            message_type="file",
            file_path=file_id,
            file_name=filename,
            timestamp=datetime.datetime.now(tz=ZoneInfo("Asia/Kolkata")),
            reactions='[]'
        )
        try:
            db.session.add(file_msg)
            db.session.commit()
            socketio.emit("receive_message", {
                "username": username,
                "message": f"Uploaded file: {filename}",
                "timestamp": file_msg.timestamp.isoformat(),
                "type": "file",
                "file_path": file_id,
                "file_name": filename,
                "id": file_id,
                "reactions": []
            }, room=room_name)
            logger.info(f"File uploaded: {filename} in room {room_name}")
            return jsonify({"success": True}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"File upload error: {e}")
            return jsonify({"success": False, "error": "Failed to upload file"}), 500
    logger.warning("Invalid upload request")
    return jsonify({"success": False, "error": "Invalid request"}), 400

@app.route("/download/<file_id>")
def download_file(file_id):
    logger.info(f"Download file request: {file_id}, Session: {dict(session)}, Cookies: {request.cookies}, Host: {request.host}")
    try:
        for filename in os.listdir(UPLOAD_DIR):
            if filename.startswith(file_id):
                return send_from_directory(UPLOAD_DIR, filename, as_attachment=True)
        logger.warning(f"File not found: {file_id}")
        return jsonify({"success": False, "error": "File not found"}), 404
    except Exception as e:
        logger.error(f"Download file error: {e}")
        return jsonify({"success": False, "error": "File download failed"}), 500

@socketio.on("join_room")
def on_join_room(data):
    username = data.get("username")
    room_name = data.get("room_name")
    model = data.get("model", "mistralai/mistral-7b-instruct")

    logger.info(f"Join room request: {username} in {room_name}, Session: {dict(session)}, Cookies: {request.cookies}, Host: {request.host}")
    if username != session.get('username'):
        logger.warning(f"Invalid session for {username}")
        emit("error", {"message": "Invalid session"})
        return

    room_obj = Room.query.filter_by(name=room_name, is_active=True).first()
    if not room_obj:
        logger.warning(f"Room not found: {room_name}")
        emit("error", {"message": "Room not found"})
        return

    session_id = str(uuid.uuid4())[:8]
    session["room_name"] = room_name
    session["session_id"] = session_id
    session["model"] = model
    session.permanent = True

    join_room(room_name)
    role = "admin" if username == room_obj.creator_username else "user"

    existing_member = RoomMember.query.filter_by(room_name=room_name, username=username).first()
    if existing_member:
        existing_member.session_id = session_id
        existing_member.model = model
        existing_member.socket_id = request.sid
        existing_member.is_active = True
        existing_member.joined_at = datetime.datetime.utcnow()
    else:
        new_member = RoomMember(
            room_name=room_name,
            username=username,
            role=role,
            session_id=session_id,
            model=model,
            socket_id=request.sid
        )
        db.session.add(new_member)
    
    try:
        db.session.commit()
        logger.info(f"{username} joined {room_name} as {role}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Join room error: {e}")
        emit("error", {"message": "Failed to join room"})
        return

    if room_name not in room_users:
        room_users[room_name] = {}
        typing_users[room_name] = set()

    room_users[room_name][username] = {
        "role": role, 
        "model": model, 
        "session_id": session_id, 
        "sid": request.sid
    }

    active_members = RoomMember.query.filter_by(room_name=room_name, is_active=True).all()
    user_list = [{"username": m.username, "role": m.role} for m in active_members]

    emit("joined_room", {
        "room_name": room_name,
        "session_id": session_id,
        "role": role,
        "users": user_list,
        "available_models": AVAILABLE_MODELS
    })
    
    emit("user_list", user_list, room=room_name)

    welcome = random.choice(WELCOME_MESSAGES).format(name=username, room=room_name)
    welcome_msg = Message(
        room_name=room_name,
        username="System",
        content=welcome,
        message_type="system",
        timestamp=datetime.datetime.now(tz=ZoneInfo("Asia/Kolkata")),
        reactions='[]'
    )
    try:
        db.session.add(welcome_msg)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Welcome message error: {e}")
        emit("error", {"message": "Failed to send welcome message"})
        return

    emit("receive_message", {
        "username": "System",
        "message": welcome,
        "timestamp": welcome_msg.timestamp.isoformat(),
        "type": "system",
        "id": str(welcome_msg.id),
        "reactions": []
    }, room=room_name)

    recent_messages = Message.query.filter_by(room_name=room_name).order_by(Message.timestamp.desc()).limit(50).all()
    recent_messages.reverse()
    
    chat_history = []
    for msg in recent_messages:
        chat_history.append({
            "username": msg.username,
            "message": msg.content,
            "timestamp": msg.timestamp.isoformat(),
            "type": msg.message_type,
            "file_path": msg.file_path,
            "file_name": msg.file_name,
            "id": str(msg.id),
            "reactions": json.loads(msg.reactions)
        })
    
    emit("chat_history", chat_history)

@socketio.on("change_model")
def change_model(data):
    session_id = data.get("session_id")
    new_model = data.get("model")
    room_name = session.get("room_name")

    logger.info(f"Change model request: {session.get('username')} to {new_model} in {room_name}, Cookies: {request.cookies}, Host: {request.host}")
    if new_model not in AVAILABLE_MODELS or not room_name:
        logger.warning(f"Invalid model or room: {new_model}, {room_name}")
        emit("error", {"message": "Invalid model or room"})
        return

    username = session.get("username")
    if username in room_users.get(room_name, {}):
        room_users[room_name][username]["model"] = new_model
        session["model"] = new_model
        
        member = RoomMember.query.filter_by(room_name=room_name, username=username).first()
        if member:
            member.model = new_model
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Change model error: {e}")
                emit("error", {"message": "Failed to change model"})
                return

        emit("model_changed", {
            "model": new_model,
            "model_name": AVAILABLE_MODELS[new_model]["name"]
        })
        
        system_msg = Message(
            room_name=room_name,
            username="System",
            content=f"{username} switched to {AVAILABLE_MODELS[new_model]['name']}",
            message_type="system",
            timestamp=datetime.datetime.now(tz=ZoneInfo("Asia/Kolkata")),
            reactions='[]'
        )
        try:
            db.session.add(system_msg)
            db.session.commit()
            emit("receive_message", {
                "username": "System",
                "message": system_msg.content,
                "timestamp": system_msg.timestamp.isoformat(),
                "type": "system",
                "id": str(system_msg.id),
                "reactions": []
            }, room=room_name)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Model change message error: {e}")
            emit("error", {"message": "Failed to broadcast model change"})

@socketio.on("typing")
def handle_typing(data):
    username = data.get("username")
    is_typing = data.get("isTyping")
    room_name = session.get("room_name")

    logger.info(f"Typing event: {username} isTyping={is_typing} in {room_name}, Cookies: {request.cookies}, Host: {request.host}")
    if not room_name or room_name not in typing_users:
        logger.warning(f"Invalid room for typing: {room_name}")
        return

    if is_typing:
        typing_users[room_name].add(username)
    else:
        typing_users[room_name].discard(username)

    emit("user_typing", {
        "username": username,
        "isTyping": is_typing
    }, room=room_name)

@socketio.on("react")
def handle_reaction(data):
    username = data.get("username")
    session_id = data.get("session_id")
    message_id = data.get("message_id")
    emoji = data.get("emoji")
    room_name = session.get("room_name")

    logger.info(f"Reaction request: {username} on message {message_id} with {emoji} in {room_name}, Cookies: {request.cookies}, Host: {request.host}")
    if not room_name or room_name not in room_users or username not in room_users[room_name]:
        logger.warning(f"Invalid room or user for reaction: {room_name}, {username}")
        emit("error", {"message": "Invalid room or user"})
        return

    if room_users[room_name][username]["session_id"] != session_id:
        logger.warning(f"Invalid session for reaction: {username}")
        emit("error", {"message": "Invalid session"})
        return

    message = Message.query.filter_by(id=message_id).first()
    if not message:
        logger.warning(f"Message not found for reaction: {message_id}")
        emit("error", {"message": "Message not found"})
        return

    reactions = json.loads(message.reactions)
    reaction_entry = next((r for r in reactions if r["emoji"] == emoji), None)
    if reaction_entry:
        if username not in reaction_entry["users"]:
            reaction_entry["users"].append(username)
    else:
        reactions.append({"emoji": emoji, "users": [username]})
    
    message.reactions = json.dumps(reactions)
    try:
        db.session.commit()
        emit("reaction", {
            "message_id": message_id,
            "reactions": reactions
        }, room=room_name)
        logger.info(f"Reaction saved: {emoji} on message {message_id}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Reaction error: {e}")
        emit("error", {"message": "Failed to save reaction"})

@socketio.on("send_message")
def handle_message(data):
    username = data.get("username")
    message = data.get("message")
    session_id = data.get("session_id")
    room_name = session.get("room_name")
    is_summary = data.get("is_summary", False)
    
    logger.info(f"Send message request: {username} in {room_name}: {message}, Cookies: {request.cookies}, Host: {request.host}")
    if not room_name or room_name not in room_users:
        logger.warning(f"Invalid room: {room_name}")
        emit("error", {"message": "Invalid room"})
        return

    if username not in room_users[room_name] or room_users[room_name][username]["session_id"] != session_id:
        logger.warning(f"Invalid session or user: {username}, {session_id}")
        emit("error", {"message": "Invalid session or user"})
        return

    model = data.get("model", room_users[room_name][username]["model"])
    user_role = room_users[room_name][username]["role"]

    if message.startswith("/kick "):
        if user_role != "admin":
            logger.warning(f"{username} attempted kick without admin role")
            emit("error", {"message": "Only room admins can kick users"})
            return
        target_username = message[6:].strip()
        if target_username not in room_users[room_name]:
            logger.warning(f"Kick attempt for non-existent user: {target_username}")
            emit("error", {"message": f"User {target_username} not found in this room"})
            return
        if target_username == username:
            logger.warning(f"{username} attempted to kick themselves")
            emit("error", {"message": "You cannot kick yourself"})
            return
        if room_users[room_name][target_username]["role"] == "admin":
            logger.warning(f"{username} attempted to kick admin {target_username}")
            emit("error", {"message": "Cannot kick room admin"})
            return
        
        member_to_kick = RoomMember.query.filter_by(room_name=room_name, username=target_username).first()
        if member_to_kick:
            member_to_kick.is_active = False
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Kick user error: {e}")
                emit("error", {"message": "Failed to kick user"})
                return

        target_sid = room_users[room_name][target_username]["sid"]
        emit("kicked", {"username": target_username}, room=target_sid)
        
        kick_msg = Message(
            room_name=room_name,
            username="System",
            content=f"{target_username} was kicked by {username}",
            message_type="system",
            timestamp=datetime.datetime.now(tz=ZoneInfo("Asia/Kolkata")),
            reactions='[]'
        )
        try:
            db.session.add(kick_msg)
            db.session.commit()
            emit("receive_message", {
                "username": "System",
                "message": kick_msg.content,
                "timestamp": kick_msg.timestamp.isoformat(),
                "type": "system",
                "id": str(kick_msg.id),
                "reactions": []
            }, room=room_name)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Kick message error: {e}")
            emit("error", {"message": "Failed to broadcast kick message"})
            return
        
        typing_users[room_name].discard(target_username)
        del room_users[room_name][target_username]
        active_members = RoomMember.query.filter_by(room_name=room_name, is_active=True).all()
        user_list = [{"username": m.username, "role": m.role} for m in active_members]
        emit("user_list", user_list, room=room_name)
        emit("user_typing", {"username": target_username, "isTyping": False}, room=room_name)
        logger.info(f"{target_username} kicked from {room_name}")
        return
    
    log_filename = f"{LOG_DIR}/{username}_{session_id}.json"
    log_entry = {
        "time": reply_msg.timestamp.isoformat(),
        "room": room_name,
        "username": username,
        "message": message,
        "reply": reply_msg.content
    }
    try:
        with open(log_filename, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        logger.info(f"Log written to {log_filename}")
    except Exception as e:
        logger.error(f"Failed to write log to {log_filename}: {e}")

    if message == "/clear":
        if user_role != "admin":
            logger.warning(f"{username} attempted clear without admin role")
            emit("error", {"message": "Only room admins can clear chat"})
            return
        
        try:
            Message.query.filter_by(room_name=room_name).delete()
            db.session.commit()
            emit("clear_chat", room=room_name)
            
            clear_msg = Message(
                room_name=room_name,
                username="System",
                content=f"{username} cleared the chat",
                message_type="system",
                timestamp=datetime.datetime.now(tz=ZoneInfo("Asia/Kolkata")),
                reactions='[]'
            )
            db.session.add(clear_msg)
            db.session.commit()
            emit("receive_message", {
                "username": "System",
                "message": clear_msg.content,
                "timestamp": clear_msg.timestamp.isoformat(),
                "type": "system",
                "id": str(clear_msg.id),
                "reactions": []
            }, room=room_name)
            logger.info(f"Chat cleared in {room_name} by {username}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Clear chat error: {e}")
            emit("error", {"message": "Failed to clear chat"})
        return

    if message == "/help":
        try:
            help_msg = Message(
                room_name=room_name,
                username="System",
                content=HELP_MESSAGE,
                message_type="system",
                timestamp=datetime.datetime.now(tz=ZoneInfo("Asia/Kolkata")),
                reactions='[]'
            )
            db.session.add(help_msg)
            db.session.commit()
            emit("receive_message", {
                "username": "System",
                "message": HELP_MESSAGE,
                "timestamp": help_msg.timestamp.isoformat(),
                "type": "system",
                "id": str(help_msg.id),
                "reactions": []
            }, room=room_name)
            logger.info(f"Help message sent in {room_name}")
        except Exception as e:
            logger.error(f"Help message error: {e}")
            emit("error", {"message": "Failed to send help message"})
        return

    mentions = re.findall(r'@(\w+)', message)
    for mentioned_user in mentions:
        if mentioned_user in room_users[room_name] and mentioned_user != username:
            try:
                emit("receive_message", {
                    "username": "System",
                    "message": f"{username} mentioned {mentioned_user}",
                    "timestamp": datetime.now(tz=ZoneInfo("Asia/Kolkata")).isoformat(),
                    "type": "system",
                    "id": str(uuid.uuid4())[:8],
                    "reactions": []
                }, room=room_users[room_name][mentioned_user]["sid"])
            except Exception as e:
                logger.error(f"Mention error: {e}")

    user_msg = Message(
        room_name=room_name,
        username=username,
        content=message,
        message_type="user",
        timestamp=datetime.datetime.now(tz=ZoneInfo("Asia/Kolkata")),
        reactions='[]'
    )
    try:
        db.session.add(user_msg)
        db.session.commit()
        emit("receive_message", {
            "username": username,
            "message": message,
            "timestamp": user_msg.timestamp.isoformat(),
            "type": "user",
            "id": str(user_msg.id),
            "reactions": []
        }, room=room_name)
        logger.info(f"Message sent by {username} in {room_name}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Save message error: {e}")
        emit("error", {"message": "Failed to save message"})
        return

    if "jarvis" not in message.lower() and not is_summary:
        return

    def call_openrouter(model_name):
        recent_msgs = Message.query.filter_by(room_name=room_name).order_by(Message.timestamp.desc()).limit(10).all()
        recent_msgs.reverse()
        
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for msg in recent_msgs:
            if msg.message_type == "user":
                messages.append({"role": "user", "content": f"{msg.username}: {msg.content}"})
            elif msg.message_type == "ai":
                messages.append({"role": "assistant", "content": msg.content})
        
        if is_summary or message.lower().startswith("jarvis summarize") or message.lower().startswith("jarvis insights"):
            prompt = f"{username}: Please provide a {'summary of recent chat activity' if message.lower().startswith('jarvis summarize') else 'insights on chat activity, including most active users and key topics'}"
            messages.append({"role": "user", "content": prompt})
        else:
            messages[-1]["content"] = messages[-1]["content"].replace("jarvis ", "", 1).replace("Jarvis ", "", 1)

        try:
            response = requests.post("https://openrouter.ai/api/v1/chat/completions",
                                   headers={
                                       "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                                       "Content-Type": "application/json",
                                   },
                                   json={
                                       "model": model_name,
                                       "messages": messages,
                                       "temperature": 0.7,
                                       "max_tokens": 300
                                   })
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"OpenRouter error: {e}")
            return None

    reply = call_openrouter(model)
    if not reply:
        logger.warning(f"Failed to get AI response for {username} in {room_name}")
        emit("error", {"message": "Failed to get response from AI"})
        return

    model_used = model.split("/")[-1]
    reply = f"Hey {username},\n{reply}"
    reply_msg = Message(
        room_name=room_name,
        username="Jarvis 🤖",
        content=f"[{model_used}] {reply}",
        message_type="ai",
        model_used=model_used,
        timestamp=datetime.datetime.now(tz=ZoneInfo("Asia/Kolkata")),
        reactions='[]'
    )
    try:
        db.session.add(reply_msg)
        chat_log = ChatLog(
            room_name=room_name,
            username=username,
            session_id=session_id,
            user_message=message,
            ai_response=reply_msg.content,
            model_used=model_used
        )
        db.session.add(chat_log)
        db.session.commit()

        emit_event = "summary" if is_summary or message.lower().startswith("jarvis summarize") or message.lower().startswith("jarvis insights") else "receive_message"
        emit(emit_event, {
            "username": "Jarvis 🤖",
            "message": reply_msg.content,
            "timestamp": reply_msg.timestamp.isoformat(),
            "type": "ai",
            "id": str(reply_msg.id),
            "reactions": []
        }, room=room_name)
        logger.info(f"AI response sent in {room_name} for {username}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"AI response error: {e}")
        emit("error", {"message": "Failed to save AI response"})
        return

    log_filename = f"{LOG_DIR}/{username}_{session_id}.json"
    log_entry = {
        "time": reply_msg.timestamp.isoformat(),
        "room": room_name,
        "username": username,
        "message": message,
        "reply": reply_msg.content
    }
    with open(log_filename, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

@socketio.on("disconnect")
def handle_disconnect():
    username = session.get("username")
    room_name = session.get("room_name")
    
    logger.info(f"Disconnect request: {username} from {room_name}, Cookies: {request.cookies}, Host: {request.host}")
    if username and room_name and room_name in room_users and username in room_users[room_name]:
        role = room_users[room_name][username]["role"]
        
        member = RoomMember.query.filter_by(room_name=room_name, username=username).first()
        if member:
            member.is_active = False
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Disconnect error: {e}")

        typing_users[room_name].discard(username)
        del room_users[room_name][username]
        
        active_members = RoomMember.query.filter_by(room_name=room_name, is_active=True).all()
        user_list = [{"username": m.username, "role": m.role} for m in active_members]
        emit("user_list", user_list, room=room_name)
        emit("user_typing", {"username": username, "isTyping": False}, room=room_name)
        
        disconnect_msg = Message(
            room_name=room_name,
            username="System",
            content=f"{username} ({role}) left the room",
            message_type="system",
            timestamp=datetime.datetime.now(tz=ZoneInfo("Asia/Kolkata")),
            reactions='[]'
        )
        try:
            db.session.add(disconnect_msg)
            db.session.commit()
            emit("receive_message", {
                "username": "System",
                "message": disconnect_msg.content,
                "timestamp": disconnect_msg.timestamp.isoformat(),
                "type": "system",
                "id": str(disconnect_msg.id),
                "reactions": []
            }, room=room_name)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Disconnect message error: {e}")
print("Starting Flask-SocketIO server...")
if __app__ == "__app__":
    try:
        print("Starting Flask-SocketIO server...")
        socketio.run(app, host="0.0.0.0", port=5000)
    except Exception as e:
        print(f"Error starting server: {e}")
