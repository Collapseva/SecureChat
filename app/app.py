from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect()

from flask import Flask, render_template, redirect, url_for, request, session, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
from flask_socketio import SocketIO, join_room, leave_room
from flask_migrate import Migrate
import re
import os
from datetime import datetime, timezone
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger('werkzeug')
logger.setLevel(logging.INFO)

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))


connection_string = os.getenv("DATABASE_URL", "")
if not connection_string:
    print("Connection env not inited")
    exit(1)

app = Flask(__name__)

app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

app.secret_key = os.getenv("SECRET_KEY", "")
if not app.secret_key:
    print("Secret key env not inited")
    exit(1)

app.config['SQLALCHEMY_DATABASE_URI'] = connection_string
db = SQLAlchemy(app)

migrate = Migrate(app, db)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx', 'xlsx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 5,
    'max_overflow': 10,
    'pool_timeout': 30,
    'pool_pre_ping': True
}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

socketio = SocketIO(
    app,
    async_mode='eventlet'
)
app.config['GOOGLE_CLIENT_ID'] = ''  
app.config['GOOGLE_CLIENT_SECRET'] = ''  

oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v2/',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v2/userinfo',
    client_kwargs={'scope': 'openid email profile'},
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

USERNAME_REGEX = r'^[A-Z0-9_]+$'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(400), nullable=True)
    oauth_provider = db.Column(db.String(50), nullable=True)
    oauth_id = db.Column(db.String(100), nullable=True)
    avatar_path = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=True)
    public_key = db.Column(db.Text, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if self.password_hash:
            return check_password_hash(self.password_hash, password)
        return False

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_group = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(150), nullable=True)
    messages = db.relationship('Message', backref='chat', lazy='dynamic')
    memberships = db.relationship('ChatMembership', backref='chat', lazy='dynamic')

class ChatMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='chat_memberships')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=True)
    content_sender = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(200), nullable=True)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    sender = db.relationship('User', backref='messages')
    is_encrypted = db.Column(db.Boolean, default=False)

class ChatInvitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    from_user = db.relationship('User', foreign_keys=[from_user_id], backref='sent_invitations')
    to_user = db.relationship('User', foreign_keys=[to_user_id], backref='received_invitations')
    chat = db.relationship('Chat', backref='invitations')

@app.route('/keys/publish', methods=['POST'])
@login_required
def publish_key():
    public_key = request.json.get('public_key')
    if not public_key:
        return {'error': 'Public key is required'}, 400
    
    user = db.session.get(User, current_user.id)
    user.public_key = public_key
    db.session.commit()
    
    return {'success': True}, 200

@app.route('/keys/user/<int:user_id>')
@login_required
def get_user_key(user_id):
    user = db.session.get(User, user_id)
    if not user or not user.public_key:
        abort(404, description="User or public key not found.")
    return {'public_key': user.public_key}


@app.template_filter('datetimeformat')
def datetimeformat_filter(value, format='%d.%m.%Y %H:%M'):
    if value is None:
        return ""
    return value.strftime(format)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
  
    memberships = ChatMembership.query.filter_by(user_id=current_user.id).all()
    chats = [m.chat for m in memberships]

  
  
    chats_with_unread = []
    for chat in chats:
        last_read_time = session.get(f'last_read_{chat.id}_{current_user.id}', datetime.now(timezone.utc).replace(tzinfo=None))
        unread_count = Message.query.filter(
            Message.chat_id == chat.id,
            Message.timestamp > last_read_time,
            Message.sender_id != current_user.id
        ).count()
      
        if not hasattr(chat, 'unread_counts'):
            chat.unread_counts = {}
        chat.unread_counts[current_user.id] = unread_count
        chats_with_unread.append(chat)

  
    invitations = ChatInvitation.query.filter_by(to_user_id=current_user.id, status='pending').all()
    error = request.args.get('error')
    message = request.args.get('message')
    return render_template('dashboard.html', username=current_user.username, chats=chats_with_unread, invitations=invitations, error=error, message=message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].upper()
        password = request.form['password']

        if not re.match(USERNAME_REGEX, username):
            error = 'Имя пользователя может содержать только заглавные английские буквы, цифры и нижнее подчёркивание.'
            return render_template('register.html', error=error)
         
        logger.info("PON 1")

        if User.query.filter_by(username=username).first():
            error = 'Пользователь с таким именем уже существует.'
            return render_template('register.html', error=error)
         

        logger.info("PON 2")
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].upper()
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            error = 'Неверное имя пользователя или пароль.'
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    oauth_id = user_info['id']
    user = User.query.filter_by(oauth_provider='google', oauth_id=oauth_id).first()
    if user is None:
        username = user_info['email'].split('@')[0].upper()
        original_username = username
        count = 1
        while User.query.filter_by(username=username).first():
            username = f"{original_username}{count}"
            count += 1
        user = User(
            username=username,
            oauth_provider='google',
            oauth_id=oauth_id
        )
        db.session.add(user)
        db.session.commit()
    login_user(user)
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/invite', methods=['POST'])
@login_required
def send_invitation():
    username = request.form['username'].upper()
    chat_id = request.form.get('chat_id', type=int)

    if username == current_user.username:
        error = 'Нельзя отправить приглашение самому себе.'
        return redirect(url_for('dashboard', error=error))

    user = User.query.filter_by(username=username).first()
    if user:
      
        if chat_id:
            chat = Chat.query.get(chat_id)
            if not chat or not chat.is_group:
                error = 'Неверный чат для приглашения.'
                return redirect(url_for('dashboard', error=error))
          
            membership = ChatMembership.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()
            if not membership:
                error = 'Вы не являетесь участником данного чата.'
                return redirect(url_for('dashboard', error=error))
            
          
            existing_membership = ChatMembership.query.filter_by(chat_id=chat_id, user_id=user.id).first()
            if existing_membership:
                error = 'Пользователь уже в чате.'
                return redirect(url_for('dashboard', error=error))

            existing_invitation = ChatInvitation.query.filter_by(
                from_user_id=current_user.id, to_user_id=user.id, chat_id=chat_id, status='pending').first()
            if existing_invitation:
                error = 'Вы уже отправили приглашение этому пользователю в эту группу.'
                return redirect(url_for('dashboard', error=error))
            
            invitation = ChatInvitation(from_user_id=current_user.id, to_user_id=user.id, chat_id=chat_id)
            db.session.add(invitation)
            db.session.commit()

            socketio.emit('new_invitation', {
                'from_username': current_user.username,
                'invitation_id': invitation.id,
                'timestamp': invitation.timestamp.strftime('%d.%m.%Y %H:%M'),
                'chat_name': invitation.chat.name,
            }, room=f'user_{user.id}')
            
            message = 'Приглашение в групповй чат отправлено.'
            return redirect(url_for('dashboard', message=message))

        else:
          
            existing_invitation = ChatInvitation.query.filter_by(
                from_user_id=current_user.id, to_user_id=user.id, status='pending', chat_id=None).first()

          
            existing_chat = None
          
            for m in current_user.chat_memberships:
                c = m.chat
                if not c.is_group:
                  
                    other_mem = ChatMembership.query.filter_by(chat_id=c.id, user_id=user.id).first()
                    if other_mem:
                        existing_chat = c
                        break

            if existing_invitation:
                error = 'Вы уже отправили приглашение этому пользователю.'
                return redirect(url_for('dashboard', error=error))
            if existing_chat:
                error = 'У вас уже есть чат с этим пользователем.'
                return redirect(url_for('dashboard', error=error))

            invitation = ChatInvitation(from_user_id=current_user.id, to_user_id=user.id)
            db.session.add(invitation)
            db.session.commit()

            socketio.emit('new_invitation', {
                'from_username': current_user.username,
                'invitation_id': invitation.id,
                'timestamp': invitation.timestamp.strftime('%d.%m.%Y %H:%M'),
                'chat_name': "Приватный чат",
            }, room=f'user_{user.id}')
            
            message = 'Приглашение отправлено.'
            return redirect(url_for('dashboard', message=message))
    else:
        error = 'Пользователь с таким именем не найден.'
        return redirect(url_for('dashboard', error=error))

@app.route('/invitation/accept/<int:invitation_id>', methods=['POST'])
@login_required
def accept_invitation(invitation_id):
    invitation = ChatInvitation.query.get_or_404(invitation_id)
    if invitation.to_user_id != current_user.id:
        abort(403)
    invitation.status = 'accepted'
    if invitation.chat_id:
      
        chat = invitation.chat
        if not chat:
            abort(404)
      
        membership = ChatMembership(chat_id=chat.id, user_id=current_user.id)
        db.session.add(membership)
        db.session.commit()
    else:
      
        chat = Chat(is_group=False)
        db.session.add(chat)
        db.session.commit()
      
        membership1 = ChatMembership(chat_id=chat.id, user_id=invitation.from_user_id)
        membership2 = ChatMembership(chat_id=chat.id, user_id=invitation.to_user_id)
        db.session.add(membership1)
        db.session.add(membership2)
        db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/invitation/decline/<int:invitation_id>', methods=['POST'])
@login_required
def decline_invitation(invitation_id):
    invitation = ChatInvitation.query.get_or_404(invitation_id)
    if invitation.to_user_id != current_user.id:
        abort(403)
    invitation.status = 'declined'
    db.session.commit()
    socketio.emit('invitation_declined', {
        'to_username': current_user.username,
    }, room=f'user_{invitation.from_user_id}')
    return redirect(url_for('dashboard'))

@app.route('/chat/<int:chat_id>', methods=['GET'])
@login_required
def chat_view(chat_id):
    chat = Chat.query.get_or_404(chat_id)
  
    membership = ChatMembership.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()
    if not membership:
        abort(403)
  
    messages = chat.messages.order_by(Message.timestamp.asc()).all()
    session[f'last_read_{chat.id}_{current_user.id}'] = datetime.now(timezone.utc).replace(tzinfo=None)
  
    other_user_id = None
    if chat.is_group:
        chat_name = chat.name if chat.name else "Групповой чат"
    else:
      
        memberships = ChatMembership.query.filter_by(chat_id=chat.id).all()
        other_user = None
        for m in memberships:
            if m.user_id != current_user.id:
                other_user = m.user
                other_user_id = other_user.id
                break
        chat_name = f"Чат с {other_user.username}" if other_user else "Чат"

    return render_template('chat.html', chat=chat, messages=messages, chat_name=chat_name, other_user_id=other_user_id)

@app.route('/send_message', methods=['POST'])
@login_required
def ajax_send_message():
    chat_id = request.form.get('chat_id', type=int)
    content = request.form.get('message', '')
    content_sender = request.form.get('message_sender', '')
    file = request.files.get('file')

    chat = db.session.get(Chat, chat_id)
    if not chat:
        return {'error': 'Chat not found'}, 400
    membership = ChatMembership.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()
    if not membership:
        return {'error': 'Not a member'}, 403

    file_path = None
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        file_path = filename

    if not content.strip() and not file_path:
        return {'error': 'Empty message'}, 400

    message = Message(
        chat_id=chat_id, 
        sender_id=current_user.id, 
        content=content.strip(), 
        content_sender=content_sender.strip(),
        file_path=file_path, 
        is_encrypted=not chat.is_group
    )
    db.session.add(message)
    db.session.commit()

  
    chat_members = ChatMembership.query.filter_by(chat_id=chat_id).all()
    for member in chat_members:
        if member.user_id != current_user.id:
            socketio.emit('new_message', {
                'chat_id': chat_id,
                'from_username': current_user.username,
                'content': content.strip(),
                'file_path': file_path,
                'timestamp': message.timestamp.strftime('%H:%M')
            }, room=f'user_{member.user_id}')

    return {
        'success': True,
        'chat_id': chat_id,
        'from_username': current_user.username,
        'content': content.strip(),
        'file_path': file_path,
        'timestamp': message.timestamp.strftime('%H:%M')
    }

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        description = request.form.get('description', '')
        file = request.files.get('avatar')
        avatar_path = current_user.avatar_path
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            avatar_path = filename
        current_user.description = description
        current_user.avatar_path = avatar_path
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('profile.html', user=current_user)

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        group_name = request.form.get('group_name')
        if not group_name.strip():
            return render_template('create_group.html', error="Введите название группы")
        chat = Chat(is_group=True, name=group_name.strip())
        db.session.add(chat)
        db.session.commit()
        membership = ChatMembership(chat_id=chat.id, user_id=current_user.id)
        db.session.add(membership)
        db.session.commit()
        return redirect(url_for('dashboard', message="Групповой чат создан! Теперь вы можете приглашать участников."))
    return render_template('create_group.html')

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')
        print(f'User {current_user.username} connected to room user_{current_user.id}')
    else:
        pass
        
@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(f'user_{current_user.id}')
        print(f'Пользователь {current_user.username} покинул комнату user_{current_user.id}')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=8000, debug=False, allow_unsafe_werkzeug=True)
