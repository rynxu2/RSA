from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from flask import g
from functools import wraps
from flask import send_file
import hashlib
import os
import uuid

app = Flask(__name__)
app.secret_key = 'Av4qf48x'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
socketio = SocketIO(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)  # SHA256 hex
    public_key = db.Column(db.Text, nullable=True)
    private_key = db.Column(db.Text, nullable=True)

    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()

    def set_keys(self, private_pem, public_pem):
        self.private_key = private_pem
        self.public_key = public_pem

    def get_private_key(self):
        if self.private_key:
            return serialization.load_pem_private_key(self.private_key.encode(), password=None)
        return None

    def get_public_key(self):
        if self.public_key:
            return serialization.load_pem_public_key(self.public_key.encode())
        return None

users = {}
rooms = {}

def get_current_user():
    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())
    user_id = session['user_id']
    if user_id not in users:
        # Tạo key cho user mới
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        users[user_id] = {
            'private_key': private_key,
            'public_key': private_key.public_key(),
            'public_pem': private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            'private_pem': private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        }
    return user_id, users[user_id]

def set_manual_private_key(pem_str):
    user_id, user = get_current_user()
    private_key = serialization.load_pem_private_key(
        pem_str.encode(), password=None
    )
    user['private_key'] = private_key
    user['public_key'] = private_key.public_key()
    user['private_pem'] = pem_str
    user['public_pem'] = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def set_manual_public_key(pem_str):
    user_id, user = get_current_user()
    user['public_key'] = serialization.load_pem_public_key(pem_str.encode())
    user['public_pem'] = pem_str

def load_private_key():
    # Ưu tiên lấy private key từ DB nếu user đã đăng nhập
    user_id = session.get('user_id')
    if user_id is not None:
        try:
            # Nếu user_id là số (id trong DB)
            user = db.session.get(User, user_id)
            if user and user.private_key:
                return serialization.load_pem_private_key(user.private_key.encode(), password=None)
        except Exception:
            pass
    # Fallback: lấy từ RAM (guest)
    _, user = get_current_user()
    return user['private_key']

def load_public_key():
    user_id, user = get_current_user()
    pem = session.get('custom_public_key')
    if pem:
        return serialization.load_pem_public_key(pem.encode())
    return user['public_key']

def generate_keys():
    user_id, user = get_current_user()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    user['private_key'] = private_key
    user['public_key'] = private_key.public_key()
    user['private_pem'] = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    user['public_pem'] = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

# Hàm lưu chữ ký vào file
def save_signature_to_file(signature, sig_path):
    with open(sig_path, 'wb') as sigf:
        sigf.write(signature)

# Hàm lấy danh sách file trong room
def get_files_in_room(room):
    return room.get('files', [])

# Hàm thêm file vào room
def add_file_to_room(room, file_info):
    room_files = get_files_in_room(room)
    room_files.append(file_info)
    room['files'] = room_files

# Hàm tạo sự kiện thông báo có file mới
def create_new_file_event(room_id, filename, file_size):
    return {
        'room_id': room_id,
        'filename': filename,
        'size': file_size
    }

# Hàm tạo room mới
def create_new_room(room_name, password):
    room_id = str(uuid.uuid4())[:8]
    rooms[room_id] = {
        'name': room_name,
        'password': password,
        'files': [],
        'created_at': datetime.now(),
        'members': []
    }
    return room_id

# Hàm kiểm tra và lưu trữ room
def check_and_store_room(room_id, password, room_name):
    room = rooms.get(room_id)
    if room and room['password'] == password:
        return room
    elif not room:
        # Nếu room không tồn tại, tạo mới
        return create_new_room(room_name, password)
    return None

# Hàm xử lý khi người dùng tham gia room
def handle_user_join_room(room_id, password):
    room = rooms.get(room_id)
    if room and room['password'] == password:
        return room
    return None

# Hàm xử lý khi người dùng tải file lên
def handle_file_upload(file, room_id):
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], room_id + '_' + filename)
    file.save(file_path)
    signature = sign_file(file_path)
    sig_path = file_path + '.sig'
    save_signature_to_file(signature, sig_path)
    file_size = os.path.getsize(file_path)
    uploaded_at = datetime.now()
    # Lấy username uploader
    uploader = None
    if 'user_id' in session:
        user = None
        try:
            user = db.session.get(User, session['user_id'])
        except Exception:
            user = User.query.get(session['user_id'])
        if user:
            uploader = user.username
    return {'filename': filename, 'path': file_path, 'sig': sig_path, 'size': file_size, 'uploaded_at': uploaded_at, 'uploader': uploader}

# Hàm xử lý khi người dùng tạo room mới
def handle_create_room(room_name, password):
    room_id = str(uuid.uuid4())[:8]
    rooms[room_id] = {
        'name': room_name,
        'password': password,
        'files': [],
        'created_at': datetime.now(),
        'members': []
    }
    return room_id

# Hàm xử lý khi người dùng tham gia room
def handle_join_room(room_id, password):
    room = rooms.get(room_id)
    if room and room['password'] == password:
        return room
    return None

# Hàm cập nhật thông tin room
def update_room_info(room_id, file_info):
    room = rooms.get(room_id)
    if room:
        add_file_to_room(room, file_info)
        return True
    return False

# Hàm phát sự kiện tới tất cả client trong room
def emit_event_to_room(room_id, event_name, data):
    socketio.emit(event_name, data, room=room_id)

# Hàm phát sự kiện tới tất cả client
def emit_event_to_all(event_name, data):
    socketio.emit(event_name, data)

# Hàm tạo room mới và phát sự kiện
def create_room_and_emit_event(room_name, password):
    room_id = handle_create_room(room_name, password)
    emit_event_to_all('new_room', {
        'room_id': room_id,
        'name': room_name
    })
    return room_id

# Hàm phát sự kiện có file mới tới tất cả client trong room
def emit_new_file_event(room_id, filename, file_size, uploader=None):
    emit_event_to_room(room_id, 'new_file', {
        'room_id': room_id,
        'filename': filename,
        'size': file_size,
        'uploader': uploader
    })

# --- Hàm ký số: ký hash SHA256 của file ---
def sign_file(filepath):
    private_key = load_private_key()
    with open(filepath, 'rb') as f:
        data = f.read()
    digest = hashlib.sha256(data).digest()
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# --- Hàm xác minh chữ ký: xác minh hash SHA256 của file ---
def verify_signature(filepath, signature, public_key):
    with open(filepath, 'rb') as f:
        data = f.read()
    digest = hashlib.sha256(data).digest()
    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# --- ROUTES ---

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', rooms=rooms)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Tên đăng nhập đã tồn tại!')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        # Tạo key mặc định cho user mới
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        user.set_keys(private_pem, public_pem)
        db.session.add(user)
        db.session.commit()
        flash('Đăng ký thành công! Đăng nhập để tiếp tục.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('Đăng nhập thành công!')
            return redirect(url_for('index'))
        flash('Sai tên đăng nhập hoặc mật khẩu!')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Đã đăng xuất!')
    return redirect(url_for('login'))

@app.route('/create_room', methods=['POST'])
def create_room():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    room_name = request.form['room_name']
    password = request.form['password']
    room_id = create_room_and_emit_event(room_name, password)
    flash('Tạo phòng thành công!')
    return redirect(url_for('room', room_id=room_id))

@app.route('/join_room', methods=['POST'])
def join_room_route():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    room_id = request.form['room_id']
    password = request.form['password']
    room = handle_join_room(room_id, password)
    if room:
        flash('Tham gia phòng thành công!')
        return redirect(url_for('room', room_id=room_id))
    flash('Sai mã phòng hoặc mật khẩu!')
    return redirect(url_for('index'))

@app.route('/room/<room_id>', methods=['GET', 'POST'])
def room(room_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    room = rooms.get(room_id)
    if not room:
        return redirect(url_for('index'))
    user = None
    try:
        user = db.session.get(User, session['user_id'])
    except Exception:
        user = User.query.get(session['user_id'])
    username = user.username if user else str(session['user_id'])
    if username not in room['members']:
        room['members'].append(username)
        socketio.emit('update_members', {'room_id': room_id, 'count': len(room['members'])}, room=room_id)
    files = get_files_in_room(room)
    user_objs = User.query.all()
    users_dict = {u.username: {'username': u.username, 'public_key': u.public_key} for u in user_objs}
    return render_template('room.html', room=room, room_id=room_id, files=files, users=users_dict)

@app.route('/upload/<room_id>', methods=['POST'])
def upload(room_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    room = rooms.get(room_id)
    if not room:
        flash('Phòng không tồn tại!')
        return redirect(url_for('index'))
    if 'file' not in request.files:
        flash('Không có file!')
        return redirect(url_for('room', room_id=room_id))
    file = request.files['file']
    if file.filename == '':
        flash('Chưa chọn file!')
        return redirect(url_for('room', room_id=room_id))
    
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        
    file_info = handle_file_upload(file, room_id)
    update_room_info(room_id, file_info)
    
    emit_new_file_event(room_id, file_info['filename'], file_info['size'], file_info.get('uploader'))
    flash('Tải file thành công!')
    return redirect(url_for('room', room_id=room_id))

@app.route('/download/<room_id>/<filename>')
def download(room_id, filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], room_id + '_' + filename)
    if not os.path.exists(file_path):
        flash('File không tồn tại!')
        return redirect(url_for('room', room_id=room_id))
    return send_file(file_path, as_attachment=True)

@app.route('/download_sig/<room_id>/<filename>')
def download_sig(room_id, filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sig_path = os.path.join(app.config['UPLOAD_FOLDER'], room_id + '_' + filename + '.sig')
    if not os.path.exists(sig_path):
        flash('Chữ ký không tồn tại!')
        return redirect(url_for('room', room_id=room_id))
    return send_file(sig_path, as_attachment=True)

@app.route('/verify/<room_id>/<filename>', methods=['POST'])
def verify(room_id, filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    public_pem = request.form.get('verify_public_pem')
    if not public_pem:
        flash('Bạn phải nhập public key để xác minh!')
        return redirect(url_for('room', room_id=room_id))
    try:
        public_key = serialization.load_pem_public_key(public_pem.encode())
    except Exception:
        flash('Public key không hợp lệ!')
        return redirect(url_for('room', room_id=room_id))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], room_id + '_' + filename)
    sig_path = file_path + '.sig'
    if not os.path.exists(file_path) or not os.path.exists(sig_path):
        flash('File hoặc chữ ký không tồn tại!')
        return redirect(url_for('room', room_id=room_id))
    with open(sig_path, 'rb') as f:
        signature = f.read()
    valid = verify_signature(file_path, signature, public_key)
    if valid:
        flash('Chữ ký hợp lệ! File toàn vẹn và đúng nguồn gửi.')
    else:
        flash('Chữ ký không hợp lệ hoặc file đã bị thay đổi!')
    return redirect(url_for('room', room_id=room_id))

@app.route('/change_key', methods=['POST'])
def change_key():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    user.set_keys(private_pem, public_pem)
    db.session.commit()
    flash('Đã tạo key mới!')
    return redirect(url_for('key'))

@socketio.on('join')
def on_join(data):
    room_id = data.get('room_id')
    if room_id:
        join_room(room_id)
        # Tăng số lượng thành viên khi join qua socket (nếu cần)
        room = rooms.get(room_id)
        if room:
            user = None
            try:
                user = db.session.get(User, session['user_id'])
            except Exception:
                user = User.query.get(session['user_id'])
            username = user.username if user else str(session['user_id'])
            if username not in room['members']:
                room['members'].append(username)
            socketio.emit('update_members', {'room_id': room_id, 'count': len(room['members'])}, room=room_id)

@socketio.on('leave')
def on_leave(data):
    room_id = data.get('room_id')
    if room_id:
        leave_room(room_id)
        room = rooms.get(room_id)
        if room:
            user = None
            try:
                user = db.session.get(User, session['user_id'])
            except Exception:
                user = User.query.get(session['user_id'])
            username = user.username if user else str(session['user_id'])
            if username in room['members']:
                room['members'].remove(username)
            socketio.emit('update_members', {'room_id': room_id, 'count': len(room['members'])}, room=room_id)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
