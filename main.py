from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import random
import string
import secrets
from PIL import Image
import pyotp
import qrcode
import io
import base64
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "wishlist_final.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', True)
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'WishLister <noreply@wishlister.com>')

app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static/uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['AVATAR_SIZE'] = (200, 200)

app.config['OTP_EXPIRE_MINUTES'] = 10
app.config['OTP_ATTEMPTS_LIMIT'] = 5
app.config['OTP_RESEND_COOLDOWN'] = 60

for folder in ['static/uploads', 'static/avatars']:
    os.makedirs(os.path.join(basedir, folder), exist_ok=True)

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    avatar = db.Column(db.String(255), default='default.png')
    bio = db.Column(db.Text)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_otp_sent = db.Column(db.DateTime)
    otp_attempts = db.Column(db.Integer, default=0)
    totp_secret = db.Column(db.String(32))
    totp_enabled = db.Column(db.Boolean, default=False)
    backup_codes = db.Column(db.Text)

    # Отношения
    wishlists = db.relationship('Wishlist', backref='owner', lazy=True, cascade='all, delete-orphan')
    sent_friend_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.sender_id',
                                           backref='sender_user', lazy=True)
    received_friend_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.receiver_id',
                                               backref='receiver_user', lazy=True)
    friendships_as_user = db.relationship('Friendship', foreign_keys='Friendship.user_id',
                                          backref='user_rel', lazy=True)
    friendships_as_friend = db.relationship('Friendship', foreign_keys='Friendship.friend_id',
                                            backref='friend_rel', lazy=True)
    shared_wishlists = db.relationship('WishlistShare', backref='shared_user', lazy=True)


class OTPCode(db.Model):
    __tablename__ = 'otp_code'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(10), nullable=False)
    purpose = db.Column(db.String(50), nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)


class Wishlist(db.Model):
    __tablename__ = 'wishlist'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    color = db.Column(db.String(20), default='#4a90e2')
    icon = db.Column(db.String(50), default='bi-gift')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    items = db.relationship('WishlistItem', backref='wishlist_rel', lazy=True, cascade='all, delete-orphan')
    shares = db.relationship('WishlistShare', backref='wishlist', lazy=True, cascade='all, delete-orphan')

    __table_args__ = (db.UniqueConstraint('user_id', 'title', name='unique_wishlist_per_user'),)


class WishlistItem(db.Model):
    __tablename__ = 'wishlist_item'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    link = db.Column(db.String(500))
    price = db.Column(db.Float)
    priority = db.Column(db.Integer, default=1)
    is_purchased = db.Column(db.Boolean, default=False)
    wishlist_id = db.Column(db.Integer, db.ForeignKey('wishlist.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class FriendRequest(db.Model):
    __tablename__ = 'friend_request'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('sender_id', 'receiver_id', name='unique_friend_request'),)


class Friendship(db.Model):
    __tablename__ = 'friendship'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'friend_id', name='unique_friendship'),)


class WishlistShare(db.Model):
    __tablename__ = 'wishlist_share'
    id = db.Column(db.Integer, primary_key=True)
    wishlist_id = db.Column(db.Integer, db.ForeignKey('wishlist.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('wishlist_id', 'user_id', name='unique_wishlist_share'),)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def save_avatar(file, user_id):
    if file and allowed_file(file.filename):
        user = User.query.get(user_id)
        if user.avatar and user.avatar != 'default.png':
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], user.avatar)
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except:
                    pass

        ext = secure_filename(file.filename).rsplit('.', 1)[1].lower()
        filename = f"avatar_{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        try:
            img = Image.open(file)
            if img.mode in ('RGBA', 'LA', 'P'):
                img = img.convert('RGB')

            img.thumbnail(app.config['AVATAR_SIZE'], Image.Resampling.LANCZOS)
            img.save(filepath, 'JPEG', quality=85)

            return filename
        except Exception as e:
            print(f"Ошибка обработки аватара: {e}")
            return None
    return None


def generate_otp_code():
    return ''.join(random.choices(string.digits, k=6))


def generate_backup_codes(count=10):
    codes = []
    for _ in range(count):
        code = secrets.token_hex(3).upper()
        codes.append(code)
    return codes


def send_email_otp(email, otp_code, purpose="регистрации"):
    try:
        subject = f"Код подтверждения WishLister: {otp_code}"
        body = f"""
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f8f9fa; border-radius: 10px;">
            <div style="text-align: center; margin-bottom: 20px;">
                <h2 style="color: #667eea; margin: 0;">WishLister</h2>
                <p style="color: #666;">Ваш список желаний</p>
            </div>

            <div style="background: white; padding: 30px; border-radius: 8px; text-align: center;">
                <h3 style="color: #333; margin-bottom: 20px;">Код подтверждения</h3>
                <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #667eea; margin: 25px 0; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    {otp_code}
                </div>
                <p style="color: #666; margin-bottom: 10px;">Используйте этот код для {purpose}</p>
                <p style="color: #999; font-size: 14px;">Код действителен в течение {app.config['OTP_EXPIRE_MINUTES']} минут</p>
            </div>

            <div style="margin-top: 20px; text-align: center; color: #999; font-size: 12px;">
                <p>Если вы не запрашивали этот код, проигнорируйте это письмо.</p>
                <p>© 2024 WishLister. Все права защищены.</p>
            </div>
        </div>
        """

        msg = Message(
            subject=subject,
            recipients=[email],
            html=body
        )

        mail.send(msg)
        return True
    except Exception as e:
        print(f"Ошибка отправки email: {e}")
        return False


def create_otp(user_id, purpose='login'):
    OTPCode.query.filter_by(
        user_id=user_id,
        purpose=purpose,
        is_used=False
    ).delete()

    otp_code = generate_otp_code()

    otp = OTPCode(
        user_id=user_id,
        code=otp_code,
        purpose=purpose,
        expires_at=datetime.utcnow() + timedelta(minutes=app.config['OTP_EXPIRE_MINUTES'])
    )

    db.session.add(otp)
    db.session.commit()

    user = User.query.get(user_id)
    success = send_email_otp(user.email, otp_code, purpose)

    if success:
        user.last_otp_sent = datetime.utcnow()
        db.session.commit()

    return success


def verify_otp(user_id, code, purpose='login'):
    user = User.query.get(user_id)
    if user.otp_attempts >= app.config['OTP_ATTEMPTS_LIMIT']:
        flash('Слишком много попыток. Попробуйте позже.', 'danger')
        return False

    otp = OTPCode.query.filter_by(
        user_id=user_id,
        purpose=purpose,
        is_used=False
    ).filter(
        OTPCode.expires_at > datetime.utcnow()
    ).first()

    if otp and otp.code == code:
        otp.is_used = True
        user.otp_attempts = 0
        db.session.commit()
        return True
    else:
        user.otp_attempts += 1
        db.session.commit()
        return False


def generate_totp_secret():
    return pyotp.random_base32()


def generate_totp_qr(user):
    if not user.totp_secret:
        user.totp_secret = generate_totp_secret()
        db.session.commit()

    totp = pyotp.TOTP(user.totp_secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="WishLister")

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#667eea", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"


def verify_totp(user, code):
    if not user.totp_secret:
        return False
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(code)


def verify_backup_code(user, code):
    if not user.backup_codes:
        return False
    try:
        backup_codes = json.loads(user.backup_codes)
        if code in backup_codes:
            backup_codes.remove(code)
            user.backup_codes = json.dumps(backup_codes)
            db.session.commit()
            return True
    except:
        pass
    return False


def get_friends(user_id):
    """Получение списка друзей без дубликатов"""
    friendships = Friendship.query.filter(
        (Friendship.user_id == user_id) | (Friendship.friend_id == user_id)
    ).all()

    friends = []
    friend_ids = set()

    for friendship in friendships:
        if friendship.user_id == user_id:
            friend_id = friendship.friend_id
        else:
            friend_id = friendship.user_id

        if friend_id not in friend_ids:
            friend = User.query.get(friend_id)
            if friend:
                friends.append(friend)
                friend_ids.add(friend_id)

    return friends


def get_accessible_wishlists(user_id):
    """Получение вишлистов, доступных пользователю"""
    wishlists = Wishlist.query.filter_by(user_id=user_id).all()

    shared_wishlists = []
    shares = WishlistShare.query.filter_by(user_id=user_id).all()
    for share in shares:
        wishlist = Wishlist.query.get(share.wishlist_id)
        if wishlist and wishlist not in wishlists:
            shared_wishlists.append(wishlist)

    public_friend_wishlists = []
    friends = get_friends(user_id)

    for friend in friends:
        friend_public_wishlists = Wishlist.query.filter_by(
            user_id=friend.id,
            is_public=True
        ).all()
        for wishlist in friend_public_wishlists:
            if wishlist not in wishlists and wishlist not in shared_wishlists:
                public_friend_wishlists.append(wishlist)

    return wishlists, shared_wishlists, public_friend_wishlists


# Обработчики ошибок
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403


# Маршруты
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Имя пользователя уже занято', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email уже используется', 'danger')
            return redirect(url_for('register'))

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )

        db.session.add(user)
        db.session.flush()

        success = create_otp(user.id, 'registration')

        if success:
            db.session.commit()
            session['pending_user_id'] = user.id
            flash('Регистрация успешна! Проверьте email для OTP кода', 'success')
            return redirect(url_for('verify_registration_otp'))
        else:
            db.session.rollback()
            flash('Ошибка отправки OTP. Попробуйте еще раз.', 'danger')

    return render_template('register.html')


@app.route('/verify-registration', methods=['GET', 'POST'])
def verify_registration_otp():
    user_id = session.get('pending_user_id')
    if not user_id:
        flash('Сессия истекла', 'danger')
        return redirect(url_for('register'))

    user = User.query.get(user_id)

    if request.method == 'POST':
        code = request.form['otp_code']

        if verify_otp(user_id, code, 'registration'):
            user.is_verified = True
            db.session.commit()

            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            db.session.commit()

            session.pop('pending_user_id', None)

            flash('Email подтвержден! Добро пожаловать!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный OTP код', 'danger')

    return render_template('verify_otp.html', purpose='регистрации', user=user)


@app.route('/resend-otp/<purpose>')
def resend_otp(purpose):
    user_id = session.get('pending_user_id') or current_user.id
    user = User.query.get(user_id)

    if not user:
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('index'))

    if user.last_otp_sent and datetime.utcnow() - user.last_otp_sent < timedelta(
            seconds=app.config['OTP_RESEND_COOLDOWN']):
        flash('Подождите перед отправкой нового кода', 'warning')
        return redirect(request.referrer or url_for('index'))

    success = create_otp(user_id, purpose)

    if success:
        flash(f'Новый OTP код отправлен на email', 'success')
    else:
        flash('Ошибка отправки OTP кода', 'danger')

    return redirect(request.referrer or url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                flash('Пожалуйста, подтвердите email', 'warning')
                return redirect(url_for('login'))

            if user.totp_enabled:
                session['pending_login_user_id'] = user.id
                return redirect(url_for('verify_2fa_login'))

            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            db.session.commit()

            flash(f'Добро пожаловать, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')

    return render_template('login.html')


@app.route('/verify-2fa-login', methods=['GET', 'POST'])
def verify_2fa_login():
    user_id = session.get('pending_login_user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    if request.method == 'POST':
        code = request.form['code']

        if verify_totp(user, code) or verify_backup_code(user, code):
            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            db.session.commit()

            session.pop('pending_login_user_id', None)

            flash('2FA подтверждена! Добро пожаловать!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный код подтверждения', 'danger')

    return render_template('verify_2fa.html', user=user)


@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()

    session.clear()

    response = redirect(url_for('index'))
    response.delete_cookie('session')
    response.delete_cookie('remember_token')
    response.delete_cookie('WishLister_session')

    flash('Вы успешно вышли из системы', 'info')
    return response


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            success = create_otp(user.id, 'reset')
            if success:
                session['reset_user_id'] = user.id
                flash('Инструкции по сбросу пароля отправлены на email', 'success')
                return redirect(url_for('reset_password'))

        flash('Если email существует, инструкции будут отправлены', 'info')

    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    user_id = session.get('reset_user_id')
    if not user_id:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        code = request.form['otp_code']
        new_password = request.form['new_password']

        if verify_otp(user_id, code, 'reset'):
            user = User.query.get(user_id)
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()

            session.pop('reset_user_id', None)
            flash('Пароль успешно изменен!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Неверный OTP код', 'danger')

    return render_template('reset_password.html')


@app.route('/profile/security')
@login_required
def security_settings():
    qr_code = None
    if not current_user.totp_enabled:
        qr_code = generate_totp_qr(current_user)

    backup_codes = []
    if current_user.backup_codes:
        backup_codes = json.loads(current_user.backup_codes)

    return render_template('security_settings.html',
                           qr_code=qr_code,
                           backup_codes=backup_codes)


@app.route('/profile/enable-totp', methods=['POST'])
@login_required
def enable_totp():
    code = request.form['code']

    if verify_totp(current_user, code):
        current_user.totp_enabled = True
        backup_codes = generate_backup_codes()
        current_user.backup_codes = json.dumps(backup_codes)
        db.session.commit()

        flash('Двухфакторная аутентификация включена!', 'success')
        flash('Сохраните резервные коды в безопасном месте!', 'warning')
    else:
        flash('Неверный код подтверждения', 'danger')

    return redirect(url_for('security_settings'))


@app.route('/profile/disable-totp', methods=['POST'])
@login_required
def disable_totp():
    password = request.form['password']

    if check_password_hash(current_user.password_hash, password):
        current_user.totp_enabled = False
        current_user.totp_secret = None
        current_user.backup_codes = None
        db.session.commit()

        flash('Двухфакторная аутентификация отключена', 'success')
    else:
        flash('Неверный пароль', 'danger')

    return redirect(url_for('security_settings'))


@app.route('/profile/regenerate-backup-codes', methods=['POST'])
@login_required
def regenerate_backup_codes():
    password = request.form['password']

    if check_password_hash(current_user.password_hash, password):
        backup_codes = generate_backup_codes()
        current_user.backup_codes = json.dumps(backup_codes)
        db.session.commit()

        flash('Новые резервные коды сгенерированы!', 'success')
    else:
        flash('Неверный пароль', 'danger')

    return redirect(url_for('security_settings'))


@app.route('/dashboard')
@login_required
def dashboard():
    tab = request.args.get('tab', 'wishlists')

    wishlists = Wishlist.query.filter_by(user_id=current_user.id).all()

    friends = get_friends(current_user.id)

    incoming_requests = FriendRequest.query.filter_by(
        receiver_id=current_user.id, status='pending'
    ).all()

    outgoing_requests = FriendRequest.query.filter_by(
        sender_id=current_user.id, status='pending'
    ).all()

    # Вишлисты друзей, которые являются публичными
    friend_wishlists = []
    for friend in friends:
        friend_wishlists.extend(
            Wishlist.query.filter(
                (Wishlist.user_id == friend.id) &
                (Wishlist.is_public == True)
            ).all()
        )

    # Удаляем дубликаты из friend_wishlists
    seen = set()
    unique_friend_wishlists = []
    for wishlist in friend_wishlists:
        if wishlist.id not in seen:
            seen.add(wishlist.id)
            unique_friend_wishlists.append(wishlist)

    friend_wishlists = unique_friend_wishlists

    total_items = sum(len(w.items) for w in wishlists)
    purchased_items = sum(1 for w in wishlists for item in w.items if item.is_purchased)

    return render_template('dashboard.html',
                           tab=tab,
                           wishlists=wishlists,
                           friends=friends,
                           incoming_requests=incoming_requests,
                           outgoing_requests=outgoing_requests,
                           friend_wishlists=friend_wishlists,
                           total_items=total_items,
                           purchased_items=purchased_items)


@app.route('/wishlist/create', methods=['GET', 'POST'])
@login_required
def create_wishlist():
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form.get('description', '').strip()
        color = request.form.get('color', '#4a90e2')
        icon = request.form.get('icon', 'bi-gift')
        is_public = 'is_public' in request.form

        if not title:
            flash('Название вишлиста не может быть пустым', 'danger')
            return redirect(url_for('create_wishlist'))

        existing_wishlist = Wishlist.query.filter_by(
            user_id=current_user.id,
            title=title
        ).first()

        if existing_wishlist:
            flash('У вас уже есть вишлист с таким названием. Выберите другое название.', 'danger')
            return redirect(url_for('create_wishlist'))

        wishlist = Wishlist(
            title=title,
            description=description,
            color=color,
            icon=icon,
            is_public=is_public,
            user_id=current_user.id
        )

        db.session.add(wishlist)
        db.session.commit()

        flash('Вишлист создан!', 'success')
        return redirect(url_for('view_wishlist', id=wishlist.id))

    icons = [
        ('bi-gift', 'Подарок'),
        ('bi-heart', 'Сердце'),
        ('bi-star', 'Звезда'),
        ('bi-flag', 'Флаг'),
        ('bi-bookmark', 'Закладка'),
        ('bi-cart', 'Корзина'),
        ('bi-house', 'Дом'),
        ('bi-bag', 'Сумка'),
        ('bi-cup-straw', 'Напиток'),
        ('bi-controller', 'Игры'),
    ]

    colors = [
        ('#4a90e2', 'Синий'),
        ('#50c878', 'Зеленый'),
        ('#ff6b6b', 'Красный'),
        ('#ffd166', 'Желтый'),
        ('#9d4edd', 'Фиолетовый'),
        ('#ff9e6d', 'Оранжевый'),
        ('#06d6a0', 'Бирюзовый'),
        ('#118ab2', 'Голубой'),
    ]

    return render_template('create_wishlist.html', icons=icons, colors=colors)


@app.route('/wishlist/<int:id>')
@login_required
def view_wishlist(id):
    wishlist = Wishlist.query.get_or_404(id)

    has_access = False
    is_owner = wishlist.user_id == current_user.id

    if is_owner:
        has_access = True
    elif wishlist.is_public:
        has_access = True
    else:
        # Проверка доступа через дружбу
        friendship = Friendship.query.filter(
            ((Friendship.user_id == current_user.id) & (Friendship.friend_id == wishlist.user_id)) |
            ((Friendship.user_id == wishlist.user_id) & (Friendship.friend_id == current_user.id))
        ).first()

        if friendship:
            wishlist_share = WishlistShare.query.filter_by(
                wishlist_id=wishlist.id,
                user_id=current_user.id
            ).first()
            if wishlist_share:
                has_access = True

    if not has_access:
        flash('У вас нет доступа к этому вишлисту', 'danger')
        return redirect(url_for('dashboard'))

    items = sorted(wishlist.items, key=lambda x: (x.is_purchased, -x.priority, x.created_at))

    # Получаем список друзей для управления доступом (только для владельца)
    friends_with_access = []
    friends_without_access = []

    if is_owner:
        friends = get_friends(current_user.id)

        for friend in friends:
            if friend.id != current_user.id:
                wishlist_share = WishlistShare.query.filter_by(
                    wishlist_id=wishlist.id,
                    user_id=friend.id
                ).first()

                if wishlist_share:
                    friends_with_access.append(friend)
                else:
                    friends_without_access.append(friend)

    return render_template('view_wishlist.html',
                           wishlist=wishlist,
                           items=items,
                           is_owner=is_owner,
                           friends_with_access=friends_with_access,
                           friends_without_access=friends_without_access)


@app.route('/wishlist/<int:id>/add_item', methods=['POST'])
@login_required
def add_wishlist_item(id):
    wishlist = Wishlist.query.get_or_404(id)

    if wishlist.user_id != current_user.id:
        flash('Вы не можете добавлять предметы в этот вишлист', 'danger')
        return redirect(url_for('view_wishlist', id=id))

    name = request.form['name'].strip()
    description = request.form.get('description', '').strip()
    link = request.form.get('link', '').strip()
    price_str = request.form.get('price', '0').strip()
    priority = request.form.get('priority', 1)

    if not name:
        flash('Название предмета не может быть пустым', 'danger')
        return redirect(url_for('view_wishlist', id=id))

    # Правильная обработка цены
    price = 0
    if price_str:
        try:
            price = float(price_str)
            if price < 0:
                price = 0
        except ValueError:
            price = 0
            flash('Цена указана неверно, установлено значение 0', 'warning')

    item = WishlistItem(
        name=name,
        description=description,
        link=link,
        price=price,
        priority=int(priority),
        wishlist_id=id
    )

    db.session.add(item)
    db.session.commit()
    flash('Предмет добавлен!', 'success')
    return redirect(url_for('view_wishlist', id=id))


@app.route('/wishlist/<int:id>/share', methods=['POST'])
@login_required
def share_wishlist(id):
    wishlist = Wishlist.query.get_or_404(id)

    if wishlist.user_id != current_user.id:
        flash('Вы не можете делиться этим вишлистом', 'danger')
        return redirect(url_for('view_wishlist', id=id))

    friend_id = request.form.get('friend_id')

    if not friend_id:
        flash('Не указан друг для предоставления доступа', 'danger')
        return redirect(url_for('view_wishlist', id=id))

    # Проверяем, является ли пользователь другом
    friendship = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == friend_id)) |
        ((Friendship.user_id == friend_id) & (Friendship.friend_id == current_user.id))
    ).first()

    if not friendship:
        flash('Этот пользователь не является вашим другом', 'danger')
        return redirect(url_for('view_wishlist', id=id))

    # Проверяем, существует ли уже доступ
    existing_share = WishlistShare.query.filter_by(
        wishlist_id=id,
        user_id=friend_id
    ).first()

    if existing_share:
        flash('Друг уже имеет доступ к этому вишлисту', 'warning')
    else:
        wishlist_share = WishlistShare(
            wishlist_id=id,
            user_id=friend_id
        )
        db.session.add(wishlist_share)
        db.session.commit()
        flash('Доступ к вишлисту предоставлен другу', 'success')

    return redirect(url_for('view_wishlist', id=id))


@app.route('/wishlist/<int:id>/remove_share', methods=['POST'])
@login_required
def remove_wishlist_share(id):
    wishlist = Wishlist.query.get_or_404(id)

    if wishlist.user_id != current_user.id:
        flash('Вы не можете управлять доступом к этому вишлисту', 'danger')
        return redirect(url_for('view_wishlist', id=id))

    friend_id = request.form.get('friend_id')

    if not friend_id:
        flash('Не указан друг для отзыва доступа', 'danger')
        return redirect(url_for('view_wishlist', id=id))

    wishlist_share = WishlistShare.query.filter_by(
        wishlist_id=id,
        user_id=friend_id
    ).first()

    if wishlist_share:
        db.session.delete(wishlist_share)
        db.session.commit()
        flash('Доступ к вишлисту отозван', 'success')

    return redirect(url_for('view_wishlist', id=id))


@app.route('/wishlist/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_wishlist(id):
    wishlist = Wishlist.query.get_or_404(id)

    if wishlist.user_id != current_user.id:
        flash('Вы не можете редактировать этот вишлист', 'danger')
        return redirect(url_for('view_wishlist', id=id))

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form.get('description', '').strip()
        color = request.form.get('color', '#4a90e2')
        icon = request.form.get('icon', 'bi-gift')
        is_public = 'is_public' in request.form

        if not title:
            flash('Название вишлиста не может быть пустым', 'danger')
            return redirect(url_for('edit_wishlist', id=id))

        existing_wishlist = Wishlist.query.filter(
            Wishlist.user_id == current_user.id,
            Wishlist.title == title,
            Wishlist.id != id
        ).first()

        if existing_wishlist:
            flash('У вас уже есть вишлист с таким названием. Выберите другое название.', 'danger')
            return redirect(url_for('edit_wishlist', id=id))

        wishlist.title = title
        wishlist.description = description
        wishlist.color = color
        wishlist.icon = icon
        wishlist.is_public = is_public

        db.session.commit()
        flash('Вишлист обновлен!', 'success')
        return redirect(url_for('view_wishlist', id=id))

    icons = [
        ('bi-gift', 'Подарок'),
        ('bi-heart', 'Сердце'),
        ('bi-star', 'Звезда'),
        ('bi-flag', 'Флаг'),
        ('bi-bookmark', 'Закладка'),
        ('bi-cart', 'Корзина'),
        ('bi-house', 'Дом'),
        ('bi-bag', 'Сумка'),
        ('bi-cup-straw', 'Напиток'),
        ('bi-controller', 'Игры'),
    ]

    colors = [
        ('#4a90e2', 'Синий'),
        ('#50c878', 'Зеленый'),
        ('#ff6b6b', 'Красный'),
        ('#ffd166', 'Желтый'),
        ('#9d4edd', 'Фиолетовый'),
        ('#ff9e6d', 'Оранжевый'),
        ('#06d6a0', 'Бирюзовый'),
        ('#118ab2', 'Голубой'),
    ]

    return render_template('edit_wishlist.html',
                           wishlist=wishlist,
                           icons=icons,
                           colors=colors)


@app.route('/item/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_wishlist_item(id):
    item = WishlistItem.query.get_or_404(id)
    wishlist = Wishlist.query.get(item.wishlist_id)

    if wishlist.user_id != current_user.id:
        flash('Вы не можете редактировать этот предмет', 'danger')
        return redirect(url_for('view_wishlist', id=wishlist.id))

    if request.method == 'POST':
        name = request.form['name'].strip()
        description = request.form.get('description', '').strip()
        link = request.form.get('link', '').strip()
        price_str = request.form.get('price', '0').strip()

        if not name:
            flash('Название предмета не может быть пустым', 'danger')
            return redirect(url_for('edit_wishlist_item', id=id))

        # Правильная обработка цены
        price = 0
        if price_str:
            try:
                price = float(price_str)
                if price < 0:
                    price = 0
            except ValueError:
                price = 0
                flash('Цена указана неверно, установлено значение 0', 'warning')

        item.name = name
        item.description = description
        item.link = link
        item.price = price
        item.priority = int(request.form.get('priority', 1))

        db.session.commit()
        flash('Предмет обновлен!', 'success')
        return redirect(url_for('view_wishlist', id=wishlist.id))

    return render_template('edit_item.html', item=item)


@app.route('/toggle-dark-mode', methods=['POST'])
def toggle_dark_mode():
    if request.is_json:
        data = request.get_json()
        session['dark_mode'] = data.get('dark_mode', False)
        return jsonify({'success': True})
    return jsonify({'success': False})


@app.route('/user/<int:id>')
@login_required
def view_user_profile(id):
    user = User.query.get_or_404(id)

    if user.id == current_user.id:
        return redirect(url_for('profile'))

    # Проверяем статус дружбы
    friendship = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == user.id)) |
        ((Friendship.user_id == user.id) & (Friendship.friend_id == current_user.id))
    ).first()

    is_friend = friendship is not None

    friend_request = FriendRequest.query.filter(
        ((FriendRequest.sender_id == current_user.id) & (FriendRequest.receiver_id == user.id)) |
        ((FriendRequest.sender_id == user.id) & (FriendRequest.receiver_id == current_user.id))
    ).first()

    # Получаем вишлисты пользователя, к которым есть доступ
    accessible_wishlists = []

    # Публичные вишлисты
    public_wishlists = Wishlist.query.filter_by(
        user_id=user.id,
        is_public=True
    ).all()
    accessible_wishlists.extend(public_wishlists)

    # Приватные вишлисты, к которым у нас есть доступ через дружбу
    if is_friend:
        shared_wishlists = WishlistShare.query.filter_by(
            user_id=current_user.id
        ).all()

        for share in shared_wishlists:
            wishlist = Wishlist.query.get(share.wishlist_id)
            if wishlist and wishlist.user_id == user.id:
                accessible_wishlists.append(wishlist)

    # Получаем друзей пользователя
    friends = get_friends(user.id)

    return render_template('user_profile.html',
                           user=user,
                           friendship=friendship,
                           is_friend=is_friend,
                           friend_request=friend_request,
                           accessible_wishlists=accessible_wishlists,
                           friends=friends)


@app.route('/search/users')
@login_required
def search_users():
    query = request.args.get('q', '')
    if query:
        users = User.query.filter(
            User.username.ilike(f'%{query}%') |
            User.email.ilike(f'%{query}%')
        ).filter(User.id != current_user.id).limit(10).all()
    else:
        users = []

    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'avatar': user.avatar
    } for user in users])


@app.route('/friends/add', methods=['POST'])
@login_required
def add_friend():
    friend_id = request.form.get('friend_id')
    friend = User.query.get_or_404(friend_id)

    if friend_id == current_user.id:
        flash('Вы не можете добавить себя в друзья', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

    # Проверяем, не добавлены ли уже в друзья
    existing_friendship = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == friend_id)) |
        ((Friendship.user_id == friend_id) & (Friendship.friend_id == current_user.id))
    ).first()

    if existing_friendship:
        flash('Вы уже друзья', 'warning')
        return redirect(request.referrer or url_for('dashboard'))

    # Проверяем, не отправлен ли уже запрос
    existing_request = FriendRequest.query.filter_by(
        sender_id=current_user.id,
        receiver_id=friend_id
    ).first()

    if existing_request:
        flash('Запрос уже отправлен', 'warning')
        return redirect(request.referrer or url_for('dashboard'))

    # Проверяем, не отправлял ли нам запрос этот пользователь
    incoming_request = FriendRequest.query.filter_by(
        sender_id=friend_id,
        receiver_id=current_user.id,
        status='pending'
    ).first()

    if incoming_request:
        # Принимаем входящий запрос
        incoming_request.status = 'accepted'

        friendship1 = Friendship(
            user_id=friend_id,
            friend_id=current_user.id
        )
        friendship2 = Friendship(
            user_id=current_user.id,
            friend_id=friend_id
        )

        db.session.add(friendship1)
        db.session.add(friendship2)
        db.session.commit()

        flash('Вы приняли запрос в друзья!', 'success')
    else:
        # Создаем новый запрос
        friend_request = FriendRequest(
            sender_id=current_user.id,
            receiver_id=friend_id
        )
        db.session.add(friend_request)
        db.session.commit()
        flash('Запрос в друзья отправлен!', 'success')

    return redirect(request.referrer or url_for('dashboard'))


@app.route('/friends/respond', methods=['POST'])
@login_required
def respond_friend_request():
    request_id = request.form.get('request_id')
    action = request.form.get('action')

    friend_request = FriendRequest.query.get_or_404(request_id)

    if friend_request.receiver_id != current_user.id:
        flash('У вас нет прав для этого действия', 'danger')
        return redirect(url_for('dashboard', tab='friends'))

    if action == 'accept':
        friend_request.status = 'accepted'

        # Проверяем, не добавлены ли уже в друзья
        existing_friendship = Friendship.query.filter(
            ((Friendship.user_id == current_user.id) & (Friendship.friend_id == friend_request.sender_id)) |
            ((Friendship.user_id == friend_request.sender_id) & (Friendship.friend_id == current_user.id))
        ).first()

        if not existing_friendship:
            # Создаем только одну запись о дружбе
            friendship = Friendship(
                user_id=current_user.id,
                friend_id=friend_request.sender_id
            )
            db.session.add(friendship)

        flash('Запрос в друзья принят!', 'success')
    else:
        friend_request.status = 'rejected'
        flash('Запрос в друзья отклонен', 'info')

    db.session.commit()
    return redirect(url_for('dashboard', tab='friends'))


@app.route('/friends/remove', methods=['POST'])
@login_required
def remove_friend():
    friend_id = request.form.get('friend_id')

    # Удаляем запись о дружбе (только одну, так как у нас уникальные связи)
    Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == friend_id)) |
        ((Friendship.user_id == friend_id) & (Friendship.friend_id == current_user.id))
    ).delete()

    # Удаляем все связанные запросы
    FriendRequest.query.filter(
        ((FriendRequest.sender_id == current_user.id) & (FriendRequest.receiver_id == friend_id)) |
        ((FriendRequest.sender_id == friend_id) & (FriendRequest.receiver_id == current_user.id))
    ).delete()

    # Также удаляем доступ к приватным вишлистам
    WishlistShare.query.filter(
        (WishlistShare.user_id == current_user.id) &
        (WishlistShare.wishlist_id.in_(
            db.session.query(Wishlist.id).filter(Wishlist.user_id == friend_id)
        ))
    ).delete()

    WishlistShare.query.filter(
        (WishlistShare.user_id == friend_id) &
        (WishlistShare.wishlist_id.in_(
            db.session.query(Wishlist.id).filter(Wishlist.user_id == current_user.id)
        ))
    ).delete()

    db.session.commit()
    flash('Друг удален', 'info')
    return redirect(url_for('dashboard', tab='friends'))


@app.route('/profile')
@login_required
def profile():
    wishlists, shared_wishlists, public_friend_wishlists = get_accessible_wishlists(current_user.id)

    friends = get_friends(current_user.id)

    return render_template('profile.html',
                           wishlists=wishlists,
                           shared_wishlists=shared_wishlists,
                           friends=friends,
                           user=current_user)


@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        bio = request.form.get('bio', '').strip()

        if not username or not email:
            flash('Имя пользователя и email не могут быть пустыми', 'danger')
            return redirect(url_for('edit_profile'))

        # Проверка уникальности имени пользователя
        if username != current_user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Имя пользователя уже занято', 'danger')
                return redirect(url_for('edit_profile'))

        # Проверка уникальности email
        if email != current_user.email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('Email уже используется', 'danger')
                return redirect(url_for('edit_profile'))

        current_user.username = username
        current_user.email = email
        current_user.bio = bio

        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename:
                filename = save_avatar(file, current_user.id)
                if filename:
                    current_user.avatar = filename
                    flash('Аватар обновлен', 'success')

        new_password = request.form.get('new_password')
        if new_password:
            current_user.password_hash = generate_password_hash(new_password)
            flash('Пароль обновлен', 'success')

        db.session.commit()
        flash('Профиль обновлен!', 'success')
        return redirect(url_for('profile'))

    return render_template('edit_profile.html')


@app.route('/item/<int:id>/toggle_purchased', methods=['POST'])
@login_required
def toggle_purchased(id):
    item = WishlistItem.query.get_or_404(id)
    wishlist = Wishlist.query.get(item.wishlist_id)

    # Проверяем доступ
    has_access = False
    if wishlist.user_id == current_user.id:
        has_access = True
    else:
        # Проверяем доступ через shared вишлисты
        share_access = WishlistShare.query.filter_by(
            wishlist_id=wishlist.id,
            user_id=current_user.id
        ).first()
        if share_access:
            has_access = True

    if not has_access:
        return jsonify({'error': 'Нет доступа'}), 403

    item.is_purchased = not item.is_purchased
    db.session.commit()

    return jsonify({
        'success': True,
        'is_purchased': item.is_purchased
    })


@app.route('/wishlist/<int:id>/delete', methods=['POST'])
@login_required
def delete_wishlist(id):
    wishlist = Wishlist.query.get_or_404(id)

    if wishlist.user_id != current_user.id:
        flash('У вас нет прав для удаления этого вишлиста', 'danger')
        return redirect(url_for('dashboard'))

    db.session.delete(wishlist)
    db.session.commit()
    flash('Вишлист удален', 'success')
    return redirect(url_for('dashboard'))


@app.route('/item/<int:id>/delete', methods=['POST'])
@login_required
def delete_wishlist_item(id):
    item = WishlistItem.query.get_or_404(id)
    wishlist = Wishlist.query.get(item.wishlist_id)

    if wishlist.user_id != current_user.id:
        flash('У вас нет прав для удаления этого предмета', 'danger')
        return redirect(url_for('view_wishlist', id=wishlist.id))

    db.session.delete(item)
    db.session.commit()
    flash('Предмет удален', 'success')
    return redirect(url_for('view_wishlist', id=wishlist.id))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/clear-sessions')
def clear_sessions():
    session.clear()
    flash('Все сессии очищены', 'info')
    return redirect(url_for('index'))


@app.route('/check-session')
def check_session():
    return jsonify({
        'authenticated': current_user.is_authenticated,
        'username': current_user.username if current_user.is_authenticated else None
    })
@app.route('/fix-sessions')
def fix_sessions():
    """Ручка для очистки невалидных сессий"""
    session.clear()
    response = redirect(url_for('index'))
    response.delete_cookie('session')
    response.delete_cookie('remember_token')
    response.delete_cookie('WishLister_session')
    flash('Сессии очищены', 'info')
    return response

with app.app_context():
    db.create_all()
    print("База данных инициализирована")

if __name__ == '__main__':
    app.run(debug=True, port=5003)