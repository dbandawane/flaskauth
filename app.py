# app.py
import random
import string
from functools import wraps

import pytz as pytz
from flask import Flask, request, jsonify, render_template, g
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime, timedelta
from flask_migrate import Migrate
from sqlalchemy import func

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flaskauth.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'your_secret_key'

migrate = Migrate(app, db)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    phone_number = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(pytz.timezone('Asia/Kolkata')))
    login_attempts = db.relationship('LoginAttempt', backref='user', lazy=True)
    verification_code = db.Column(db.String(6))


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now(pytz.timezone('Asia/Kolkata')))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    attempts = db.Column(db.Integer, default=0)


@app.route('/', methods=['GET'])
def index():
    users = User.query.all()
    login_attempts = LoginAttempt.query.all()
    return render_template('index.html', users=users, login_attempts=login_attempts)


# routes...


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Please provide the required fields', 'st': '201'})
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'Email not found', 'st': '201'})

    if not bcrypt.check_password_hash(user.password, password):
        login_atm = get_login_attempt(user)
        if login_atm:
            login_atm.attempts += 1
            db.session.commit()
            if login_atm.attempts >= 3:
                return jsonify({'message': 'Too many unsuccessful login attempts', 'st': '201'})
        print(login_atm, 'ddddddd')
        return jsonify({'message': 'Incorrect password', 'st': '201'})

    # Implement 3 unsuccessful login attempt logic here...

    # Generate JWT token
    token = jwt.encode({'user_id': user.id, 'exp': datetime.now() + timedelta(minutes=30)},
                       app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': str(token)})


@app.route('/signup', methods=['POST'])
def signup():
    from utils import is_valid_email
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Please provide the required fields'})
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    phone_number = data.get('phone_number')

    # Check for digits and length in phone_number
    if not phone_number.isdigit() or len(phone_number) != 10:
        return jsonify({'message': 'Invalid phone number', 'st': '201'})

    # Check for digits in name
    if any(char.isdigit() for char in name):
        return jsonify({'message': 'Invalid name', 'st': '201'})

    if not is_valid_email(email):
        return jsonify({'message': 'Invalid email', 'st': '201'})

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'User already exists', 'st': '201'})

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(name=name, email=email, password=hashed_password, phone_number=phone_number)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'st': '201'})


@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'message': 'Please provide email', 'st': '201'})

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'Email not found', 'st': '201'})

    # Generate a verification code
    verification_code = ''.join(random.choices(string.digits, k=6))
    user.verification_code = verification_code
    db.session.commit()

    # verification code via email
    # send_verification_email(user.email, verification_code)

    return jsonify({'message': 'Verification code sent successfully', 'st': '200'})


# Change Password route
@app.route('/change_password', methods=['POST'])
def change_password():
    data = request.get_json()
    verification_code = data.get('verification_code')
    new_password = data.get('new_password')
    email = data.get('email')

    if not verification_code and new_password:
        return jsonify({'message': 'Please provide required fields', 'st': '201'})

    user = User.query.filter_by(email=email, verification_code=verification_code).first()

    if not user:
        return jsonify({'message': 'Invalid verification code', 'st': '201'})

    # Hash the received new password
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password
    user.verification_code = None  # Clear the verification code after changing the password
    db.session.commit()

    return jsonify({'message': 'Password changed successfully', 'st': '200'})


# Function to send a verification code via email
def send_verification_email(to_email, verification_code):
    subject = 'Forgot Password - Verification Code'
    body = f'Your verification code is: {verification_code}'

    message = Message(subject, recipients=[to_email], body=body)
    mail.send(message)
    return ''


def login_required(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        # Extract JWT token from the request headers
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Authorization token missing', 'st': '201'}), 401

        try:
            # Decode the token to check its validity
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.user_id = decoded_token.get('user_id')  # Store user_id in Flask's global context (g)
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired', 'st': '201'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token', 'st': '201'}), 401

        return view_func(*args, **kwargs)

    return decorated_function


@app.route('/user_details', methods=['GET'])
@login_required
def user_details():
    # Access user_id from Flask's global context (g)
    user_id = g.user_id

    # Retrieve additional data based on user_id
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify({'message': 'User not found', 'st': '404'}), 404

    user_details = {
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'phone_number': user.phone_number,
        'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }

    return jsonify({'user_details': user_details, 'st': '200'})


def get_login_attempt(user):
    today_start = datetime.now()
    login_attempt = LoginAttempt.query.filter(
        LoginAttempt.user_id == user.id,
        func.date(LoginAttempt.timestamp) == today_start.date()
    ).first()

    if not login_attempt:
        login_attempt = LoginAttempt(user_id=user.id)
        db.session.add(login_attempt)
        db.session.commit()

    return login_attempt


if __name__ == '__main__':
    app.run(debug=True)
