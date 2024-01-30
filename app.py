# app.py
import pytz as pytz
from flask import Flask, request, jsonify, render_template
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


@app.route('/', methods=['GET'])
def index():
    users = User.query.all()
    login_attempts = LoginAttempt.query.all()
    return render_template('index.html', users=users, login_attempts=login_attempts)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    phone_number = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(pytz.timezone('Asia/Kolkata')))
    login_attempts = db.relationship('LoginAttempt', backref='user', lazy=True)


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now(pytz.timezone('Asia/Kolkata')))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    attempts = db.Column(db.Integer, default=0)


# Other routes...


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
            if login_atm.attempts >=3:
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


# Implement other routes...

if __name__ == '__main__':
    app.run(debug=True)
