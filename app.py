from flask import Flask, request, jsonify, url_for
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_jwt_extended import JWTManager, create_access_token
import os
from db import Database  # db.py에서 Database 클래스를 임포트
from dotenv import load_dotenv
from werkzeug.security import check_password_hash

# Flask 애플리케이션 객체 생성
app = Flask(__name__)

# .env 파일을 로드하여 환경 변수 설정
load_dotenv()

# 환경 변수로부터 설정 읽어오기
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default_jwt_secret_key')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Flask-JWT 설정
jwt = JWTManager(app)

# Database 객체 생성
db = Database("local")  # 데이터베이스 객체 생성


@app.before_request
def before_request():
    print("각 요청 전에 실행됩니다.")

# 기본 경로 설정
@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Flask API!"})

# 사용자 추가 라우트(POST 요청)
@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    print(data)
    print(email)
    print(password)
    
    if not email or not password:
        return jsonify({'error': 'Missing email or password'}), 400

    result, status_code = db.register_user(email, password)
    if status_code == 400:
        return jsonify(result), status_code

    # 이메일 인증 링크 보내기
    token = s.dumps(email, salt='email-confirm')
    confirmation_url = url_for('confirm_email', token=token, _external=True)
    msg = Message('Confirm Your Email', recipients=[email],sender=os.getenv('MAIL_USERNAME'))
    msg.body = f'Click the link to confirm your email: {confirmation_url}'
    mail.send(msg)

    return jsonify({"message": "User registered. Please check your email to confirm."}), 201




# 사용자 목록 조회 라우트 (GET 요청)
@app.route('/get_users', methods=['GET'])
def get_users():
    users = db.test()
    return jsonify(users)

# 이메일 인증 라우트
@app.route('/confirm_email/<token>', methods=['GET'])
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)  # 토큰 유효시간 1시간
    except SignatureExpired:
        return jsonify({'message': 'The confirmation link has expired.'}), 400
    except BadSignature:
        return jsonify({'message': 'Invalid confirmation link.'}), 400
    
    result = db.get_user(email)
    if result:
        user = result[0]
        if user['is_verified']:
            return jsonify({'message': 'Email already confirmed.'}), 200
        db.update_user_verification_status(email)  # 이메일 인증 상태 업데이트
        return jsonify({'message': 'Email confirmed!'}), 200
    return jsonify({'message': 'User not found'}), 404

# 로그인 라우트
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Missing email or password'}), 400

    user = db.get_user(email)
    if user and check_password_hash(user[0]['password'], password):  # 해시된 비밀번호와 비교
        if not user[0]['is_verified']:
            return jsonify({'error': 'Please verify your email first.'}), 400

        access_token = create_access_token(identity=email)
        return jsonify(access_token=access_token), 200

    return jsonify({'error': 'Invalid credentials'}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
