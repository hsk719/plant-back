
import logging
logging.basicConfig(level=logging.DEBUG)
from flask import Flask, request, jsonify,send_from_directory
from flask_jwt_extended import JWTManager, create_access_token
import os
import json
from flask_cors import CORS
from db import Database  # db.py에서 Database 클래스를 임포트
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
import requests  #  1365 API 연동을 위한 모듈
import xmltodict #  XML을 JSON처럼 다루게 해줌
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask import jsonify
import urllib.parse
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer
from itsdangerous import SignatureExpired, BadSignature
from flask_jwt_extended import get_jwt_identity
from functools import wraps
from flask_jwt_extended import verify_jwt_in_request

# 환경 설정 파일 불러오기
with open('env.json', 'r') as f:
    env_config = json.load(f)
    
# 현재 환경 설정 (prod 또는 local)
ENV = "prod"
SERVICE_KEY = env_config[ENV]['volunteer_service_key']  # 1365 API 서비스 키


# 로깅 설정
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# Flask 애플리케이션 객체 생성
app = Flask(__name__)
CORS(app, origins="*")  # 모든 도메인에서 접근 가능하게 설정
app.logger.setLevel(logging.DEBUG)

# 임시로 메모리에 인증코드 저장
verification_codes = {}

# 비밀번호 해시화
hashed_password = generate_password_hash("my_secure_password")


# 비밀번호 검증 (입력한 비밀번호와 해시된 비밀번호 비교)
is_valid = check_password_hash(hashed_password, "my_secure_password")
print(is_valid)  # True 출력

# 다른 비밀번호 비교
is_valid = check_password_hash(hashed_password, "wrong_password")
print(is_valid)  # False 출력

# 비밀번호 검증 함수
def verify_password(plain_password, hashed_password):
     return check_password_hash(hashed_password, plain_password)


# 환경 변수로부터 설정 읽어오기
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default_jwt_secret_key')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'gkstjdrb719@gmail.com'
app.config['MAIL_PASSWORD'] = 'ixwj wpus rkip jove'  # 위에서 생성한 앱 비밀번호
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# Flask-JWT 설정
jwt = JWTManager(app)

# DB 인스턴스 (local)
db = Database("prod")  

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

#이메일 인증 환경변수 
def send_email(to_email, subject, html_content):
    msg = MIMEText(html_content, "html")
    msg["Subject"] = subject
    msg["From"] = app.config['MAIL_USERNAME']
    msg["To"] = to_email
    
    try:
        with smtplib.SMTP_SSL(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as smtp:
            smtp.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            smtp.send_message(msg)
        logger.debug(f"메일 전송 성공: {to_email}")
    except Exception as e:
        logger.error(f"메일 전송 실패: {e}")
        
# get_current_user() 구현       
def get_current_user():
    email = get_jwt_identity()
    if not email:
        return None
    admin_list = db.raw_query("SELECT * FROM admins WHERE email = %s", (email,))
    if not admin_list:
        return None
    admin = admin_list[0]
    # admin은 list의 첫 번째 row (튜플 등)일 수 있으니 dict 변환을 원하면 아래 참고
    return {
        "email": admin[1],  # 인덱스 조정 필요 시 수정
        "is_confirmed": admin[3]
    }
# @admin_required 데코레이터 정의   
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request()  # JWT 유효성 검사
            user = get_current_user()
            if not user:
                return jsonify({"msg": "인증된 관리자가 아닙니다."}), 403
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({"msg": "JWT 인증 실패", "error": str(e)}), 401
    return decorated_function

# flask 내부 print/log도 gunicorn 로그에 잘 보임
logging.debug("디버깅 메시지입니다.")
logging.info("정보 메시지입니다.")

@app.before_request
def log_request_data():
    if request.method == 'GET':
        return

    try:
        data = request.get_json()
        masked_data = data.copy() if isinstance(data, dict) else {}

        if 'password' in masked_data:
            masked_data['password'] = '********'

        logging.debug(f"요청 데이터 (마스킹): {masked_data}")
        logging.debug(f"요청 헤더: {request.headers}")

    except Exception as e:
        logging.debug(f"요청 로깅 중 오류 발생: {e}")
     
@app.before_request
def log_request_info():
    logging.debug('Headers: %s', request.headers)
    logging.debug('Body: %s', request.get_data())

# 기본 경로 설정
@app.route('/')
def home():
    return jsonify({"message": "Hello, AWS!"})


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


# 사용자 목록 조회 라우트 (GET 요청)
@app.route('/get_users', methods=['GET'])
def get_users():
    users = db.test()
    return jsonify(users)

# 비밀번호를 마스킹해서 로그에 출력하는 함수
def log_request(data):
    # 비밀번호를 마스킹
    masked_data = data.copy()
    if 'password' in masked_data:
        masked_data['password'] = '********'
        logger.debug(f"요청 데이터: {masked_data}")
        
# 함수 정의: 로그 기록용 data 인자를 받도록 함수 정의 수정
def log_request_data(data=None):
    if data is None:
        data = request.get_json()
    app.logger.debug(f"Body: {data}")

        
# 사용자(user) 로그인 라우트 (POST 요청)
@app.route('/login', methods=['POST'])
def login():
    try:
        # 클라이언트로부터 전달된 JSON 데이터 가져오기
        data = request.get_json()
        log_request_data(data)
        # 로그인 처리 로직.
        email = data.get('email')
        password = data.get('password')
        
        # 이메일과 비밀번호가 모두 필요한지 확인
        if not email or not password:
            return jsonify({'error': '이메일과 비밀번호가 필요합니다.'}), 400
        
        # DB에서 사용자 정보 가져오기
        user = db.get_user(email)  # db.get_user()는 이메일로 사용자 정보를 반환한다고 가정
        
        if not user:
            return jsonify({'error': '사용자를 찾을 수 없습니다.'}), 401
        
        # user가 리스트인지 딕셔너리인지 확인 후 접근 방식 수정
        print(f"user 타입: {type(user)}")  # user가 리스트인지 딕셔너리인지 확인
        
        # user 데이터가 리스트라면 첫 번째 요소 사용
        if isinstance(user, list):
            user = user[0]
            
        logger.debug(f"user 타입: {type(user)}")
        logger.debug("비밀번호 검증 결과: 일치" if check_password_hash(user['password'], password) else "불일치")
        # 절대로 입력된 평문 비밀번호는 출력x

        # 비밀번호 비교: 비밀번호가 일치하지 않으면 오류 반환
        if not check_password_hash(user['password'], password):
            return jsonify({'error': '비밀번호가 일치하지 않습니다.'}), 401
        
        # JWT 토큰 생성
        access_token = create_access_token(identity=email)
        return jsonify({'access_token': access_token}), 200  # JWT 토큰 반환
    
    except Exception as e:
        logger.exception("회원가입 중 예외 발생")
        return jsonify({'error': '로그인 처리 중 오류가 발생했습니다.'}), 500
    

    
# 사용자(user) 등록 (회원가입) 라우트
@app.route('/register', methods=['POST'])
def register():
    try:
        # 요청 데이터 가져오기
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        # 필수 입력값 확인
        if not email or not password:
            return jsonify({'error': '이메일과 비밀번호가 필요합니다.'}), 400

        # 이메일, 비밀번호 길이 제한
        MAX_EMAIL_LENGTH = 255
        MAX_PASSWORD_LENGTH = 120

        if len(email) > MAX_EMAIL_LENGTH:
            return jsonify({"error": f"이메일은 {MAX_EMAIL_LENGTH}자 이하로 입력해주세요."}), 400

        if len(password) > MAX_PASSWORD_LENGTH:
            return jsonify({"error": f"비밀번호는 {MAX_PASSWORD_LENGTH}자 이하로 입력해주세요."}), 400

        # 이미 존재하는 사용자 확인
        existing_user = db.get_user(email)
        if existing_user:
            return jsonify({'error': '이미 등록된 이메일입니다.'}), 409

        # 비밀번호 해싱
        hashed_password = generate_password_hash(password, method='scrypt')
        
        # 확인용 로그
        print(check_password_hash(hashed_password,password)) # True 
        print(check_password_hash(hashed_password, "wrong")) # False

        # DB에 사용자 등록
        result, status_code = db.register_user(email, hashed_password)

        if status_code == 201:
            return jsonify({"message": "회원가입이 완료되었습니다."}), 201
        else:
            return jsonify(result), status_code

    except Exception as e:
        print(f"회원가입 중 오류 발생: {e}")
        return jsonify({'error': '회원가입 처리 중 오류가 발생했습니다.'}), 500
    
# 관리자 회원가입(이메일 인증)
@app.route('/admin/signup', methods=['POST'])
def admin_signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # 이메일 중복 체크
    existing_admin = db.raw_query("SELECT * FROM admins WHERE email = %s", (email,))
    if existing_admin:
        return jsonify({"msg": "이미 가입된 이메일입니다."}), 400
    
    # 이메일 인증용 토큰 생성
    token = serializer.dumps(email, salt='email-confirm')
    # 토큰 로그 찍기 (서버 콘솔에 출력)
    import logging
    logging.debug(f"생성된 토큰: {token}")
    print("생성된 토큰:", token)  # print도 추가 가능
    
    confirm_url = f"{request.host_url}admin/confirm/{token}"
    html = f"<p>아래 링크를 클릭하여 이메일 인증을 완료하세요.</p><a href='{confirm_url}'>이메일 인증하기</a>"
    send_email(email, "관리자 이메일 인증", html)
    
    # 이메일 본문 HTML 로그 찍기
    print("이메일 본문 HTML:", html)
    
    send_email(email, "관리자 이메일 인증", html)
    # 임시로 비밀번호 해시 저장 또는 별도 컬럼에 저장 후 인증 시 업데이트 처리 가능 (여기선 임시 저장)
    hashed_pw = generate_password_hash(password)
    db.execute("INSERT INTO admins (email, password, is_confirmed) VALUES (%s, %s, %s)", (email, hashed_pw, False))

    return jsonify({"msg": "인증 이메일을 발송했습니다.", "token": token}), 200

 # 관리자 이메일 토큰발급                   
@app.route('/admin/confirm/<token>', methods=['GET'])
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return jsonify({"msg": "토큰이 만료되었습니다."}), 400
    except BadSignature:
        return jsonify({"msg": "토큰이 잘못되었습니다."}), 400

    # 인증 완료 처리 (예: is_confirmed 컬럼 True로 업데이트)
    db.execute("UPDATE admins SET is_confirmed = %s WHERE email = %s", (True, email))

    return "이메일 인증이 완료되었습니다. 로그인 해주세요.", 200

#관리자 비밀번호 찾기 api
@app.route('/admin/forgot', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    admin = db.execute("SELECT * FROM admins WHERE email = %s", (email,))
    if not admin:
        return jsonify({"msg": "등록된 이메일이 없습니다."}), 404

    token = serializer.dumps(email, salt='password-recover')
    reset_url = f"{request.host_url}admin/reset/{token}"
    # 토큰 출력 
    app.logger.debug(f"비밀번호 재설정 링크: {reset_url}")
    html = f"<p>비밀번호를 재설정하려면 아래 링크를 클릭하세요.</p><a href='{reset_url}'>비밀번호 재설정</a>"
    send_email(email, "비밀번호 재설정 안내", html)

    return jsonify({"msg": "비밀번호 재설정 이메일을 발송했습니다."}), 200

#관리자 비밀번호 토큰발급 api 
@app.route('/admin/reset/<token>', methods=['POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-recover', max_age=3600)
    except Exception:
        return jsonify({"msg": "토큰이 만료되었거나 잘못되었습니다."}), 400

    data = request.get_json()
    new_password = data.get('password')
    hashed_pw = generate_password_hash(new_password)

    db.execute("UPDATE admins SET password = %s WHERE email = %s", (hashed_pw, email))

    return jsonify({"msg": "비밀번호가 성공적으로 변경되었습니다."}), 200

#관리자 로그인 
@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    admin_list = db.raw_query("SELECT * FROM admins WHERE email = %s", (email,))
    if not admin_list:
        return jsonify({"msg": "이메일이 존재하지 않습니다."}), 404

    admin = admin_list[0]
    hashed_password = admin[2]  # index 맞추세요
    is_confirmed = admin[3]

    if not check_password_hash(hashed_password, password):
        return jsonify({"msg": "비밀번호가 일치하지 않습니다."}), 401

    if not is_confirmed:
        return jsonify({"msg": "이메일 인증이 완료되지 않았습니다."}), 403

    access_token = create_access_token(identity=email)
    return jsonify({"access_token": access_token}), 200


    
    
    # 이메일로 사용자 정보 조회 (DB에서)
def get_user_by_email(email):
    # 예시로, db.get_user(email)을 통해 사용자의 데이터를 가져옵니다.
    user = db.get_user(email)  # db.get_user(email) 가 DB에서 이메일로 사용자 찾기
    if user:
        return user[0]['password']  # DB에서 가져온 첫 번째 사용자 정보
    return None


    
    # 이메일 인증 체크 (원하면 활성화 가능)
    # if not user[0].get('is_verified', True):
    #     return jsonify({'error': '이메일 인증이 필요합니다.'}), 401
  


# 프로필 조회(4/11에 추가함)
@app.route('/user/profile', methods=['GET'])
@jwt_required()
def get_profile():
    user_email = get_jwt_identity()  # JWT로부터 사용자 이메일 추출
    user = db.get_user(user_email)   # DB에서 사용자 정보 조회
    if user:
        return jsonify(user), 200
    else:
        return jsonify({"error": "사용자 정보를 찾을 수 없습니다."}), 404
    
# 비밀번호 수정
@app.route('/user/password', methods=['PUT'])
@jwt_required()
def update_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    user_email = get_jwt_identity()
    user = db.get_user(user_email)

    if not user:
        return jsonify({"error": "사용자를 찾을 수 없습니다."}), 404

    # 기존 비밀번호 확인
    if not check_password_hash(user[0]['password'], current_password):
        return jsonify({"error": "현재 비밀번호가 틀렸습니다."}), 400

    # 새로운 비밀번호 해시화 후 저장
    hashed_password = generate_password_hash(new_password)
    result = db.update_password(user_email, hashed_password)
    
    if result:
        return jsonify({"message": "비밀번호가 수정되었습니다."}), 200
    else:
        return jsonify({"error": "비밀번호 수정에 실패했습니다."}), 500
    
# 회원탈퇴
@app.route('/user/delete', methods=['DELETE'])
@jwt_required()
def delete_account():
    user_email = get_jwt_identity()
    result = db.delete_user(user_email)  # 사용자 계정 및 관련 데이터 삭제

    if result:
        return jsonify({"message": "회원탈퇴가 완료되었습니다."}), 200
    else:
        return jsonify({"error": "회원탈퇴에 실패했습니다."}), 500
    
#5월22일 최신화

# 1. 관리자 인증 신청 api   
@app.route('/verification/request', methods=['POST'])
@jwt_required()
def request_admin_verification_route():
    data = request.get_json()
    user_id = data.get("user_id")
    center_name = data.get("center_name")
    position = data.get("position")

    if not user_id or not center_name or not position:
        return {"error": "모든 필드를 입력해주세요."}, 400

    return db.register_admin_verification(user_id=user_id, center_name=center_name, position=position)

# 2. 관리자 인증 상태 조회 API
@app.route('/verification/status', methods=['GET'])
def check_admin_verification_status():
    user_id = request.args.get("user_id", type=int)

    if not user_id:
        return {"error": "user_id를 query string으로 전달해주세요."}, 400

    return db.get_admin_verification_status(user_id=user_id)

# 3. 관리자 인증 신청 취소 API 
@app.route('/verification/cancel', methods=['POST'])
def cancel_admin_verification_request():
    data = request.get_json()
    user_id = data.get("user_id")

    if not user_id:
        return {"error": "user_id를 요청 바디에 포함시켜야 합니다."}, 400

    return db.cancel_admin_verification(user_id=user_id)

# 4.관리자 인증 승인/반려 처리
@app.route('/admin/verification/<int:request_id>/approve_or_reject', methods=['POST'])
@admin_required
def handle_verification(request_id):
    data = request.get_json()
    action = data.get('action')
    if action not in ['approve', 'reject']:
        return {"msg": "Invalid action"}, 400
    
    # DB 업데이트 예시
    success = db.update_verification_status(request_id=request_id, action=action, reason=data.get('reason'))
    if not success:
        return {"msg": "Request not found or already processed"}, 404
    return {"msg": f"Verification {action}d"}, 200

#봉사 신청자 관리 API

# 5. 신청자 목록 조회
@app.route('/admin/volunteer/<int:post_id>/applicants', methods=['GET'])
@admin_required
def get_applicants(post_id):
    result = db.get_applicants_by_post(post_id)
    return jsonify(result), 200

# 6. 신청 수락 / 반려
@app.route('/admin/volunteer/<int:post_id>/applicant/<int:user_id>/<string:action>', methods=['PUT'])
@admin_required
def handle_application(post_id, user_id, action):
    if action not in ['approve', 'reject']:
        return {"msg": "action은 approve 또는 reject여야 합니다."}, 400
    result = db.update_application_status(post_id, user_id, action)
    return jsonify(result), 200

# 봉사 실적 처리 API
# 7. 수락된 사용자 목록
@app.route('/admin/volunteer/<int:post_id>/approved-users', methods=['GET'])
@admin_required
def get_approved_users(post_id):
    result = db.get_approved_users(post_id)
    return jsonify(result), 200
    
# 8. 실적 등록 승인
@app.route('/admin/volunteer/<int:post_id>/user/<int:user_id>/record', methods=['PUT'])
@admin_required
def approve_record(post_id, user_id):
    result = db.update_volunteer_record(post_id, user_id, 'approved')
    return jsonify(result), 200

# 9. 실적 등록 반려
@app.route('/admin/volunteer/<int:post_id>/user/<int:user_id>/record/reject', methods=['PUT'])
@admin_required
def reject_record(post_id, user_id):
    result = db.update_volunteer_record(post_id, user_id, 'rejected')
    return jsonify(result), 200

# 10. 수요처 실적 현황 목록 조회 (관리자)
@app.route('/admin/stats', methods=['GET'])
@admin_required
def get_stats():
    status = request.args.get('status')          # 예: 'approved', 'pending', 'rejected' 등
    start_date = request.args.get('start_date')  # yyyy-mm-dd 형식
    end_date = request.args.get('end_date')      # yyyy-mm-dd 형식
    center_name = request.args.get('center_name')  # 센터명 검색용

    result = db.get_stats(status=status, start_date=start_date, end_date=end_date, center_name=center_name)
    return jsonify(result), 200
    

    

# 1365 api (검색하여 봉사참여정보목록조회)
@app.route('/volunteer/meals', methods=['GET'])
def get_volunteer_meals():
    # API 요청 파라미터 설정
    
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    keyword = request.args.get('keyword')
    sido = request.args.get('sido', None)  # 시도명 파라미터 추가
    
    # 키워드에서 지역명 추출 시도 (sido 파라미터가 없을 경우)
    region_keywords = ['서울', '서울특별시', '부산', '부산광역시', '대구', '대구광역시', 
                      '인천', '인천광역시', '광주', '광주광역시', '대전', '대전광역시', 
                      '울산', '울산광역시', '세종', '세종특별자치시', '경기', '경기도', 
                      '강원', '강원도', '충북', '충청북도', '충남', '충청남도', 
                      '전북', '전라북도', '전남', '전라남도', '경북', '경상북도', 
                      '경남', '경상남도', '제주', '제주특별자치도',
                      '동두천', '고양', '성남', '수원', '안양', '부천', '안산', '고양시', '성남시', '수원시']
    
    extracted_sido = None
    search_keyword = keyword
    
    if sido is None and keyword:
        for region in region_keywords:
            if region in keyword:
                if region == '서울' or region == '서울특별시':
                    extracted_sido = '서울특별시'
                elif region == '부산' or region == '부산광역시':
                    extracted_sido = '부산광역시'
                elif region == '대구' or region == '대구광역시':
                    extracted_sido = '대구광역시'
                elif region == '인천' or region == '인천광역시':
                    extracted_sido = '인천광역시'
                elif region == '광주' or region == '광주광역시':
                    extracted_sido = '광주광역시'
                elif region == '대전' or region == '대전광역시':
                    extracted_sido = '대전광역시'
                elif region == '울산' or region == '울산광역시':
                    extracted_sido = '울산광역시'
                elif region == '세종' or region == '세종특별자치시':
                    extracted_sido = '세종특별자치시'
                elif region == '경기' or region == '경기도' or region in ['동두천', '고양', '성남', '수원', '안양', '부천', '안산', '고양시', '성남시', '수원시']:
                    extracted_sido = '경기도'
                elif region == '강원' or region == '강원도':
                    extracted_sido = '강원도'
                elif region == '충북' or region == '충청북도':
                    extracted_sido = '충청북도'
                elif region == '충남' or region == '충청남도':
                    extracted_sido = '충청남도'
                elif region == '전북' or region == '전라북도':
                    extracted_sido = '전라북도'
                elif region == '전남' or region == '전라남도':
                    extracted_sido = '전라남도'
                elif region == '경북' or region == '경상북도':
                    extracted_sido = '경상북도'
                elif region == '경남' or region == '경상남도':
                    extracted_sido = '경상남도'
                elif region == '제주' or region == '제주특별자치도':
                    extracted_sido = '제주특별자치도'
                
                # 검색어에서 지역명 제거 (선택사항)
                search_keyword = keyword.replace(region, '').strip()
                break
    
    # sido 파라미터가 제공된 경우 그것을 사용, 아니면 추출된 값 사용, 둘 다 없으면 전체 지역 검색
    final_sido = sido or extracted_sido
    
    # 공식 API 문서에 맞게 파라미터 이름 수정
    params = {
        'ServiceKey': SERVICE_KEY,  # env.json에서 가져온 서비스 키 사용
        'numOfRows': 100,
        'pageNo': 1,
        'progrmSj': search_keyword if extracted_sido else keyword,  # 키워드 검색 파라미터
        'progrmBgnde': start_date,  # 시작일
        'progrmEndde': end_date,  # 종료일
        'srvcClCode': '',  # 봉사분야
    }
    
    # 지역 필터링이 있는 경우에만 추가
    if final_sido:
        params['sidoNm'] = final_sido
    
    print(f"1365 API 요청 파라미터: {params}")
    
    url = 'http://openapi.1365.go.kr/openapi/service/rest/VolunteerPartcptnService/getVltrSearchWordList'
    
    try:
        headers = {
            'Accept': 'application/xml',
            'Content-Type': 'application/xml'
        }
        # API 호출
        response = requests.get(url, params=params, headers=headers)
        
        # 디버깅을 위한 출력
        print("Status Code:", response.status_code)
        print("Response Content 일부:", response.content.decode('utf-8')[:1000])  # 응답 내용 일부만 출력
        
        # 응답 상태 코드 확인
        if response.status_code != 200:
            return jsonify({
                'status': f'API 호출 실패: {response.status_code}',
                'total_count': '0',
                'items': []
            }), 200
            
        # XML 응답을 딕셔너리로 변환
        dict_data = xmltodict.parse(response.content)
        
        # 응답 구조 확인
        if 'response' not in dict_data:
            return jsonify({
                'status': '잘못된 응답 형식',
                'total_count': '0',
                'items': []
            }), 200
            
        # 결과 데이터 추출 및 정제
        result = {
            'status': dict_data['response']['header']['resultMsg'],
            'total_count': dict_data['response']['body']['totalCount'],
            'items': []
        }
        
        # items 데이터가 있는 경우에만 처리
        if dict_data['response']['body'].get('items'):
            items = dict_data['response']['body']['items'].get('item', [])
            # 단일 항목인 경우 리스트로 변환
            if isinstance(items, dict):
                items = [items]
                
            # 디버깅: 각 아이템의 제목과 지역 정보 출력
            print("=== 검색 결과 항목 디버깅 ===")
            for idx, item in enumerate(items[:5]):  # 처음 5개 항목만 출력
                print(f"항목 {idx+1}:")
                print(f"  제목(prgramSj): {item.get('prgramSj', '제목 없음')}")
                print(f"  장소(actPlace): {item.get('actPlace', '장소 정보 없음')}")
                print(f"  기관(nanmmbyNm): {item.get('nanmmbyNm', '기관 정보 없음')}")
                print(f"  시도명(sidoNm): {item.get('sidoNm', '지역 정보 없음')}")
                
                # API 응답에서 모든 키 값 확인 (첫번째 항목만)
                if idx == 0:
                    print("  항목의 모든 키:")
                    for key in item.keys():
                        print(f"    {key}: {item.get(key, '')}")
                        
            # 필드가 누락되었을 때 기본값을 제공하도록 각 항목 처리
            processed_items = []
            for item in items:
                # API 응답에서 필드명이 다를 수 있으므로 대체 필드 확인
                if 'prgramSj' not in item:
                    # 가능한 대체 필드명 확인 (API 문서 참조)
                    if 'progrmSj' in item:
                        item['prgramSj'] = item['progrmSj']
                    elif 'pgmNm' in item:
                        item['prgramSj'] = item['pgmNm']
                    elif 'title' in item:
                        item['prgramSj'] = item['title']
                    else:
                        item['prgramSj'] = '제목 정보 없음'
                
                # 필수 필드에 기본값 제공
                item_with_defaults = {
                    'progrmRegistNo': item.get('progrmRegistNo', ''),
                    'prgramSj': item.get('prgramSj', '제목 정보 없음'),
                    'actBeginDe': item.get('actBeginDe', ''),
                    'actEndDe': item.get('actEndDe', ''),
                    'actPlace': item.get('actPlace', '장소 정보 없음'),
                    'progrmSttusSe': item.get('progrmSttusSe', '상태 미정'),
                    'nanmmbyNm': item.get('nanmmbyNm', '기관 정보 없음'),
                    'sidoNm': item.get('sidoNm', ''),
                    'gugunNm': item.get('gugunNm', ''),
                    'rcritNmpr': item.get('rcritNmpr', '0'),
                    'actWkdy': item.get('actWkdy', ''),
                    'actTime': item.get('actTime', ''),
                    'telno': item.get('telno', ''),
                }
                
                # 연락처 정보 처리: telno가 없으면 다른 가능한 필드 확인
                if not item_with_defaults['telno'] or item_with_defaults['telno'] == '':
                    if 'nanmmbyNmAdmnTelno' in item and item['nanmmbyNmAdmnTelno']:
                        item_with_defaults['telno'] = item['nanmmbyNmAdmnTelno']
                    elif 'admNmtel' in item and item['admNmtel']:
                        item_with_defaults['telno'] = item['admNmtel']
                    elif 'tel' in item and item['tel']:
                        item_with_defaults['telno'] = item['tel']
                        
                # 모집인원 정보 처리: rcritNmpr가 없으면 다른 가능한 필드 확인
                if not item_with_defaults['rcritNmpr'] or item_with_defaults['rcritNmpr'] == '0' or item_with_defaults['rcritNmpr'] == '':
                    if 'recruitNmpr' in item and item['recruitNmpr']:
                        item_with_defaults['rcritNmpr'] = item['recruitNmpr']
                    elif 'recruitNum' in item and item['recruitNum']:
                        item_with_defaults['rcritNmpr'] = item['recruitNum']
                        
                # 활동 요일 및 시간 정보 처리
                if not item_with_defaults['actWkdy'] or item_with_defaults['actWkdy'] == '':
                    if 'actDay' in item and item['actDay']:
                        item_with_defaults['actWkdy'] = item['actDay']
                        
                if not item_with_defaults['actTime'] or item_with_defaults['actTime'] == '':
                    if 'actHour' in item and item['actHour']:
                        item_with_defaults['actTime'] = item['actHour']
                        
                # 원본 항목에서 누락된 필드 추가
                for key, value in item.items():
                    if key not in item_with_defaults:
                        item_with_defaults[key] = value
                
                processed_items.append(item_with_defaults)
                
            # 검색어에 지역명이 있고 응답에서 다른 지역의 결과가 포함된 경우 추가 필터링
            if final_sido:
                filtered_items = []
                for item in processed_items:
                    # sidoNm 필드가 있고 검색한 지역과 일치하는지 확인
                    item_sido = item.get('sidoNm', '')
                    # 지역명이 없거나 검색한 지역과 일치하면 포함
                    if not item_sido or final_sido in item_sido:
                        filtered_items.append(item)
                        
                print(f"지역 필터링 전 결과 수: {len(processed_items)}")
                print(f"지역 필터링 후 결과 수: {len(filtered_items)}")
                result['items'] = filtered_items
            else:
                result['items'] = processed_items
        
        return jsonify(result), 200
    
    except requests.exceptions.RequestException as e:
        print(f"요청 실패: {str(e)}")
        return jsonify({
            'status': f'API 요청 실패: {str(e)}',
            'total_count': '0',
            'items': []
        }), 200
    except xmltodict.expat.ExpatError as e:
        print(f"XML 파싱 실패: {str(e)}")
        return jsonify({
            'status': f'XML 파싱 실패: {str(e)}',
            'total_count': '0',
            'items': []
        }), 200
    except Exception as e:
        print(f"예상치 못한 오류: {str(e)}")
        return jsonify({
            'status': f'예상치 못한 오류: {str(e)}',
            'total_count': '0',
            'items': []
        }), 200

    
#1365 api(기간별 봉사 참여 정보 목록 조회)
@app.route('/volunteer/period', methods=['GET'])
def get_volunteer_period():
    start_date = request.args.get('start_date')  # 예: 20250101
    end_date = request.args.get('end_date')      # 예: 20250131

    params = {
        'ServiceKey': SERVICE_KEY,
        'schprogrmBgnde': start_date,
        'progrmEndde': end_date,
        'numOfRows': 10,
        'pageNo': 1
    }

    url = 'http://openapi.1365.go.kr/openapi/service/rest/VolunteerPartcptnService/getVltrPeriodSrvcList'

    return call_volunteer_api(url, params)
#1365 api(지역별 봉사 참여 정보 목록 조회)
@app.route('/volunteer/area', methods=['GET'])
def get_volunteer_area():
    sido = request.args.get('sido')  # 예: 서울특별시
    gugun = request.args.get('gugun')  # 예: 강남구

    params = {
        'ServiceKey': SERVICE_KEY,
        'schSign1': sido,
        'schSign2': gugun,
        'numOfRows': 10,
        'pageNo': 1
    }

    url = 'http://openapi.1365.go.kr/openapi/service/rest/VolunteerPartcptnService/getVltrAreaList'

    return call_volunteer_api(url, params)

# 1365 api(분야별 봉사 참여 정보 목록 조회)
@app.route('/volunteer/category', methods=['GET'])
def get_volunteer_category():
    category = request.args.get('category')  # 예: 환경정화

    params = {
        'ServiceKey': SERVICE_KEY,
        'schCateGu': category,
        'numOfRows': 10,
        'pageNo': 1
    }

    url = 'http://openapi.1365.go.kr/openapi/service/rest/VolunteerPartcptnService/getVltrCategoryList'

    return call_volunteer_api(url, params)

#1365 api (봉사 참여 정보 상세 조회)
@app.route('/volunteer/detail', methods=['GET'])
def get_volunteer_detail():
    progrmRegistNo = request.args.get('progrmRegistNo')  # 고유 프로그램 ID

    params = {
        'ServiceKey': SERVICE_KEY,
        'progrmRegistNo': progrmRegistNo
    }

    url = 'http://openapi.1365.go.kr/openapi/service/rest/VolunteerPartcptnService/getVltrPartcptnItem'

    return call_volunteer_api(url, params)

def call_volunteer_api(url, params):
    try:
        headers = {
            'Accept': 'application/xml',
            'Content-Type': 'application/xml'
        }
        response = requests.get(url, params=params, headers=headers)

        print("Status Code:", response.status_code)
        print("Response Content:", response.content.decode('utf-8'))

        if response.status_code != 200:
            return jsonify({
                'status': f'API 요청 실패: {response.status_code}',
                'total_count': '0',
                'items': []
            }), 200

        dict_data = xmltodict.parse(response.content)

        if 'response' not in dict_data:
            return jsonify({
                'status': '잘못된 응답 형식',
                'total_count': '0',
                'items': []
            }), 200

        result = {
            'status': dict_data['response']['header']['resultMsg'],
            'total_count': dict_data['response']['body'].get('totalCount', 0),
            'items': []
        }

        if dict_data['response']['body'].get('items'):
            items = dict_data['response']['body']['items'].get('item', [])
            if isinstance(items, dict):
                items = [items]
            result['items'] = items

        return jsonify(result), 200

    except requests.exceptions.RequestException as e:
        return jsonify({
            'status': f'API 요청 실패: {str(e)}',
            'total_count': '0',
            'items': []
        }), 200
    except xmltodict.expat.ExpatError as e:
        return jsonify({
            'status': f'XML 파싱 실패: {str(e)}',
            'total_count': '0',
            'items': []
        }), 200
    except Exception as e:
        return jsonify({
            'status': f'예상치 못한 오류: {str(e)}',
            'total_count': '0',
            'items': []
        }), 200
        
#커스텀 봉사 / 1365와 분리 

# 관리자 전용: 봉사 공고 등록 API
@app.route('/admin/volunteer', methods=['POST'])
def create_volunteer_post():
    data = request.get_json()

    title = data.get('title')
    description = data.get('description')
    location = data.get('location')
    date = data.get('date')  # 'YYYY-MM-DD' 형식

    if not all([title, description, date]):
        return jsonify({'error': '필수 항목 누락'}), 400

    try:
        db.insert_volunteer_post(title, description, location, date)
        return jsonify({'message': '공고 등록 완료'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    
# 관리자 전용 : 모든 봉사 공고 목록 조회 API    
@app.route('/admin/volunteer/list', methods=['GET'])
def get_all_volunteer_posts_admin():
    try:
        posts = db.get_all_volunteer_posts()  # 사용자와 동일하거나 관리자 전용 메서드
        return jsonify({'posts': posts}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 관리자 전용 : 봉사 공고 상세 조회 API
@app.route('/admin/volunteer/<int:post_id>', methods=['GET'])
def get_volunteer_post_detail(post_id):
    try:
        post = db.get_volunteer_post_by_id(post_id)
        if not post:
            return jsonify({'error': '해당 공고를 찾을 수 없습니다.'}), 404
        return jsonify(post), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    
# 관리자 전용 : 봉사 공고 수정 API     
@app.route('/admin/volunteer/<int:post_id>', methods=['PUT'])
def update_volunteer_posts(post_id):
    data = request.get_json()
    try:
        title = data.get('title')
        description = data.get('description')
        location = data.get('location')
        date = data.get('date')

        if not all([title, description, date]):
            return jsonify({'error': '필수 항목 누락'}), 400

        db.update_volunteer_posts(post_id, title, description, location, date)
        return jsonify({'message': '공고 수정 완료'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    
 # 관리자 전용 : 봉사 공고 삭제 API
@app.route('/admin/volunteer/<int:post_id>', methods=['DELETE'])
def delete_volunteer_posts(post_id):
    try:
        db.delete_volunteer_posts(post_id)
        return jsonify({'message': '공고 삭제 완료'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

# 사용자: 봉사 공고 목록 조회 API
@app.route('/volunteer/custom-list', methods=['GET'])
def get_custom_volunteer_posts():
    try:
        posts = db.get_all_volunteer_posts()
        return jsonify(posts), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# 커스텀 봉사 봉사신청(관리자가 등록한 봉사를 신청)  
@app.route('/volunteer/custom-apply', methods=['POST'])
def apply_custom_volunteer():
    try:
        data = request.get_json()
        user_id = data['user_id']
        post_id = data['post_id']

        result = db.insert_custom_volunteer_application(user_id, post_id)
        return jsonify(result[0]), result[1]

    except KeyError:
        return jsonify({'error': 'user_id 또는 post_id가 누락됨'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    
# 게시판 관련 API

# 글 작성 (JWT 로그인 필요)
@app.route('/posts', methods=['POST'])
@jwt_required()
def create_post():
    data = request.get_json() # JSON 데이터 받기
    title = data['title']
    content = data['content']
    author_email = get_jwt_identity()  # JWT로부터 사용자 이메일 추출

    db.insert_post(title, content, author_email)
    return jsonify({"message": "게시글이 등록되었습니다."}), 201

# 글 목록 조회
@app.route('/posts', methods=['GET'])
def get_posts():
    author_email = request.args.get('author_email')
    
    # 특정 사용자의 게시물을 요청하는 경우
    if author_email:
        posts = db.get_user_posts(author_email)
        print(f"사용자 게시물 요청: {author_email}, 결과: {len(posts)}개")
        return jsonify(posts)
    
    # 전체 게시물 목록을 요청하는 경우
    posts = db.get_all_posts()
    return jsonify(posts)

# 특정 사용자가 작성한 게시물 목록 조회 (별도 엔드포인트)
@app.route('/posts/user', methods=['GET'])
def get_user_posts():
    author_email = request.args.get('author_email')
    
    if not author_email:
        return jsonify({"error": "사용자 이메일이 필요합니다."}), 400
    
    posts = db.get_user_posts(author_email)
    print(f"사용자 게시물 요청: {author_email}, 결과: {len(posts)}개")
    return jsonify(posts)

# 글 상세
@app.route('/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    post = db.get_post(post_id)
    comments = db.get_comments(post_id)
    if post:
        return jsonify({
            "post": post,
            "comments": comments
        })
    else:
        return jsonify({"error": "글을 찾을 수 없습니다."}), 404

# 댓글 작성 (JWT 로그인 필요)
@app.route('/posts/<int:post_id>/comment', methods=['POST'])
@jwt_required()
def add_comment(post_id):
    data = request.get_json()
    content = data.get('content')
    author_email = get_jwt_identity()

    if not content:
        return jsonify({"error": "댓글 내용을 입력해주세요."}), 400

    db.insert_comment(post_id, content, author_email)
    return jsonify({"message": "댓글이 등록되었습니다."}), 201

# 글 수정 (JWT 로그인 필요)
@app.route('/posts/<int:post_id>', methods=['PUT'])
@jwt_required()
def update_post(post_id):
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    
    # 글 수정
    result = db.update_post(post_id, title, content)
    if result:
        return jsonify({"message": "게시글이 수정되었습니다."}), 200
    else:
        return jsonify({"error": "게시글 수정에 실패했습니다."}), 400

# 글 삭제 (JWT 로그인 필요) -> 오류 뜸 
@app.route('/posts/<int:post_id>', methods=['DELETE'])
@jwt_required()
def delete_post(post_id):
    print(f"POST request body: {request.get_data()}")
    result = db.delete_post(post_id)
    if result:
        return jsonify({"message": "게시글이 삭제되었습니다."}), 200
    else:
        return jsonify({"error": "게시글 삭제에 실패했습니다."}), 400
    
    
# 댓글 수정 (JWT 로그인 필요) -> 오류뜸 
@app.route('/posts/<int:post_id>/comment/<int:comment_id>', methods=['PUT'])
@jwt_required()
def update_comment(post_id, comment_id):
    data = request.get_json()
    content = data.get('content')

    if not content:
        return jsonify({"error": "댓글 내용을 입력해주세요."}), 400

    # 댓글 수정
    result = db.update_comment(comment_id, content)
    if result:
        return jsonify({"message": "댓글이 수정되었습니다."}), 200
    else:
        return jsonify({"error": "댓글 수정에 실패했습니다."}), 400
    
# 댓글 삭제 (JWT 로그인 필요) -> 오류뜸 
@app.route('/posts/<int:post_id>/comment/<int:comment_id>', methods=['DELETE'])
@jwt_required()
def delete_comment(post_id, comment_id):
    result = db.delete_comment(comment_id)
    if result:
        return jsonify({"message": "댓글이 삭제되었습니다."}), 200
    else:
        return jsonify({"error": "댓글 삭제에 실패했습니다."}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
print("내용", flush=True)
    


