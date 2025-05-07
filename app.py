import logging
logging.basicConfig(level=logging.DEBUG)
from flask import Flask, request, jsonify,send_from_directory
from flask_jwt_extended import JWTManager, create_access_token
import os
from flask_cors import CORS
from db import Database  # db.py에서 Database 클래스를 임포트
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
import requests  #  1365 API 연동을 위한 모듈
import xmltodict #  XML을 JSON처럼 다루게 해줌
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask import jsonify
import urllib.parse




logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# Flask 애플리케이션 객체 생성
app = Flask(__name__)
CORS(app, origins="*")  # 모든 도메인에서 접근 가능하게 설정


app.logger.setLevel(logging.DEBUG)

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

# Flask-JWT 설정
jwt = JWTManager(app)

# DB 인스턴스 (local)
db = Database("prod")  

# flask 내부 print/log도 gunicorn 로그에 잘 보임
logging.debug("디버깅 메시지입니다.")
logging.info("정보 메시지입니다.")

@app.before_request
def log_request_data():
    if request.method == 'GET':
        return None
    data = request.get_json()
    print(f"Request data (from get_json): {data}")
    print(f"Request data (raw): {request.data}")
     # 비밀번호를 포함하여 전체 요청 데이터를 출력
     
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


# 사용자 등록 라우트 (POST 요청)
@app.route('/login', methods=['POST'])
def login():
    try:
        # 요청 데이터 받기
        data = request.get_json()
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
            
        print(f"DB에 저장된 해시: {user['password']}")
        print(f"입력된 비밀번호: {password}")
        print(f"비교 결과: {check_password_hash(user['password'], password)}")

        # 비밀번호 비교: 비밀번호가 일치하지 않으면 오류 반환
        if not check_password_hash(user['password'], password):
            return jsonify({'error': '비밀번호가 일치하지 않습니다.'}), 401
        
        # JWT 토큰 생성
        access_token = create_access_token(identity=email)
        return jsonify({'access_token': access_token}), 200  # JWT 토큰 반환
    
    except Exception as e:
        print(f"Error during login: {e}")
        return jsonify({'error': '로그인 처리 중 오류가 발생했습니다.'}), 500
    

    
    
# 사용자 등록 (회원가입) 라우트
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


@app.route('/volunteer/meals', methods=['GET'])
def get_volunteer_meals():
    # API 요청 파라미터 설정
    
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    keyword = request.args.get('keyword')
    
    params = {
        'ServiceKey': '여기에_실제_서비스키_입력',  # 필수! 공공데이터 포털에서 발급받은 서비스 키
        'SchCateGu': 'prormSj',
        'keyword': keyword,
        'schSign1': '3000000',
        'schprogrmBgnde': start_date,
        'progrmEndde': end_date
    }
    
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
        print("Response Content:", response.content.decode('utf-8'))
        
        # 응답 상태 코드 확인
        if response.status_code != 200:
            return jsonify({
                'error': f'API 요청 실패: {response.status_code}',
                'content': response.content.decode('utf-8')
            }), response.status_code
            
        # XML 응답을 딕셔너리로 변환
        dict_data = xmltodict.parse(response.content)
        
        # 응답 구조 확인
        if 'response' not in dict_data:
            return jsonify({
                'error': 'Invalid response format',
                'content': dict_data
            }), 500
            
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
            result['items'] = items
        
        return jsonify(result, 200, {'Content-Type':'application/json'})
    
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Request failed: {str(e)}'}), 500
    except xmltodict.expat.ExpatError as e:
        return jsonify({'error': f'XML parsing failed: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500


    
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
    posts = db.get_all_posts()
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
    


