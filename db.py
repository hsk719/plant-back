import json
from psycopg2 import pool
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import os
# Database 클래스 정의
class Database:
    def __init__(self, env):
        # env.json 파일 읽기
        with open('./env.json') as env_file:
            env_json = json.load(env_file)
            
            config = env_json[env]
            
        if env == 'local':
            host = config['host']
        elif env == 'cloud':
            connection_name = config.get("connection_name")
            if not connection_name:
                raise ValueError("Cloud SQL connection_name이 env.json에 없음")
            host = f"/cloudsql/{connection_name}"
        else:
                raise ValueError("❌ 환경(env)은 'local' 또는 'cloud'여야 합니다.")
            
        print("✅ DB HOST:", host)  # 디버깅용 출력
        self.pool = pool.ThreadedConnectionPool(
            1,
            10,
            user=config['user'],
            password=config['password'],
            host=host,
            database=config['dbname']
        )

    def _strftime(self, dt):
        if dt is not None:
            return dt.strftime('%Y-%m-%d')
        else:
            return None

    def query_decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            conn = None
            try:
                conn = self.pool.getconn()
                if not conn:
                    print("[{}] Can't get db connection".format(datetime.now()))
                    return
                return func(self, conn, *args, **kwargs)
            except Exception as e:
                print('[{}] {}'.format(datetime.now(), e))
            finally:
                if conn:
                    self.pool.putconn(conn)

        return wrapper

    @query_decorator
    def test(self, conn):
        cursor = conn.cursor()
        sql = '''SELECT * FROM "app_user"'''
        cursor.execute(sql)
        rows = cursor.fetchall()
        result = []
        for row in rows:
            r = {
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "password": row[3],
                "is_verified": row[4]  # 이메일 인증 여부 추가
            }
            result.append(r)
        return result

    @query_decorator
    def register_user(self, conn, email, hashed_password):
        
            
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM "app_user" WHERE email = %s', (email,))
        if cursor.fetchone():
            return {"error": "Email already exists"}, 400
        
        try:
            if self.check_email_exists(email):
             return {'error': '이미 등록된 이메일입니다.'}, 409

            
            # 비밀번호를 해시화된 값으로 삽입
            sql = """INSERT INTO "app_user" (email, hashed_password, is_verified) VALUES (%s, %s, %s)"""  # is_verified 추가
            cursor.execute(sql, (email, hashed_password, True))  # is_verified True로 설정 (즉시 인증된 상태)
            conn.commit()
            
            return {"message": "User registered successfully"}, 201
        except Exception as e:
            print(f"Error occurred: {e}")
            return {"error": "Internal server error"}, 500
        
    @query_decorator
    def check_user_password(self, conn, email, entered_password):
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM "app_user" WHERE email = %s', (email,))
        user = cursor.fetchone()
        
        if not user:
            return {"error": "User not found"}, 404
        
        stored_password_hash = user[3]  # assuming the password is at index 2
        
        # 비밀번호 확인 추가된 부분
        if check_password_hash(stored_password_hash, entered_password):  # 비밀번호 확인
            # 비밀번호가 맞으면 로그인 성공
            return {"message": "Login successful"}, 200
        else:
            # 비밀번호가 틀리면 로그인 실패
            return {"error": "Invalid credentials"}, 401
    
    @query_decorator
    def get_user(self, conn, email):
        cursor = conn.cursor()
        sql = '''SELECT * FROM "app_user" WHERE email = %s'''
        cursor.execute(sql, (email,))
        rows = cursor.fetchall()
        result = []
        for row in rows:
            r = {
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "password": row[3],
                "is_verified": row[4]  # 이메일 인증 여부 추가
            }
            result.append(r)
        return result
    
    @query_decorator
    def insert_volunteer_info(self, conn, progrmRegistNo, prgramSj, actBeginDe, actEndDe, actPlace):
        cursor = conn.cursor()
        
        # 이미 해당 프로그램 등록 번호가 DB에 있는지 확인
        cursor.execute("SELECT * FROM volunteer_info WHERE progrmRegistNo = %s", (progrmRegistNo,))
        if cursor.fetchone():
            return {"error": "이미 존재하는 봉사활동입니다."}, 400

        # 봉사활동 정보 DB에 삽입
        sql = """
        INSERT INTO volunteer_info (progrmRegistNo, prgramSj, actBeginDe, actEndDe, actPlace)
        VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(sql, (progrmRegistNo, prgramSj, actBeginDe, actEndDe, actPlace))
        conn.commit()

        return {"message": "봉사활동 정보가 성공적으로 저장되었습니다."}, 201
    
    @query_decorator
    def get_volunteer_info(self, conn, progrmRegistNo):
        cursor = conn.cursor()
        sql = "SELECT * FROM volunteer_info WHERE progrmRegistNo = %s"
        cursor.execute(sql, (progrmRegistNo,))
        row = cursor.fetchone()

        if not row:
            return None

        return {
            "progrmRegistNo": row[1],
            "prgramSj": row[2],
            "actBeginDe": row[3],
            "actEndDe": row[4],
            "actPlace": row[5]
        }
    # 게시판 db 함수들
    
    # 게시글 저장
    @query_decorator
    def insert_post(self, conn, title, content, author_email):
        cursor = conn.cursor()
        sql = '''INSERT INTO board_post (title, content, author_email) VALUES (%s, %s, %s)'''
        cursor.execute(sql, (title, content, author_email))
        conn.commit()

    # 게시글 목록 조회
    @query_decorator
    def get_all_posts(self, conn):
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM board_post ORDER BY created_at DESC')
        rows = cursor.fetchall()
        result = []
        for row in rows:
            result.append({
            "id": row[0],
            "title": row[1],
            "content": row[2],
            "author_email": row[3],
            "created_at": row[4].strftime('%Y-%m-%d %H:%M')
            })
        return result

    # 게시글 상세 조회
    @query_decorator
    def get_post(self, conn, post_id):
     cursor = conn.cursor()
     cursor.execute('SELECT * FROM board_post WHERE id = %s', (post_id,))
     row = cursor.fetchone()
     if row:
        return {
            "id": row[0],
            "title": row[1],
            "content": row[2],
            "author_email": row[3],
            "created_at": row[4].strftime('%Y-%m-%d %H:%M')
        }
        return None

    # 댓글 저장
    @query_decorator
    def insert_comment(self, conn, post_id, content, author_email):
        cursor = conn.cursor()
        sql = '''INSERT INTO board_comment (post_id, content, author_email) VALUES (%s, %s, %s)'''
        cursor.execute(sql, (post_id, content, author_email))
        conn.commit()

    # 댓글 조회
    @query_decorator
    def get_comments(self, conn, post_id):
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM board_comment WHERE post_id = %s ORDER BY created_at', (post_id,))
        rows = cursor.fetchall()
        return [{
        "id": row[0],
        "post_id": row[1],
        "content": row[2],
        "author_email": row[3],
        "created_at": row[4].strftime('%Y-%m-%d %H:%M')
    } for row in rows]

    
    



