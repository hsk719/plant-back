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

             # 선택한 환경에 맞는 config 설정
            config = env_json[env]
            
        if not config:
            raise ValueError(f"❌ 환경(env) '{env}'는 유효하지 않습니다.")
        
        # 공통 키로 접근
        host = config['host']
        port = config.get('port', 5432)
        user = config['user']
        password = config['password']
        dbname = config['dbname']
        
        print(f"✅ DB 연결: {host}")  # 디버깅용 출력
           

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
            return {"error": "Email already exists"}, 400  # ✅ 이걸로 충분

        try:
        # 비밀번호를 해시화된 값으로 삽입
            sql = """INSERT INTO "app_user" (email, password, is_verified) VALUES (%s, %s, %s)"""
            cursor.execute(sql, (email, hashed_password, True))
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
        
    # 게시글 수정
    @query_decorator
    def update_post(self, conn, post_id, title, content):
        cursor = conn.cursor()
        
        # SQL 쿼리 작성 (게시글 수정)
        sql = """
        UPDATE board_post
        SET title = %s, content = %s
        WHERE id = %s
        RETURNING id;
        """
        
        # 쿼리 실행
        cursor.execute(sql, (title, content, post_id))
        
        # 수정된 게시글 ID 가져오기
        result = cursor.fetchone()
        
        # 커밋 후 연결 종료
        conn.commit()
        cursor.close()

        # 수정된 게시글이 있으면 수정 성공
        if result:
            return True
        else:
            return False
        
    # 게시글 삭제
    @query_decorator
    def delete_post(self, conn, post_id):
        cursor = conn.cursor()

        # 글이 존재하는지 확인
        cursor.execute('SELECT * FROM board_post WHERE id = %s', (post_id,))
        if not cursor.fetchone():
            return False  # 삭제 실패 (글이 없음)

        # 글 삭제
        cursor.execute('DELETE FROM board_post WHERE id = %s', (post_id,))
        conn.commit()
        return True  # 삭제 성공
    
    @query_decorator
    def update_comment(self, conn, comment_id, content):
        cursor = conn.cursor()

    # 댓글이 존재하는지 확인
        cursor.execute('SELECT * FROM board_comment WHERE id = %s', (comment_id,))
        comment = cursor.fetchone()

        if not comment:
            return False  # 댓글이 없으면 수정 실패

        # 댓글 수정
        cursor.execute('UPDATE board_comment SET content = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s',
                   (content, comment_id))
        conn.commit()

        return True  # 수정 성공
    
    #댓글 삭제 함수 
    @query_decorator
    def delete_comment(self, conn, post_id, comment_id, author_email):
        cursor = conn.cursor()

        # 댓글이 존재하고 본인이 작성한 것인지 확인
        cursor.execute('''
            SELECT * FROM board_comment 
            WHERE id = %s AND post_id = %s AND author_email = %s
        ''', (comment_id, post_id, author_email))
        comment = cursor.fetchone()

        if not comment:
            return False  # 댓글이 없거나 작성자가 아님

        # 댓글 삭제
        cursor.execute('DELETE FROM board_comment WHERE id = %s', (comment_id,))
        conn.commit()
        return True
    
    



