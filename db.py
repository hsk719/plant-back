
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
                # 예외 발생 시에도 호출부에 적절한 튜플을 반환해야 함
                return {"error": f"DB 처리 중 오류: {str(e)}"}, 500  #  반환문 추가
            
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
            return {"error": "Email already exists"}, 400  #  이걸로 충분

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
        
        stored_password_hash = user[3]  
        
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
    def insert_volunteer_info(self, conn, progrmRegistNo, progrmSj, actBeginDe, actEndDe, actPlace):
        cursor = conn.cursor()
        
        # 이미 해당 프로그램 등록 번호가 DB에 있는지 확인
        cursor.execute("SELECT * FROM volunteer_info WHERE progrmRegistNo = %s", (progrmRegistNo,))
        if cursor.fetchone():
            return {"error": "이미 존재하는 봉사활동입니다."}, 400

        # 봉사활동 정보 DB에 삽입
        sql = """
        INSERT INTO volunteer_info (progrmRegistNo, progrmSj, actBeginDe, actEndDe, actPlace)
        VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(sql, (progrmRegistNo, progrmSj, actBeginDe, actEndDe, actPlace))
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
            "progrmSj": row[2],
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
    
    # 관리자 관련 DB 함수 모음 
    @query_decorator
    def get_admin(self, conn, email):
        """이메일로 app_admin 테이블에서 관리자 1명을 조회"""
        try:
            cursor = conn.cursor()
            sql = "SELECT * FROM app_admin WHERE email = %s;"
            cursor.execute(sql, (email,))
            row = cursor.fetchone()

            if not row:
                # 해당 이메일의 관리자가 없으면 에러 반환
                return {"error": "관리자를 찾을 수 없습니다."}, 404
            
            # 튜플(row)을 딕셔너리로 변환
            admin = {
            "email": row[0],
            "username": row[1],
            "password": row[2]
            }
            return admin, 200

        except Exception as e:
            # 조회 중 예외 발생 시 에러 반환
            return {"error": f"관리자 조회 오류: {str(e)}"}, 500
        
    #관리자 회원가입 함수
    @query_decorator
    def register_admin(self, conn, email, username, hashed_password):
        """app_admin 테이블에 새로운 관리자 추가. 이메일 중복 시 409"""
        try:
            cursor = conn.cursor()
            # 이메일 중복 검사
            cursor.execute("SELECT * FROM app_admin WHERE email = %s", (email,))
            existing_admin = cursor.fetchone()
        
            if existing_admin:
                # 중복된 이메일이 있으면 등록 실패 반환
                print(f"이메일 {email} 이미 존재: {existing_admin}")  #  디버깅 로그
                return {"error": "이미 존재하는 이메일입니다."}, 409

            # 중복 없으면 관리자 정보 DB에 삽입
            sql = """
            INSERT INTO app_admin (email, username, password)
            VALUES (%s, %s, %s);
            """
            cursor.execute(sql, (email, username, hashed_password))
            conn.commit()
            return {"message": "관리자 등록 완료"}, 201

        except Exception as e:
            return {"error": f"관리자 등록 오류: {str(e)}"}, 500

    #관리자 비밀번호 함수
    @query_decorator
    def check_admin_password(self, conn, email, entered_password):
        """이메일과 비밀번호 확인 후 로그인"""
        try:
            cursor = conn.cursor()
            sql = "SELECT * FROM app_admin WHERE email = %s;"
            cursor.execute(sql, (email,))
            row = cursor.fetchone()

            if not row:
                # 관리자 존재하지 않으면 404 반환
                return {"error": "관리자를 찾을 수 없습니다."}, 404

            stored_password_hash = row[1]
            # 입력 비밀번호와 DB 해시값 비교
            if not check_password_hash(stored_password_hash, entered_password):
                return {"error": "비밀번호가 일치하지 않습니다."}, 401
             # 비밀번호 일치 시 성공 반환
            return {"message": "로그인 성공"}, 200

        except Exception as e:
            # 로그인 확인 중 예외 발생 시 에러 반환
            return {"error": f"비밀번호 확인 오류: {str(e)}"}, 500   
        
# 1365 데이터에서 봉사 신청 정보 저장 
    @query_decorator
    def insert_volunteer_application(self, conn, user_id, progrm_regist_no):
        cursor = conn.cursor()

    # 이미 신청한 봉사활동인지 확인
        cursor.execute("""
        SELECT * FROM volunteer_1365_applications
        WHERE user_id = %s AND progrm_regist_no = %s
    """, (user_id, progrm_regist_no))
        if cursor.fetchone():
            return {"error": "이미 신청한 봉사활동입니다."}, 400

    # 봉사 신청 정보 저장
        cursor.execute("""
        INSERT INTO volunteer_1365_applications (user_id, progrm_regist_no,applied_at, status)
        VALUES (%s, %s, NOW(), '신청완료')
    """, (user_id, progrm_regist_no))
        conn.commit()

        return {"message": "봉사 신청이 완료되었습니다."}, 201
    
    # 웹 관리자의 봉사 등록 함수
    @query_decorator
    def insert_volunteer_post(self, conn, title, description, location, date):
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO volunteer_posts (title, description, location, date)
        VALUES (%s, %s, %s, %s)
    """, (title, description, location, date))
        conn.commit()
        cursor.close()
        return {"message": "봉사 공고가 등록되었습니다."}, 201
    
    # 사용자의 웹에 대한 봉사 조회 함수 
    @query_decorator
    def get_all_volunteer_posts(self, conn):
        cursor = conn.cursor()
        cursor.execute("""
        SELECT id, title, description, location, date, created_at
        FROM volunteer_posts
        ORDER BY date ASC
        """)
        rows = cursor.fetchall()
        cursor.close()
        columns = [desc[0] for desc in cursor.description]
        result = [dict(zip(columns, row)) for row in rows]
        return result
    
    # 커스텀 봉사 신청용 함수 
    @query_decorator
    def insert_custom_volunteer_application(self, conn, user_id, post_id):
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO custom_volunteer_applications (user_id, post_id)
        VALUES (%s, %s)
        """, (user_id, post_id))
        conn.commit()
        cursor.close()
        return {"message": "봉사 신청이 완료되었습니다."}, 201
    
    



