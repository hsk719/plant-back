import json
from datetime import datetime, timedelta
from functools import wraps
from psycopg2 import pool
from flask import Flask, request, jsonify, url_for
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash


# TrackerDatabase 클래스 정의
class Database:
    def __init__(self, env):
        with open('./env.json') as env_file:
            env_json = json.load(env_file)
        if env == 'local':
            min_conn = 1
            max_conn = 3
        else:
            min_conn = 1
            max_conn = 20
        self.pool = pool.ThreadedConnectionPool(
            min_conn,
            max_conn,
            user=env_json[env]['user'],
            password=env_json[env]['password'],
            host=env_json[env]['host'],
            database=env_json[env]['dbname']
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
        sql = '''SELECT * FROM "user"'''
        cursor.execute(sql)
        rows = cursor.fetchall()
        result = []
        for row in rows:
            r = {
                "id": row[0],
                "user_name": row[1],
                "email": row[2],
                "password": row[3],
                "is_verified": row[4]  # 이메일 인증 여부 추가
            }
            result.append(r)
        return result

    @query_decorator
    def register_user(self, conn, email, password):
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM "user" WHERE email = %s', (email,))
        if cursor.fetchone():
            return {"error": "Email already exists"}, 400
        
        hashed_password = generate_password_hash(password)  # 비밀번호 해시화
        sql = """INSERT INTO "user" (email, password, is_verified) VALUES (%s, %s, %s)"""
        cursor.execute(sql, (email, password, False))  # 기본값으로 is_verified를 False로 설정
        conn.commit()
        return {"message": "User registered successfully"}, 201

    @query_decorator
    def get_user(self, conn, email):
        cursor = conn.cursor()
        sql = '''SELECT * FROM "user" WHERE email = %s'''
        cursor.execute(sql, (email,))
        rows = cursor.fetchall()
        result = []
        for row in rows:
            r = {
                "id": row[0],
                "user_name": row[1],
                "email": row[2],
                "password": row[3],
                "is_verified": row[4]
            }
            result.append(r)
        return result
    
    
    @query_decorator
    def update_user_verification_status(self, conn, email):
        cursor = conn.cursor() 
        sql = '''UPDATE "user" SET is_verified = TRUE WHERE email = %s'''
        cursor.execute(sql, (email,))
        conn.commit()
        return {"message": "Email verified successfully"}

    



