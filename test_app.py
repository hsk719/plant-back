import pytest
from app import app, db, User  # Flask 애플리케이션과 db 모델을 임포트

@pytest.fixture
def client():
    """테스트 클라이언트 생성"""
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            db.create_all()  # 테이블 생성
            db.session.query(User).delete()  # 기존 사용자 삭제 (중복 방지)
            db.session.commit()
        yield client
        with app.app_context():
            db.session.remove()
            db.drop_all()

def test_home(client):
    """홈 페이지 테스트"""
    response = client.get('/')
    assert response.status_code == 200

def test_add_user(client):
    """사용자 추가 테스트"""
    response = client.get("/add_user")
    assert b"User john_doe added to the database!" in response.data

def test_get_users(client):
    """사용자 조회 테스트"""
    client.get("/add_user")  # 사용자 추가
    response = client.get("/get_users")
    assert b"Username: john_doe" in response.data
    assert b"Email: john@example.com" in response.data


