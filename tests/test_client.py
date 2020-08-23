import unittest
import re
from app import create_app, db
from app.models import User, Role


class FlaskClientTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()
        # app.test_client 是Flask测试客户端对象
        self.client = self.app.test_client(use_cookies=True)

    def tearDown(self) -> None:
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_home_page(self):
        # 用get 方法发起请求 参数为请求地址
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        # response.get_data() 获得响应主体
        self.assertTrue('Stranger' in response.get_data(as_text=True))

    def test_register_and_login(self):
        # 注册新账户
        response = self.client.post('/auth/register',
                                    data={
                                        'email': 'coco@example.com',
                                        'username': 'coco',
                                        'password': 'cat',
                                        'password2': 'cat'
                                    })
        self.assertTrue(response.status_code, 302)

        # 使用新注册的账户登录
        response = self.client.post('/auth/login',
                                    data={
                                        'email': 'coco@example.com',
                                        'password': 'cat',
                                    }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(re.search('Hello,\s+coco!', response.get_data(as_text=True)))
        self.assertTrue('You have not confirmed your account yet' in response.get_data(as_text=True))

        # 发送令牌
        user = User.query.filter_by(email='coco@example.com').first()
        token = user.generate_confirmation_token()
        response = self.client.get('/auth/confirm/{}'.format(token), follow_redirects=True)
        user.confirm(token)
        self.assertEqual(response.status_code, 200)
        self.assertTrue('You have confirmed your account' in response.get_data(as_text=True))

        # 退出
        response = self.client.get('/auth/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue('You have been logged out' in response.get_data(as_text=True))
