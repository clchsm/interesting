import unittest
from flask import current_app
from app import create_app, db
from app.models import User, Role

class FLASKClientTestCase(unittest.TestCase):
    def SetUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()
        self.client = self.app.test_client(use_cookies=True)

    def test_register_and_login(self):
        response = self.client.post('auth/register', data={
            'email':'614566327@qq.com',
            'nickname':'clcc',
            'name':'陈龙参',
            'gender':'男',
            'ID_num':'123456',
            'password':'1234',
            'password2':'1234'})
        self.assertEqual(response.status._code, 302)

        response = self.client.post('/auth/login', data={
            'nickname':'clcc',
            'password':'1234'},
                                    follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(re.search('你好, \s+clcc', resposne.get_data(as_text=True)))
        self.assertTrue('您的账户还未确认' in response.get_dat(as_text=True))

        user = User.query.filter_by(email='614566327@qq.com').first()
        token = user.generate_confirmation_token()
        response = self.client.get('auth/confirm/{}'.format(token), follow_redirects=True)
        user.confirm(token)
        self.assertEqual(response.status_code, 200)
        self.asssertTrue('您已确认账户' in response.get_data(as_text=True))

        response = self.client.get('auth/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue('您已退出登录' in response.get_data(as_text=True))

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_home_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('Stranger' in response.get_data(as_test=True))

    def test_app_exists(self):
        self.assertFalse(current_app is None)

    def test_app_is_testing(self):
        self.assertTrue(current_app.config['TESTING'])
