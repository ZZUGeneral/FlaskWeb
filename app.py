# -*- coding: utf-8 -*-
# @Time : 2020/9/4 11:25
# @Author : YHL <yanghelong@inspur.com>
# @File : app.py
# explain : description

# 导入Flask扩展
from flask import Flask, render_template, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo

from config import mysqlConifg
# 创建Flask应用程序实例
# __name__ ：为了确定资源所在路径
from stu_cou import *

app = Flask(__name__)
app.register_blueprint(stu_cou_blu, url_prefix='/stu_cou')


# 定义路由和视图函数
# Flask中定义路由是通过装饰器实现的
# 路由默认只支持GET，如果需要增加，需要自行制定
@app.route('/', methods=['GET', 'POST'])
def index():
	# return 'Hello Flask!'
	return render_template('index.html')


# <name> ： 定义路由的参数，name表示参数名称，默认类型为字符串，可以添加int,float限定传入类型
@app.route('/order/<int:order_id>')
def get_order_id(order_id):
	# 需要在视图函数的参数中填入传入参数名
	print(type(order_id))

	return 'order_id is {}'.format(order_id)


# 如何返回一个网页模板
@app.route('/template')
def template():
	url_string = 'www.baidu.com'
	# 键值对传输数据，key=value
	my_list = {1, 2, 3, 4, 5}

	my_dict = {
		'name': '百度',
		'url': 'www.baidu.com'
	}

	return render_template('template.html', url_string=url_string, my_list=my_list, my_dict=my_dict)


'''
 实现简单的登录处理
 1. 路由需要有get和post两种请求方式 --->判断请求方式
 2. 获取请求的参数
 3. 判断参数是否填写 & 密码是否相同
 4. 如果判断都没有问题，返回登录成功
 flash 需要对内容加密，所以需要设置secret_key
'''
app.secret_key = 'yhl'


@app.route("/login", methods=['GET', 'POST'])
def login_deal():
	# request ：请求对象 --获取请求方式，数据
	# 1. 获取请求方式
	if request.method == 'POST':
		# 2. 获取请求数据
		username = request.form.get('username')
		password = request.form.get('password')
		password2 = request.form.get('password2')
		# print(username)
		# 3。 判断参数是否完整
		if not all([username, password, password2]):
			flash('参数不完整')
		# 4. 判断密码是否相同
		elif password == password2:
			return '登录成功'
		else:
			flash('密码不一致')

	return render_template('login.html')


'''
使用WTF实现表单
'''


# 自定义表单类
class login_form(FlaskForm):
	username = StringField('用户名', validators=[DataRequired()])
	password = PasswordField('密码', validators=[DataRequired()])
	password2 = PasswordField('确认密码', validators=[DataRequired(), EqualTo('password', message='密码错误')])
	submit = SubmitField('提交')


@app.route('/form', methods=['GET', 'POST'])
def form():
	loginForm = login_form()

	# 判断请求参数
	if request.method == 'POST':
		# 获取参数
		if loginForm.validate_on_submit():
			return 'SUCCESS'
		else:
			flash('参数有误')
	# 验证数据
	return render_template('form.html', form=loginForm)


'''
两张表： 角色（管理员/普通用户），用户（角色ID）
'''


# 数据库模型，需要继承db.Model
class Role(db.Model):
	# 定义表名
	__tablename__ = 'roles'

	# 定义字段 db.Column()表示是一个字段
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(16), unique=True)

	# 在一的一方，写关联
	# db.relationship('User') ： 表示和 User模型发生了关联，增加了一个User属性
	# backref='role' ： 表明 role是User要用的一个属性
	Users = db.relationship('User', backref='role')

	# repr() 方法显示一个可读字符串
	def __repr__(self):
		return '<Role: {} {}>'.format(self.name, self.id)


class User(db.Model):
	__tablename__ = 'users'
	user_id = db.Column(db.Integer, primary_key=True)
	user_name = db.Column(db.String(16), unique=False)
	email = db.Column(db.String(16), unique=True)
	password = db.Column(db.String(32))

	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

	def __repr__(self):
		return '<User: {} {} {} {}>'.format(self.user_name, self.user_id, self.email, self.password)


@app.route('/init')
def dbInit():
	# 删除表
	db.drop_all()

	# 创建表
	db.create_all()

	role1 = Role(name='admin')
	db.session.add(role1)
	db.session.commit()

	# 再次插入一条数据
	role2 = Role(name='user')
	db.session.add(role2)
	db.session.commit()

	user1 = User(user_name='wang', email='wang@qq.com', password='123456', role_id=role1.id)
	user2 = User(user_name='zhang', email='zhang@qq.com', password='123456', role_id=role1.id)
	user3 = User(user_name='chen', email='chen@qq.com', password='123456', role_id=role2.id)
	user4 = User(user_name='zhou', email='zhou@qq.com', password='123456', role_id=role2.id)
	user5 = User(user_name='tang', email='tang@qq.com', password='123456', role_id=role2.id)
	user6 = User(user_name='wu', email='wu@qq.com', password='123456', role_id=role2.id)
	user7 = User(user_name='qian', email='qian@qq.com', password='123456', role_id=role2.id)
	user8 = User(user_name='zhao', email='zhao@qq.com', password='123456', role_id=role2.id)
	user9 = User(user_name='liu', email='liu@qq.com', password='123456', role_id=role2.id)
	user10 = User(user_name='yang', email='yang@qq.com', password='123456', role_id=role1.id)

	db.session.add_all([user1, user2, user3, user4, user5, user6, user7, user8, user9, user10])
	print("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
	db.session.commit()
	user1 = db.session.query(User).first()
	print(user1)

	return 'Database init success'


app.config.from_object(mysqlConifg.Config)
db = mysqlConifg.db
db.init_app(app)
# 启动程序
if __name__ == '__main__':
	# 将Flask程序运行在一个简易服务器（Flask提供的，用于测试）
	app.run(debug=True)
