# -*- coding: utf-8 -*- 
# @Time : 2020/9/7 10:33 
# @Author : YHL <yanghelong@inspur.com>
# @File : mysqlConifg.py 
# explain : description
from flask_sqlalchemy import SQLAlchemy

# 创建db对象
db = SQLAlchemy()


class Config(object):
	DEBUG = True
	# 配置数据库的地址
	SQLALCHEMY_DATABASE_URI = 'mysql://root:root@127.0.0.1:3306/flask'
	# 跟踪数据库修改 ---->不建议开启，未来版本中会删除
	SQLALCHEMY_TRACK_MODIFICATIONS = False
