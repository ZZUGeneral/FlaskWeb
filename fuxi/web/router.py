# -*- coding: utf-8 -*-
# @Time    : 2020/12/22 17:07
# @Author  : yanghelong
# @File    : router.py
# @Software: PyCharm
from flask_restful import Api

from fuxi.web.quart_app import quart_app
from quart import blueprints

# quart_app.register_blueprint(blue_view)
api = Api(quart_app)
