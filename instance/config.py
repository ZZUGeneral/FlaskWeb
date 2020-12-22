# -*- coding: utf-8 -*-
# @Time    : 2020/12/22 16:32
# @Author  : yanghelong
# @File    : config.py
# @Software: PyCharm
import os

LOGGER_PATH = os.path.abspath(os.path.dirname(__file__)) + '/../logs/'


class BaseConfig(object):
    # 日志配置
    DEBUG = False
    AUTH = True
    SERVER_HOST = '0.0.0.0'
    SERVER_POST = 50020
    SECRET_KEY = 'B10ySw1nPL8JBo6z'


class DevelopmentConfig(BaseConfig):
    # Redis 配置
    REDIS_HOST = '127.0.0.1'
    REDIS_POST = 6379
    REDIS_PASSWORD = ""
    REDIS_DB = 0

    # MongoDB 配置
    MONGO_HOST = '127.0.0.1'
    MONGO_PORT = 27017
    MONGO_DB = 'fuxi'
    MONGO_USER = ''
    MONGO_PASSWORD = ''


class ProductionConfig(BaseConfig):
    pass


config = {
    'dev': DevelopmentConfig,
    'prod': ProductionConfig,
    'default': DevelopmentConfig
}
