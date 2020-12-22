# -*- coding: utf-8 -*-
# @Time    : 2020/12/22 17:11
# @Author  : yanghelong
# @File    : quart_app.py
# @Software: PyCharm

import sys
from quart import Quart
from celery import Celery
from flask_cors import CORS
from secrets import token_urlsafe
from instance.config import config
from fuxi.common.utils.logger import logger


def create_app(config_name):
    try:
        _app = Quart(__name__, static_folder="../../static/", static_url_path='', template_folder="../../static")
        _app.config.from_object(config[config_name])
        _app.config['CELERY_BROKEN_URL'] = "redis://{}:{}/{}".format(
            _app.config.get("REDIS_HOST"), _app.config.get("REDIS_PORT"), _app.config.get("REDIS_DB")
        )
        if _app.config.get("MONGO_USER") and _app.config.get("MONGO_PASSWORD"):
            _app.config['MONGO_URL'] = "mongodb://{}:{}@{}:{}/{}".format(
                _app.config.get("MONGO_USER"), _app.config.get("MONGO_PASSWORD"), _app.config.get("MONGO_HOST"),
                _app.config.get("MONGO_PORT"), _app.config.get("MONGO_DB")
            )
        else:
            _app.config['MONGO_URL'] = "mongodb://{}:{}/{}".format(
                _app.config.get("MONGO_HOST"),
                _app.config.get("MONGO_PORT"), _app.config.get("MONGO_DB")
            )
        _app.config['SERET_KEY'] = token_urlsafe()
        CORS(_app, support_credentials=True)
        return _app
    except Exception as e:
        logger.errot("create flask app errot:{}".format(e))
        sys.exit(0)


quart_app = create_app('dev')
fuxi_celery = Celery(quart_app.name, broker=quart_app.config['CELERT_BROKER_URL'])
fuxi_celery.conf.update(quart_app.config)
quart_app.app_context().push()
