# -*- coding: utf-8 -*-
# @Time    : 2020/12/19 15:19
# @Author  : yanghelong
# @File    : Response.py
# @Software: PyCharm
import time


class _ResponseContext:
    def __init__(self):
        self.date = {
            "status": {"status": "", "code": 0, "message": ""},
            "result": "",
            "timestamp": 0
        }

    def success(self, status=None, message=None, data=""):
        self.date['status']['code'], self.date['status']['message'] = StatusCode.SUCCESS
        self.date['status']['status'] = 'success'
        self.date['result'] = data
        self.date['timestamp'] = int(time.time())
        if status:
            self.date['status']['code'], self.date['status']['message'] = status
        if message:
            self.date['status']['message'] = str(message)
        return self.date

    def fail(self, status=None, message=None, data=""):
        self.date['status']['code'], self.date['status']['message'] = StatusCode.FAILED
        self.date['status']['status'] = 'failed'
        self.date['result'] = data
        self.date['timestamp'] = int(time.time())
        if status:
            self.date['status']['code'], self.date['status']['message'] = status
        if message:
            self.date['status']['message'] = str(message)
        return self.date


class StatusCode:
    # success
    SUCCESS = (10200, "")
    # fail
    AUTH_FAILED = (10401, "The access token is invalid")
    NOT_FOUNT = (10404, "The requested URL was not found on the server")
    FAILED = (10503, "Unkonwn error,Please try again later")
    SERVER_ERROR = (10500, "Internal Server Error")


Response = _ResponseContext
