# -*- coding: utf-8 -*-
# @Time    : 2020/12/22 17:34
# @Author  : yanghelong
# @File    : logger.py
# @Software: PyCharm
import logging
import time
import sys
import os
import inspect
from instance.config import LOGGER_PATH


def _format_message(level, message):
    '''
    格式化日志
    :param level:logger level:
    :param message:logger data:
    :return : formatted data:
    '''
    frame = inspect.currentframe().f_back.f_back
    frame_info = inspect.getframeinfo(frame)
    line_no = frame_info.lineno
    file_name = frame_info.filename
    module_name = os.path.split(file_name)[-1]
    message = "{time} {level} - {module}[{line}]: {message}".format(
        time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        module=module_name,
        line=line_no,
        message=message,
        level=level
    )
    return message


class _Logger:
    def __init__(self):
        try:
            # 获取日志保存路径
            self._log_file = LOGGER_PATH + '/' + "fuxi_{}.log".format(time.strftime("%Y_%m_%d", time.localtime()))
            if not os.path.exists(LOGGER_PATH):
                os.mkdir(LOGGER_PATH)
            self._logger = logging.getLogger("fuxi")
            self._logger.setLevel(logging.DEBUG)
            # 将日志保存到文件
            file_handler = logging.FileHandler(self._log_file)
            self._logger.addHandler(hdlr=file_handler)
            # 标准输出
            stream_handler = logging.StreamHandler(sys.stdout)
            # stream_handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(hdlr=stream_handler)
        except Exception as e:
            raise e

    def info(self, message):
        self._logger.info(_format_message("INFO", message))

    def success(self, message):
        self._logger.info(_format_message("INFO", message))

    def warning(self, message):
        self._logger.warning(_format_message("WARn", message))

    def error(self, message):
        self._logger.error(_format_message("ERROR", message))

    def debug(self, message):
        self._logger.info(_format_message("DEBUG", message))

    def access(self, message):
        self._logger.info("{time} ACCESS - {message}".format(
            time=time.strftime("%Y_%m_%d %H:%M:%S", time.localtime()),
            message=message
        ))


logger = _Logger
