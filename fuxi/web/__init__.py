# -*- coding: utf-8 -*-
# @Time    : 2020/12/22 17:07
# @Author  : yanghelong
# @File    : __init__.py.py
# @Software: PyCharm
import os
import subprocess
import sys
import time

import requests


def _sqlmap_restful_server_start(port):
    # 获取 sqlmap_server.py 文件
    sqlmap_file = os.path.abspath(os.path.dirname(__file__))+"/../../instace/sqlmap_api_server.py"
    # 启动 sqlmapapi_server
    subprocess.Popen("{} {} -p {}".format(
        sys.executable,sqlmap_file,port
    ),shell=True,encoding="utf-8",stdout=subprocess.PIPE,stderr=subprocess.PIPE)

def _sqlmap_restful_server_check(server):
    time.sleep()
    try:
        response = requests.get("{}/task/new".format(server))
        if response.json()['success']:
            return  True
    except Exception as  e:
        return False

class ThirdPartyAppInit(object):
    def __init__(self):
        self.name_exe = "nmap_exe"
        self.whatweb_exe = "whatweb_exe"
        self.sqlmap_api = "sqlmap_api"


