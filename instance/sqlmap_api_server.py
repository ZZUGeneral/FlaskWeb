# -*- coding: utf-8 -*-
# @Time    : 2020/12/22 16:44
# @Author  : yanghelong
# @File    : sqlmap_api_server.py
# @Software: PyCharm
import sys
import getopt
# 引用sqlmapapi_server,在启动服务后打印信息
from sqlmap.lib.util.api import server as sqlmap_restful_server


# 启动 sqlmapapi_server ，python sqlmapapi_server.py -h 127.0.0.1 --port=8878,启动后在服务端打印信息
def sqlmap_server(argv):
    port = 0
    try:
        opts, args = getopt.getopt(argv, "hp:", ["port="])
    except getopt.GetoptError:
        print("sqlmap_api_server.py --port 8778")
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print("sqlmap_api_server.py --port 8778")
            sys.exit()
        elif opt in ("-p", "--port"):
            port = arg
    if port != 0:
        sqlmap_restful_server("127.0.0.1", int(port))


if __name__ == '__main__':
    sqlmap_server(sys.argv[1:])
