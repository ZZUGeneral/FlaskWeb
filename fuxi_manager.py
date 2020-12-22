# -*- coding: utf-8 -*-
# @Time    : 2020/12/22 17:07
# @Author  : yanghelong
# @File    : fuxi_manager.py
# @Software: PyCharm

from fuxi.web.router import quart_app

if __name__ == '__main__':
    quart_app.run(
        host=quart_app.config.get('SERVER_HOST'),
        port=int(quart_app.config.get('SERVER_PORT'))
    )
