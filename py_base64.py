# -*- coding: utf-8 -*-
import base64


def py_base64(s):
    """
    """
    return base64.b64encode(s.encode('utf-8'))


if __name__ == '__main__':
    s = '我是字符串'
    base64_ret = py_base64(s)
    print(base64_ret)
    print(base64_ret.decode('utf-8'))
    print(str(base64_ret, 'utf-8'))
