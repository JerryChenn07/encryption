# -*- coding: utf-8 -*-
import hashlib


def py_sha1(s):
    """
    安全哈希算法（Secure Hash Algorithm）主要适用于数字签名标准（Digital Signature Standard DSS）里面定义的数字签名算法（Digital Signature Algorithm DSA），
    SHA1比MD5的安全性更强。对于长度小于2^ 64位的消息，SHA1会产生一个160位的消息摘要。
    """
    return hashlib.sha1(s.encode('utf-8')).hexdigest()


if __name__ == '__main__':
    s = '我是字符串'
    sha1_ret = py_sha1(s)
    print(sha1_ret)
