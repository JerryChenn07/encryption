# -*- coding: utf-8 -*-
import hashlib


def py_md5(s):
    """
    MD5消息摘要算法（英语：MD5 Message-Digest Algorithm），
    一种被广泛使用的密码散列函数，可以产生出一个128位（16字节）的散列值（hash value），用于确保信息传输完整一致。
    md5加密算法是不可逆的，所以解密一般都是通过暴力穷举方法，通过网站的接口实现解密。
    """
    return hashlib.md5(s.encode('utf-8')).hexdigest()


if __name__ == '__main__':
    s = '我是字符串'
    md5_ret = py_md5(s)
    print(md5_ret)
