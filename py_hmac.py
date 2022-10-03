# -*- coding: utf-8 -*-
import hashlib
import hmac


def py_hmac(key, s):
    """
    散列消息鉴别码（Hash Message Authentication Code）， HMAC加密算法是一种安全的基于加密hash函数和共享密钥的消息认证协议。
    实现原理是用公开函数和密钥产生一个固定长度的值作为认证标识，用这个标识鉴别消息的完整性。
    使用一个密钥生成一个固定大小的小数据块，即 MAC，并将其加入到消息中，然后传输。接收方利用与发送方共享的密钥进行鉴别认证等。
    """
    # 第一个参数是密钥key，第二个参数是待加密的字符串，第三个参数是hash函数
    mac = hmac.new(key.encode('utf-8'), s.encode('utf-8'), hashlib.md5)
    mac.digest()  # 字符串的ascii格式
    return mac.hexdigest()  # 加密后字符串的十六进制格式


if __name__ == '__main__':
    key = 'key'
    s = '我是字符串'
    hmac_ret = py_hmac(key, s)
    print(hmac_ret)
