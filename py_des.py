import binascii

from pyDes import des, CBC, PAD_PKCS5


def py_des(key, s):
    """
    数据加密标准（Data Encryption Standard），属于对称加密算法。
    DES是一个分组加密算法，典型的DES以64位为分组对数据加密，加密和解密用的是同一个算法。
    它的密钥长度是56位（因为每个第8 位都用作奇偶校验），密钥可以是任意的56位的数，而且可以任意时候改变。
    """

    def des_encrypt(secret_key, s):
        """
        加密
        """
        iv = secret_key
        k = des(secret_key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        en = k.encrypt(s, padmode=PAD_PKCS5)
        return binascii.b2a_hex(en)

    def des_decrypt(secret_key, s):
        """
        解密
        """
        iv = secret_key
        k = des(secret_key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        de = k.decrypt(binascii.a2b_hex(s), padmode=PAD_PKCS5)
        return de

    secret_str = des_encrypt(key, s)
    print(secret_str)
    clear_str = des_decrypt(key, secret_str)
    print(clear_str)


if __name__ == '__main__':
    key = '12345678'
    s = 'test des'
    hmac_ret = py_des(key, s)
    print(hmac_ret)
