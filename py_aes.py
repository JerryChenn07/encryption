import base64

# pip install pycryptodome
from Crypto.Cipher import AES

'''
AES对称加密算法
高级加密标准（英语：Advanced Encryption Standard），在密码学中又称Rijndael加密法，是美国联邦政府采用的一种区块加密标准。
这个标准用来替代原先的DES，已经被多方分析且广为全世界所使用。
'''


# 需要补位，str不是16的倍数那就补足为16的倍数
def add_to_16(value):
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode(value)  # 返回bytes


# 加密方法
def aes_encrypt(key, text):
    aes = AES.new(add_to_16(key), AES.MODE_ECB)  # 初始化加密器
    encrypt_aes = aes.encrypt(add_to_16(text))  # 先进行aes加密
    encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  # 执行加密并转码返回bytes
    return encrypted_text


# 解密方法
def aes_decrypt(key, text):
    aes = AES.new(add_to_16(key), AES.MODE_ECB)  # 初始化加密器
    base64_decrypted = base64.decodebytes(text.encode(encoding='utf-8'))  # 优先逆向解密base64成bytes
    decrypted_text = str(aes.decrypt(base64_decrypted), encoding='utf-8').replace('\0', '')  # 执行解密密并转码返回str
    return decrypted_text


if __name__ == '__main__':
    # 期望 7Tyj2uXr2l/8GiYfASTedw==
    ret_aes_encrypt = aes_encrypt('abcdefgabcdefg12', 'Ksai1234')
    ret_aes_decrypt = aes_decrypt('abcdefgabcdefg12', ret_aes_encrypt)
    print(ret_aes_encrypt)
    print(ret_aes_decrypt)
