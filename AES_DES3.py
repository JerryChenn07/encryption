import base64
import gzip
from binascii import b2a_hex, a2b_hex
from io import BytesIO

from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from hexdump import hexdump


# 需要补位，str不是16的倍数那就补足为16的倍数
def add_to_16(value):
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode(value)  # 返回bytes


class EncryptDate:
    def __init__(self, type, key, iv=None):
        if type == 'AES':
            self.unpad = lambda date: date[0:-ord(date[-1])]
            self.key = key  # 初始化密钥
            if iv:
                print(f"有向量<{iv}>AES加解密>>CBC模式\n")
                self.iv = iv
                self.length = AES.block_size  # 初始化数据块大小
                self.aes = AES.new(self.key, AES.MODE_CBC, self.iv)  # 初始化AES,ECB模式的实例
                # 截断函数，去除填充的字符

            else:
                print("无向量AES加解密>>ECB模式\n")
                self.length = AES.block_size  # 初始化数据块大小
                # self.aes = AES.new(self.key, AES.MODE_ECB)  # 初始化AES,ECB模式的实例
                self.aes = AES.new(add_to_16(self.key), AES.MODE_ECB)  # 初始化AES,ECB模式的实例
                # 截断函数，去除填充的字符
        elif type == 'DES3':
            self.key = key  # 初始化密钥
            if iv:
                print(f"有向量<{iv}>DES加解密>>CBC模式\n")
                self.iv = iv
                self.length = DES3.block_size  # 初始化数据块大小
                self.aes = DES3.new(
                    self.key, DES3.MODE_CBC, self.iv)  # 初始化AES,ECB模式的实例

            else:
                print(f"无向量<{iv}>DES加解密>>EBC模式\n")
                self.length = DES3.block_size  # 初始化数据块大小
                self.aes = DES3.new(self.key, DES3.MODE_ECB)  # 初始化AES,ECB模式的实例
        elif type == 'DES':
            self.key = key  # 初始化密钥
            if iv:
                print(f"有向量<{iv}>DES加解密>>CBC模式\n")
                self.iv = iv
                self.length = DES.block_size  # 初始化数据块大小
                self.aes = DES.new(
                    self.key, DES.MODE_CBC, self.iv)  # 初始化AES,ECB模式的实例

            else:
                print(f"无向量<{iv}>DES加解密>>EBC模式\n")
                self.length = DES.block_size  # 初始化数据块大小
                self.aes = DES.new(self.key, DES.MODE_ECB)  # 初始化AES,ECB模式的实例

    def base64_decode(self, text):
        return base64.b64decode(text)

    def pad(self, text):
        """
        #填充函数，使被加密数据的字节码长度是block_size的整数倍
        """
        count = len(text.encode('utf-8'))
        add = self.length - (count % self.length)
        entext = text + (chr(add) * add)
        return entext

    # base64输出
    def encrypt(self, encrData):  # 加密函数
        res = self.aes.encrypt(self.pad(encrData).encode("utf8"))
        print(hexdump(res))
        print(len(res))
        msg = str(base64.b64encode(res), encoding="utf8")
        return msg

    def decrypt(self, decrData):  # 解密函数
        res = base64.b64decode(decrData.encode("utf8"))
        print(len(res))
        # print(len(res))
        # print(res)
        # print(b2a_hex(res))
        # print(res)
        print(self.aes.decrypt(res))
        msg = self.aes.decrypt(res).decode()

        return self.unpad(msg)

    # 16进制输出
    def encrypt_hex(self, encrData):  # 加密函数
        res = self.aes.encrypt(self.pad(encrData).encode())
        print(hexdump(res))
        # msg = str(base64.b64encode(res), encoding="utf8")
        return b2a_hex(res).decode()

    def decrypt_hex(self, decrData):  # 解密函数
        res = a2b_hex(decrData)
        plain_text = self.aes.decrypt(res)
        #
        print(len(plain_text))
        print(b2a_hex(plain_text).decode())
        print("解密bytes:", hexdump(plain_text))

        # return self.unpad(plain_text.decode())
        return plain_text.decode()


def gzip_decompress(buf: bytes):
    buf = BytesIO(buf)
    gf = gzip.GzipFile(fileobj=buf)
    content_bytes = gf.read()
    return content_bytes


if __name__ == "__main__":
    # a = "FIIBIckYL8OFPUp25VbKgZpJauHR7a6jlit/Z75TEXUWvlropB3Vt0OYZ5mFxCbB+qzdvs+GIBGhbJIzRdlFnQ=="
    # print(base64.b64decode(a.encode()))
    # # a="2daaf5f45222d792fb3eebaa4aa274c9122df992f4e7cd2cd8331ab5d48ff11e116a634d73ac1e88bbe5a5d219f4468a7d1357f80c14f14cc7e289011abdc872663ff0a9c2ba6b756de303fc8f6120966f2c442dd619def4748e6f016b9d5fbb6dc46ccd49008f36f9188e502d35f36cf06c75842c78a0d78e64a1e9cc5c1a59c378e37ac08cd491086fafd33a054ccc740abb8361e261c976843d4bb91d90d955926e7b0b7e38d6ec644bf653364cd6f628f5946322759ab2ec2cdf35ac3cd3a80ee3c061f589f72f5a15cedee0a9ac7a14d3a9e16adae458c2aa67be0936d8afc43c9717bd767f5a74fd962ee964b6689a832193972b54fbf92232b60f46a26c044fca93f1a64eba815d2b0c6a501484449fe62d9a7e9342048b720813c7f0a472fc564f78aac1daceafb2264f1c27fc55ecb3ca57628958b236ff38c2e54d3c262c9da0e5c87e6389f5c2830fc4d697453aafd5479fda09830ae4fc9397a72cdc76ed9d8cadc440cad2fa7f3c049707e0a30b075059b0ed1f4d85fdff3c9b3c33205590213c2e97c6efca1e5a986ce415a61114dd974bc5ec23c9fef610975f777b89f4488ae0aacb7ced893855773cdca261884073b999c789fb8658c7e6542b6ee7b374cf51ceee2bd1087728886385269856396cac17af9d67820279dbbe63547296fdc4a8508b0e10b91b6478fed4b41b576b4e0e06e83a3e7ece365b5d052df349170d1eec1ae58bda691238"
    # key = a2b_hex("f72ccae4dc732149f0ab817e45f84744")
    # # print(key)
    # key = '8e963b3c738748e9'.encode()
    # iv = a2b_hex("30313032303330343035303630373038")
    # print(iv)
    # aes = EncryptDate('AES', key)
    # data = aes.decrypt(a)
    # print(data)

    key = 'abcdefgabcdefg12'
    aes = EncryptDate('AES', key)
    ret_aes_encrypt = aes.encrypt('Cluo667788')
    print(ret_aes_encrypt)
    # b6vmwH18ZrUmyqUe0key+w==
