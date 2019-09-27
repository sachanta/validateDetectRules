# taken from https://tutorialsoverflow.com/how-to-make-a-file-encryption-and-decryption-tool/

import sys
import funcy
import base64
import Crypto.Protocol
from Crypto import Random
from Crypto.Cipher import AES


def start():
    print("Start file crypto ...")


class FileCrypto(object):
    """
    Crypto class providing file encrypt and decrypt functions
    """

    def __init__(self, input_file, output_file, secret_key):
        """
        Creates a new instance of the client.

        :param input_file: str input file path.
        :param output_file: str output file path.
        :secret_key: str secret key to encrypt or decrypt file

        """
        (self.input_file, self.output_file, self.secret_key) = (input_file, output_file, secret_key)

    def decrypt_file(self):

        # if isinstance(file_name, str) and isinstance(encrypt_key, str):
        #     print ("Decrypting the file ...")
        # else:
        #     print("Argument to decrpyt_file function is incorrect. Aborting the program!")
        #     sys.exit(0)

        with open(self.input_file, "rb") as encryptedFile:
            chunk_size = 24 * 1024
            encrypted = base64.b64decode(encryptedFile.read(64))
            setup = encrypted[:48]
            # key_confirm = input("Please enter the key used to encrypt the file:- ")
            salt = b'\x9aX\x10\xa6^\x1fUVu\xc0\xa2\xc8\xff\xceOV'
            key_check = Crypto.Protocol.KDF.PBKDF2(password=self.secret_key, salt=salt, dkLen=32, count=10000)

            def unpad(s):
                return s[:-ord(s[len(s) - 1:])]

            if key_check == setup[:32]:
                print("Password Correct!")
            else:
                print("Wrong Password!")
                sys.exit(0)

            iv = setup[32:]
            cipher = AES.new(key_check, AES.MODE_CBC, iv)
            with open(self.output_file, "wb") as decryptedFile:
                encrypted = base64.b64decode(encryptedFile.read())
                chunks = list(funcy.chunks(chunk_size, encrypted))
                for chunk in chunks:
                    decrypted_chunk = unpad(cipher.decrypt(chunk))
                    decryptedFile.write(decrypted_chunk)

    def encrypt_file(self):

        salt = b'\x9aX\x10\xa6^\x1fUVu\xc0\xa2\xc8\xff\xceOV'
        key = Crypto.Protocol.KDF.PBKDF2(password=self.secret_key, salt=salt, dkLen=32, count=10000)
        iv = Random.new().read(AES.block_size)
        bs = AES.block_size
        chunk_size = 64 * 1024

        def pad(s):
            return s + (bs - len(s) % bs) * chr(bs - len(s) % bs).encode('utf-8')

        cipher = AES.new(key, AES.MODE_CBC, iv)
        with open(self.input_file, "rb") as plain:
            with open(self.output_file, "wb") as outFile:
                outFile.write(base64.b64encode(key + iv))
                while True:
                    chunk = plain.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    chunk = pad(chunk)
                    outFile.write(base64.b64encode(cipher.encrypt(chunk)))


if __name__ == '__main__':
    start()