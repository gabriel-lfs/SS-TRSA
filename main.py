from flask import Flask, request, abort, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from http.client import OK, UNPROCESSABLE_ENTITY
import uuid
from os import getenv


app = Flask(__name__)

with open("./public_rsa.pem") as file:
    chave_publica = RSA.importKey(file.read())
    cifra_publica = PKCS1_OAEP.new(chave_publica)

with open("./private_rsa.pem") as file:
    chave_privada = RSA.importKey(file.read())
    cifra_privada = PKCS1_OAEP.new(chave_privada)

with open("./aes_key", "wb+") as file:
    key = cifra_publica.encrypt(bytes(getenv("AES_KEY"), encoding='utf-8'))
    file.write(key)


@app.route('/encrypt', methods=['POST'])
def encrypt():
    content = request.data

    length = len(content)
    length %= 16
    if length > 0:
        content += b'\x80' + b'\0' * (15 - length)
    aes_cypher = AES.new(cifra_privada.decrypt(key), AES.MODE_CBC, IV=b'\0' * 16)

    filename = uuid.uuid4()
    with open(f"files/{filename}.bin", "wb+") as file:

        encrypted_content = aes_cypher.encrypt(content)
        file.write(encrypted_content)

    return jsonify({"encryptedName": f"{filename}", "encryptedContent": str(encrypted_content)}), OK


@app.route('/decrypt/<filename>', methods=['GET'])
def decrypt(filename):

    try:
        filename = uuid.UUID(filename)
    except ValueError():
        abort("Nome de arquivo invalido", UNPROCESSABLE_ENTITY)

    with open(f"files/{filename}.bin", "rb") as f:
        content = f.read()

    aes_cypher = AES.new(cifra_privada.decrypt(key), AES.MODE_CBC, IV=b'\0' * 16)

    return aes_cypher.decrypt(content), OK


if __name__ == "__main__":
    app.run()
