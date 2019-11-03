from flask import Flask, request, abort
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from http.client import OK, UNPROCESSABLE_ENTITY
from Crypto.Cipher import PKCS1_OAEP
import uuid
from os import getenv


app = Flask(__name__)

with open("./public_rsa") as file:
    chave_publica = RSA.importKey("".join(line for line in file))

with open("./private_rsa") as file:
    chave_privada = RSA.importKey("".join(line for line in file))

with open("./aes_key", "wb+") as file:
    key = chave_publica.encrypt(getenv("AES_KEY"))
    file.write(key)


@app.route('/encrypt', methods=['POST'])
def encrypt():
    body = request.data
    aes_cypher = AES.new(chave_privada.decrypt(key))

    filename = uuid.uuid4()
    with open(f"files/{filename}.txt", "wb+") as file:
        file.write(aes_cypher.encrypt(body))

    return f"{filename}", OK


@app.route('/decrypt/{filename}', methods=['POST'])
def decrypt(filename):
    
    try:
        filename = uuid.UUID(filename)
    except ValueError():
        abort("Nome de arquivo invalido", UNPROCESSABLE_ENTITY)

    with open(f"files/{filename}.txt", "") as file:
        return file.read(), OK

    

if __name__ == "__main__":
    app.run()