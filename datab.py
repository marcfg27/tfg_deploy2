import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask_sqlalchemy import SQLAlchemy


def cifrar_clave(clave_a_cifrar, clave_cifrado):
    encode= clave_cifrado.encode('utf-8')
    aesgcm = AESGCM(encode)
    nonce = secrets.token_bytes(12)
    clave1_cifrada = aesgcm.encrypt(nonce, clave_a_cifrar.encode('utf-8'), None)
    key = nonce + clave1_cifrada
    key = key.hex()
    return  key



def descifrar_clave(clave1_cifrada, clave_cifrado):

    try:
        token_bytes = bytes.fromhex(clave1_cifrada)
        nonce = token_bytes[:12]
        ciphertext = token_bytes[12:]
        k = str.encode(clave_cifrado)
        aesgcm = AESGCM(k)
        clave1_descifrada = aesgcm.decrypt(nonce, ciphertext, None)
    except:
        return None
    return clave1_descifrada.decode("utf-8")

db = SQLAlchemy()
KEK = os.environ.get('KEK')
secret_key = descifrar_clave(os.environ.get('MI_SECRET_KEY'),KEK)
secret_key2 = descifrar_clave(os.environ.get('MI_SECRET_KEY2'),KEK)
admin_pass = descifrar_clave(os.environ.get('ADMIN_PASS'),KEK)
email_user = descifrar_clave(os.environ.get('MAIL_USERNAME'),KEK)
email_pass = descifrar_clave(os.environ.get('MAIL_PASSWORD'),KEK)


#Salt = "11600f8a2e578cc957564c13dc3f5c57bc52c5cfd5324f36b40be7b96f090b6d"