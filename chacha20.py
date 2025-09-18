import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import base64, secrets
from cryptography.hazmat.primitives import padding
key = secrets.token_bytes(32)
nonce = secrets.token_bytes(16)

cipher = Cipher(algorithm=algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())

encryptor = cipher.encryptor()
inpurrrrr = input("А вам вообще... Что шифровать? файл там, или просто сюда текст введите я че знаю. коротко - 1 для файла, 2 для ввода: ")
if inpurrrrr == "1":
    file = input("Ну, введи имя файла: ")
    with open(file, "r", encoding='utf-8') as f:
        texsst = f.read()

    plaintext = texsst.encode('utf-8')
elif inpurrrrr == "2":
    IMMmM = input("И что тебе зашифровать?: ")
    plaintext = IMMmM.encode('utf-8')
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

if inpurrrrr == "1":
    with open(f"{file}.enc", 'w') as f:
        f.write(base64.b64encode(ciphertext).decode('utf-8'))
    with open(f"{file}.enc.keys", 'w') as f:
        f.write(f"nonce: {base64.b64encode(nonce).decode('utf-8')}\n")
        f.write(f"key: {base64.b64encode(key).decode('utf-8')}")
elif inpurrrrr == "2":
    print(f"ciphertext: {base64.b64encode(ciphertext).decode('utf-8')}")
    print("==============================================================================")
    print(f"nonce:{base64.b64encode(nonce).decode('utf-8')}")
    print("=======================================================================================")
    print(f'key:{base64.b64encode(key).decode('utf-8')}')

