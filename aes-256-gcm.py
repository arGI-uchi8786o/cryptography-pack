from colorama import Fore, init
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets
import base64
init()
print(Fore.YELLOW + "=" * 60)
print(Fore.RED + "Welcome to encrypt-AES256GCM!")
key = secrets.token_bytes(32)
nonce = secrets.token_bytes(12)
cipher = Cipher(
    algorithm=algorithms.AES256(key=key),
    mode=modes.GCM(nonce),
    backend=default_backend
)
a = int(input("File or input?(file - 1, input - 2): "))
if a == 1:
    aaa = input(Fore.BLUE + "Enter filename to enc: ")
    with open(aaa, 'r', encoding='utf-8') as f:
        plaintext = f.read()
if a == 2:
   

   plaintext = input(Fore.RED + "Enter text to encrypt: ")
plaintext_byte = plaintext.encode('utf-8')
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext_byte) + encryptor.finalize()
tag = encryptor.tag
if a == 1:
    with open(f"{aaa}_key_and_tag_and_nonce", 'w') as f:
        f.seek(1)
        f.write("===================TAG=====================")
        f.write("" \
        "")
        

        f.write(f"tag: {base64.b64encode(tag).decode('utf-8')}\n")
        f.write('======================== KEY ================================================\n')
        f.write(f"key: {base64.b64encode(key).decode('utf-8')}\n")
        f.write('============================ NONCE ================================\n')
        f.write(f"nonce: {base64.b64encode(nonce).decode('utf-8')}\n")
        f.write('' \
        '')
        

    
    with open(f"{aaa}.enc",'w') as f:
        f.write(base64.b64encode(ciphertext).decode('utf-8'))
        
        


if a == 2:
   #
   print(f"tag: {base64.b64encode(tag).decode('utf-8')}")
   print(f"key: {base64.b64encode(key).decode('utf-8')}")
   print(f"nonce: {base64.b64encode(nonce).decode('utf-8')}")
   print(f"ciphertext: {base64.b64encode(ciphertext).decode('utf-8')}")
   print(f"tag: {base64.b64encode(tag).decode('utf-8')}")
