import os
import argon2
import base64
import json


def argon2_hash(data, salt=None):
        """Хеширование с помощью Argon2id"""
        if salt is None:
            salt = os.urandom(16)
        data_bytes = data.encode('utf-8')


        hasher = argon2.PasswordHasher(
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            salt_len=16,
            type=argon2.Type.ID
        )



        hash_result = hasher.hash(data_bytes + salt)
        # hash_result is str, encode to bytes before base64
        hash_bytes = hash_result.encode('utf-8')
        hash_b64 = base64.b64encode(hash_bytes).decode()
        salt_b64 = base64.b64encode(salt).decode()
        return {
             'hash': hash_b64,
             'salt': salt_b64
        }

a = input("Файл или ввод(1 - файл, 2 - ввод)?: ")
if a == "1":
     aa = input("Введи имя файл: ")
     with open(aa, 'r', encoding='utf-8') as f:
          aaa = f.read()

     with open(f"{aa}.argoin2id", 'w', encoding='utf-8') as f:

          aaaa = argon2_hash(aaa)
          f.write(json.dumps(aaaa))
elif a == '2':
     aaaaaaaaaa = input('Что хешировать?')
     aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa = argon2_hash(aaaaaaaaaa)
     print(json.dumps(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa))



          
