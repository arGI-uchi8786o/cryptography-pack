import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from kyber_py.kyber import Kyber1024 as Kyber
from colorama import Fore, init
from Crypto.Hash import SHA3_256, SHA256
from Crypto.Signature import DSS
from Crypto.PublicKey import ECC
import argon2
init()
class HybridEncryption:
    def __init__(self):
        self.kyber_key = None
        self.ec_private_key = None
        self.ec_public_key = None
       
    def generate_kyber_keys(self):
        """Генерация ключей Kyber-1024"""
        public_key, private_key = Kyber.keygen()
        return public_key, private_key
   
    def generate_ec_keys(self):
        """Генерация ECDSA ключей для подписи"""
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        return private_key, public_key
   
    def kyber_encrypt(self, public_key):
        """Шифрование с помощью Kyber"""
        shared_secret, ciphertext = Kyber.encaps(public_key)
        return ciphertext, shared_secret
   
    def kyber_decrypt(self, ciphertext, private_key):
        """Дешифрование с помощью Kyber"""
        shared_secret = Kyber.decaps(private_key, ciphertext)
        return shared_secret
   
    def derive_aes_key(self, shared_secret, salt=None):
        """Производный AES ключ с помощью HKDF и SHA256"""
        if salt is None:
            salt = os.urandom(32)
       
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'aes-256-gcm-key',
        )
        return hkdf.derive(shared_secret), salt
   
    def argon2_hash(self, data, salt=None):
        """Хеширование с помощью Argon2id"""
        if salt is None:
            salt = os.urandom(16)
       
        hasher = argon2.PasswordHasher(
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            salt_len=16,
            type=argon2.Type.ID
        )
       
        # Для совместимости с данными
        if isinstance(data, str):
            data = data.encode()
       
        hash_result = hasher.hash(data + salt)
        return hash_result, salt
   
    def sha256_hash(self, data):
        """Хеширование с помощью SHA256"""
        if isinstance(data, str):
            data = data.encode()
       
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()
   
    def sign_data(self, data, private_key):
        """Подпись данных с помощью ECDSA"""
        if isinstance(data, str):
            data = data.encode()
       
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return signature
   
    def verify_signature(self, data, signature, public_key):
        """Проверка подписи"""
        if isinstance(data, str):
            data = data.encode()
       
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
   
    def aes_gcm_encrypt(self, data, key, associated_data=None):
        """Шифрование AES-256-GCM"""
        if isinstance(data, str):
            data = data.encode()
       
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
       
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
       
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv, ciphertext, encryptor.tag
   
    def aes_gcm_decrypt(self, iv, ciphertext, tag, key, associated_data=None):
        """Дешифрование AES-256-GCM"""
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
       
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
       
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
   
    def encrypt_data(self, data, use_signature=False, use_argon2=False):
        """Основная функция шифрования"""
        # Генерация ключей Kyber
        kyber_public, kyber_private = self.generate_kyber_keys()
       
        # Шифрование с помощью Kyber
        kyber_ciphertext, kyber_shared_secret = self.kyber_encrypt(kyber_public)
       
        # Производный AES ключ
        aes_key, salt = self.derive_aes_key(kyber_shared_secret)
       
        # Дополнительные хеши
        hashes_data = {}
        if use_argon2:
            argon2_hash, argon2_salt = self.argon2_hash(data)
            hashes_data['argon2'] = base64.b64encode(argon2_hash.encode()).decode()
            hashes_data['argon2_salt'] = base64.b64encode(argon2_salt).decode()
       
        sha256_hash = self.sha256_hash(data)
        hashes_data['sha256'] = base64.b64encode(sha256_hash).decode()
       
        # Подпись если требуется
        signature_data = {}
        if use_signature:
            ec_private, ec_public = self.generate_ec_keys()
            signature = self.sign_data(data, ec_private)
            signature_data['signature'] = base64.b64encode(signature).decode()
            signature_data['public_key'] = base64.b64encode(
                ec_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ).decode()
       
        # Шифрование данных AES-GCM
        iv, ciphertext, tag = self.aes_gcm_encrypt(data, aes_key)
       
        # Формирование результата
        result = {
            'kyber_ciphertext': base64.b64encode(kyber_ciphertext).decode(),
            'kyber_private_key': base64.b64encode(kyber_private).decode(),
            'aes_salt': base64.b64encode(salt).decode(),
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'hashes': hashes_data,
            'signature': signature_data if use_signature else None
        }
       
        return result
   
    def decrypt_data(self, encrypted_data):
        """Основная функция дешифрования"""
        # Извлечение компонентов
        kyber_ciphertext = base64.b64decode(encrypted_data['kyber_ciphertext'])
        kyber_private_key = base64.b64decode(encrypted_data['kyber_private_key'])
        salt = base64.b64decode(encrypted_data['aes_salt'])
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])
       
        # Дешифрование Kyber
        shared_secret = self.kyber_decrypt(kyber_ciphertext, kyber_private_key)
       
        # Производный AES ключ
        aes_key, _ = self.derive_aes_key(shared_secret, salt)
       
        # Дешифрование AES-GCM
        plaintext = self.aes_gcm_decrypt(iv, ciphertext, tag, aes_key)
       
        # Проверка хешей
        if 'hashes' in encrypted_data:
            sha256_received = base64.b64decode(encrypted_data['hashes']['sha256'])
            sha256_calculated = self.sha256_hash(plaintext)
           
            if sha256_received != sha256_calculated:
                raise ValueError("SHA256 hash verification failed!")
       
        # Проверка подписи если есть
        if encrypted_data.get('signature'):
            signature_data = encrypted_data['signature']
            signature = base64.b64decode(signature_data['signature'])
            public_key_bytes = base64.b64decode(signature_data['public_key'])
           
            public_key = serialization.load_pem_public_key(public_key_bytes)
            if not self.verify_signature(plaintext, signature, public_key):
                raise ValueError("Signature verification failed!")
       
        return plaintext

def main():
    encryption = HybridEncryption()
   
    print(Fore.GREEN + "Гибридное шифрование AES256-GCM + Kyber1024")
    print(Fore.RED + "=" * 50)
   
    choice = input("Что зашифровать (1 - файл, 2 - твой ввод): ").strip()
   
    use_signature = input("Использовать постквантовую подпись? (y/n): ").lower() == 'y'
    use_argon2 = input("Использовать Argon2id хеш? (y/n): ").lower() == 'y'
   
    if choice == '1':
        # Шифрование файла
        file_path = input("Введи файл что я зашифрую: ").strip()
       
        if not os.path.exists(file_path):
            print(Fore.RED + "Файл не существует!")
            return
       
        with open(file_path, 'rb') as f:
            data = f.read()
       
        print(Fore.LIGHTRED_EX + "Шифрую файл...")
        encrypted_data = encryption.encrypt_data(data, use_signature, use_argon2)
       
        # Сохранение зашифрованного файла
        enc_file = file_path + '.enc'
        with open(enc_file, 'w') as f:
            json.dump({'ciphertext': encrypted_data['ciphertext'],
                      'iv': encrypted_data['iv'],
                      'tag': encrypted_data['tag']}, f)
       
        # Сохранение ключей
        key_file = file_path + '.enc_key'
        key_data = {k: v for k, v in encrypted_data.items()
                   if k not in ['ciphertext', 'iv', 'tag']}
       
        with open(key_file, 'w') as f:
            json.dump(key_data, f, indent=2)
       
        print(f"Файл зашифрован: {enc_file}")
        print(f"Ключи сохранены: {key_file}")
       
    elif choice == '2':
        # Шифрование текстового ввода
        text = input("Введи ввод что я зашифрую: ")
       
        print("Шифрую данные...")
        encrypted_data = encryption.encrypt_data(text, use_signature, use_argon2)
       
        print("\nЗашифрованные данные:")
        print("=" * 50)
        print(f"Kyber ciphertext: {encrypted_data['kyber_ciphertext'][:100]}...")
        print(f"IV: {encrypted_data['iv']}")
        print(f"Tag: {encrypted_data['tag']}")
        print(f"AES Salt: {encrypted_data['aes_salt']}")
       
        if use_argon2:
            print(f"Argon2 hash: {encrypted_data['hashes']['argon2'][:50]}...")
       
        print(f"SHA256 hash: {encrypted_data['hashes']['sha256']}")
       
        if use_signature:
            print(f"Signature: {encrypted_data['signature']['signature'][:50]}...")
       
        # Демонстрация дешифрования
        print("\n" + "=" * 50)
        decrypt_choice = input("Показать дешифрованные данные? (y/n): ").lower()
       
        if decrypt_choice == 'y':
            try:
                decrypted = encryption.decrypt_data(encrypted_data)
                if isinstance(decrypted, bytes):
                    decrypted = decrypted.decode()
                print(f"\nДешифрованные данные: {decrypted}")
            except Exception as e:
                print(f"Ошибка дешифрования: {e}")
   
    else:
        print("Неверный выбор!")

if __name__ == "__main__":
    main()