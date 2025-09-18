# ==================
# ПОЖАЛУЙСТА: НЕ ЮЗАТЬ ЭТО ДЛЯ ПРАКТИКИ
# СЕРЬЕЗНО. ЭТО НЕБЕЗОПАСНО.

import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class RSA4096Encryption:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """Генерация ключей RSA-4096"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        self.public_key = self.private_key.public_key()
        return self.public_key, self.private_key

    def encrypt_data(self, data):
        """Шифрование данных с помощью RSA-4096"""
        if isinstance(data, str):
            data = data.encode()

        if len(data) > 512:  # RSA-4096 can encrypt up to ~512 bytes
            raise ValueError("Данные слишком большие для шифрования RSA-4096 (макс 512 байт)")
        

        ciphertext = self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt_data(self, ciphertext):
        """Дешифрование данных с помощью RSA-4096"""
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def export_keys_base64(self):
        """Экспорт ключей в base64"""
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {
            'private_key': base64.b64encode(private_pem).decode(),
            'public_key': base64.b64encode(public_pem).decode()
        }

def main():
    print("ПРЕДУПРЕЖДЕНИЕ: Это шифрование RSA-4096 предназначено только для образовательных целей и не подходит для реальной защиты данных!")
    print("Это 'музейный' пример, демонстрирующий работу RSA. Не используйте для защиты чувствительной информации.")
    print("=" * 80)

    rsa_enc = RSA4096Encryption()
    rsa_enc.generate_keys()

    keys = rsa_enc.export_keys_base64()
    print("Сгенерированные ключи (base64):")
    print(f"Публичный ключ: {keys['public_key'][:100]}...")
    print(f"Приватный ключ: {keys['private_key'][:100]}...")
    print()

    message = input("Введите сообщение для шифрования (макс 512 байт): ").strip()
    if len(message.encode('utf-8')) > 512:
        print("Сообщение слишком длинное!")
        return

    print("Шифрую...")
    ciphertext = rsa_enc.encrypt_data(message)
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    print(f"Зашифрованное сообщение (base64): {ciphertext_b64}")
    print()

    decrypt_choice = input("Расшифровать сообщение? (y/n): ").lower()
    if decrypt_choice == 'y':
        print("Расшифровываю...")
        decrypted = rsa_enc.decrypt_data(ciphertext)
        if isinstance(decrypted, bytes):
            decrypted = decrypted.decode()
        print(f"Расшифрованное сообщение: {decrypted}")

if __name__ == "__main__":
    main()
