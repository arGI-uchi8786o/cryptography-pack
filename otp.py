import secrets
import os
import base64
from pathlib import Path

def ideal_otp_encrypt(data: bytes) -> tuple[bytes, bytes]:
    """
    Идеальная эталонная реализация OTP шифрования.
    Возвращает (ключ, шифротекст)
    """
    if not data:
        return b'', b''

    # Генерация истинно случайного ключа той же длины
    key = secrets.token_bytes(len(data))

    # Шифрование XOR
    ciphertext = bytes([d ^ k for d, k in zip(data, key)])

    return key, ciphertext

def encrypt_file(filename: str):
    """Шифрование файла идеальным OTP"""
    try:
        # Чтение файла
        with open(filename, 'rb') as f:
            plaintext = f.read()

        if not plaintext:
            print("❌ Файл пустой!")
            return

        # Шифрование
        key, ciphertext = ideal_otp_encrypt(plaintext)

        # Формирование имен выходных файлов
        base_name = Path(filename).stem
        key_filename = f"{base_name}_password.enc"
        enc_filename = f"{base_name}.otp.enc"

        # Сохранение ключа и шифротекста
        with open(key_filename, 'wb') as f:
            f.write(key)

        with open(enc_filename, 'wb') as f:
            f.write(ciphertext)

        print(f"✅ Файл успешно зашифрован!")
        print(f"📁 Исходный файл: {filename} ({len(plaintext)} байт)")
        print(f"🔑 Ключ сохранен в: {key_filename}")
        print(f"🔒 Шифротекст сохранен в: {enc_filename}")
        print(f"🎯 Энтропия ключа: {calculate_entropy(key):.6f} бит/байт")

    except FileNotFoundError:
        print(f"❌ Файл '{filename}' не найден!")
    except Exception as e:
        print(f"❌ Ошибка при шифровании файла: {e}")

def encrypt_text():
    """Шифрование текста из ввода"""
    text = input("Введите текст для шифрования: ")

    if not text:
        print("❌ Текст не может быть пустым!")
        return

    plaintext = text.encode('utf-8')
    key, ciphertext = ideal_otp_encrypt(plaintext)

    print("\n" + "="*50)
    print("🔐 РЕЗУЛЬТАТ ШИФРОВАНИЯ:")
    print("="*50)
    print(f"📝 Исходный текст: {text}")
    print(f"🔑 Ключ (Base64): {base64.b64encode(key).decode('utf-8')}")
    print(f"🔒 Шифротекст (Base64): {base64.b64encode(ciphertext).decode('utf-8')}")
    print(f"📊 Длина: {len(plaintext)} байт")
    print(f"🎯 Энтропия ключа: {calculate_entropy(key):.6f} бит/байт")
    print("="*50)

def calculate_entropy(data: bytes) -> float:
    """Вычисляет энтропию Шеннона"""
    from math import log2
    if not data:
        return 0.0

    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / len(data)
            entropy -= p * log2(p)

    return entropy

def main():
    """Главная функция"""
    print("="*60)
    print("🔐 IDEAL OTP ENCRYPTOR - ЭТАЛОННАЯ РЕАЛИЗАЦИЯ OTP")
    print("="*60)
    print("1. 📁 Шифровать файл")
    print("2. ⌨️ Шифровать текст")
    print("="*60)

    while True:
        choice = input("Выберите вариант (1 или 2): ").strip()

        if choice == '1':
            filename = input("Введите имя файла для шифрования: ").strip()
            encrypt_file(filename)
            break
        elif choice == '2':
            encrypt_text()
            break
        else:
            print("❌ Неверный выбор! Введите 1 или 2.")

if __name__ == "__main__":
    main()