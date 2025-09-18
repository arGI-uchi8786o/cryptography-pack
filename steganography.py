import numpy as np
from PIL import Image
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Зашифровать данные AES-256-GCM"""
    nonce = os.urandom(12)
   
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
   
    encrypted = encryptor.update(data) + encryptor.finalize()
    return nonce + encryptor.tag + encrypted

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """Расшифровать данные AES-256-GCM"""
    nonce = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
   
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
   
    return decryptor.update(ciphertext) + decryptor.finalize()

def hide_data(image_path: str, data: str, output_path: str, encrypt: bool = False) -> bool:
    """Спрятать данные в изображении"""
    try:
        # Подготовка данных
        if encrypt:
            key = os.urandom(32)  # Генерируем случайный ключ
            data_bytes = encrypt_data(data.encode(), key)
            print(f"🔑 Ключ для дешифрования: {key.hex()}")
        else:
            data_bytes = data.encode()
            key = None
       
        # Добавляем маркер и флаг шифрования
        encrypt_flag = b'\x01' if encrypt else b'\x00'
        header = b"STEG" + encrypt_flag + len(data_bytes).to_bytes(4, 'big')
        full_data = header + data_bytes
       
        # Открываем изображение
        img = Image.open(image_path)
        img = img.convert('RGB')
        pixels = np.array(img)
       
        # Проверяем вместимость
        max_data_size = (pixels.size * 3) // 8
        if len(full_data) > max_data_size:
            raise ValueError(f"Данные слишком большие. Максимум: {max_data_size} байт")
       
        # Преобразуем данные в биты
        data_bits = []
        for byte in full_data:
            bits = bin(byte)[2:].zfill(8)
            data_bits.extend([int(bit) for bit in bits])
       
        # Встраиваем данные в LSB
        data_index = 0
        for i in range(pixels.shape[0]):
            for j in range(pixels.shape[1]):
                for k in range(3):
                    if data_index < len(data_bits):
                        pixels[i, j, k] = (pixels[i, j, k] & 0xFE) | data_bits[data_index]
                        data_index += 1
       
        # Сохраняем результат
        Image.fromarray(pixels).save(output_path)
        print(f"✅ Данные спрятаны в: {output_path}")
        return True
       
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return False

def extract_data(image_path: str, key_hex: str = None) -> str:
    """Извлечь данные из изображения"""
    try:
        # Открываем изображение
        img = Image.open(image_path)
        pixels = np.array(img.convert('RGB'))
       
        # Извлекаем биты данных
        extracted_bits = []
        for i in range(pixels.shape[0]):
            for j in range(pixels.shape[1]):
                for k in range(3):
                    extracted_bits.append(pixels[i, j, k] & 1)
       
        # Преобразуем биты в байты
        extracted_bytes = bytearray()
        for i in range(0, len(extracted_bits), 8):
            if i + 8 > len(extracted_bits):
                break
            byte_bits = extracted_bits[i:i+8]
            byte_val = int(''.join(str(bit) for bit in byte_bits), 2)
            extracted_bytes.append(byte_val)
       
        # Ищем маркер начала данных
        data_start = -1
        for i in range(len(extracted_bytes) - 8):
            if extracted_bytes[i:i+4] == b'STEG':
                data_start = i + 5  # Пропускаем STEG + флаг
                break
       
        if data_start == -1:
            return "❌ Данные не найдены"
       
        # Проверяем флаг шифрования
        encrypt_flag = extracted_bytes[data_start-1] == 1
        data_length = int.from_bytes(extracted_bytes[data_start:data_start+4], 'big')
        data_bytes = bytes(extracted_bytes[data_start+4:data_start+4+data_length])
       
        if encrypt_flag:
            if not key_hex:
                key_hex = input("Введите ключ для дешифрования (hex): ").strip()
            try:
                key = bytes.fromhex(key_hex)
                decrypted = decrypt_data(data_bytes, key)
                return decrypted.decode('utf-8')
            except:
                return "❌ Неверный ключ или данные повреждены"
        else:
            return data_bytes.decode('utf-8')
           
    except Exception as e:
        return f"❌ Ошибка: {e}"

# Интерфейс
def main():
    print("🔐 СТЕГАНОГРАФИЯ")
    print("=" * 40)
   
    action = input("Действие (1 - спрятать, 2 - извлечь): ").strip()
   
    if action == "1":
        image_path = input("В какой файл вшить данные?: ").strip()
        data = input("Какую строку вшить?: ").strip()
        encrypt = input("Зашифровать AES-256-GCM? (y/n): ").strip().lower() == 'y'
        output_path = input("Куда сохранить?: ").strip()
       
        hide_data(image_path, data, output_path, encrypt)
       
    elif action == "2":
        image_path = input("Из какого файла извлечь?: ").strip()
        result = extract_data(image_path)
        print(f"📩 Результат: {result}")
       
    else:
        print("❌ Неверное действие")

if __name__ == "__main__":
    main()