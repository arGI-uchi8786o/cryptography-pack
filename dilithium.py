import os
import base64
import json
from dilithium_py.ml_dsa import ML_DSA_44

class DilithiumSignature:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """Генерация ключей Dilithium"""
        self.public_key, self.private_key = ML_DSA_44.keygen()
        return self.public_key, self.private_key

    def sign_data(self, data):
        """Подпись данных с помощью Dilithium"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        signature = ML_DSA_44.sign(self.private_key, data)
        return signature

    def verify_signature(self, signature, data, public_key):
        """Проверка подписи"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return ML_DSA_44.verify(public_key, data, signature)

    def export_keys_base64(self):
        """Экспорт ключей в base64"""
        public_b64 = base64.b64encode(self.public_key).decode()
        private_b64 = base64.b64encode(self.private_key).decode()
        return {
            'public_key': public_b64,
            'private_key': private_b64
        }

def main():
    print("ПРЕДУПРЕЖДЕНИЕ: Это постквантовый алгоритм подписи Dilithium.")
    print("Используйте для практических целей с осторожностью.")
    print("=" * 80)

    dilithium = DilithiumSignature()
    dilithium.generate_keys()

    keys = dilithium.export_keys_base64()
    print("Сгенерированные ключи (base64):")
    print(f"Публичный ключ: {keys['public_key'][:100]}...")
    print(f"Приватный ключ: {keys['private_key'][:100]}...")
    print()

    choice = input("Что подписать (1 - файл, 2 - ваша строка)?: ").strip()

    if choice == "1":
        file_path = input("Введи имя файла: ").strip()
        if not os.path.exists(file_path):
            print("Файл не существует!")
            return

        with open(file_path, 'rb') as f:
            data = f.read()

        print("Подписываю файл...")
        signature = dilithium.sign_data(data)
        signature_b64 = base64.b64encode(signature).decode()

        sig_file = file_path + '.dilithium'
        with open(sig_file, 'w') as f:
            json.dump({
                'signature': signature_b64,
                'public_key': keys['public_key']
            }, f, indent=2)

        print(f"Подпись сохранена: {sig_file}")

        # Демонстрация проверки
        verify_choice = input("Проверить подпись? (y/n): ").lower()
        if verify_choice == 'y':
            if dilithium.verify_signature(signature, data, dilithium.public_key):
                print("Подпись верна!")
            else:
                print("Подпись неверна!")

    elif choice == "2":
        message = input("Введите строку для подписи: ")
        print("Подписываю строку...")
        signature = dilithium.sign_data(message)
        signature_b64 = base64.b64encode(signature).decode()

        print("Подпись (base64):")
        print(signature_b64)

        # Демонстрация проверки
        verify_choice = input("Проверить подпись? (y/n): ").lower()
        if verify_choice == 'y':
            if dilithium.verify_signature(signature, message, dilithium.public_key):
                print("Подпись верна!")
            else:
                print("Подпись неверна!")

    else:
        print("Неверный выбор!")

if __name__ == "__main__":
    main()
