# Пакет Криптографии

Комплексный набор криптографических инструментов и реализаций на Python, включающий симметричное и асимметричное шифрование, постквантовую криптографию, стеганографию и многое другое.

## Возможности

### Симметричное Шифрование
- **AES-256-GCM**: Высокозащищенное симметричное шифрование с аутентификацией
- **ChaCha20**: Поточный шифр для быстрого шифрования
- **Одноразовый Блокнот (OTP)**: Теоретически невзламываемое шифрование

### Асимметричное Шифрование
- **RSA-4096**: Шифрование с открытым ключом (только для образовательных целей)

### Постквантовая Криптография
- **Dilithium**: Постквантовая схема цифровой подписи
- **Kyber-1024**: Постквантовая схема инкапсуляции ключей
- **Гибрид AES + Kyber**: Комбинирует классическое и постквантовое шифрование

### Другие Инструменты
- **Стеганография**: Скрытие данных в изображениях с использованием LSB с опциональным шифрованием
- **Argon2id**: Хеширование паролей с высокой памятью
- **Shamir's secret sharing**: Разделение секрета на доли
- **Генератор SEED фраз для кошелька**: 4664 Слов на русском.Мощная энтропия.
## Требования

- Python 3.7+
- cryptography
- numpy
- Pillow (PIL)
- colorama
- argon2-cffi
- dilithium_py
- kyber_py
- pycryptodome

## Установка

1. Клонируйте или скачайте репозиторий
2. Установите зависимости:
```bash
pip install cryptography numpy pillow colorama argon2-cffi pycryptodome
```

Для постквантовых модулей может потребоваться установка дополнительных пакетов:
```bash
pip install dilithium_py kyber_py
```

## Использование

### Шифрование AES-256-GCM
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

key = secrets.token_bytes(32)
nonce = secrets.token_bytes(12)
cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(b"ваши данные") + encryptor.finalize()
```

### Стеганография
```python
from steganography import hide_data, extract_data

# Скрыть данные в изображении
hide_data("image.png", "секретное сообщение", "output.png", encrypt=True)

# Извлечь данные
message = extract_data("output.png")
```

### RSA-4096
```python
from rsa_4096 import RSA4096Encryption

rsa = RSA4096Encryption()
rsa.generate_keys()
ciphertext = rsa.encrypt_data("сообщение")
plaintext = rsa.decrypt_data(ciphertext)
```

### Одноразовый Блокнот
```python
from otp import ideal_otp_encrypt

key, ciphertext = ideal_otp_encrypt(b"открытый текст")
```

### Подпись Dilithium
```python
from dilithium import DilithiumSignature

dilithium = DilithiumSignature()
dilithium.generate_keys()
signature = dilithium.sign_data("сообщение")
is_valid = dilithium.verify_signature(signature, "сообщение", dilithium.public_key)
```

### Гибридное Шифрование (AES + Kyber)
```python
from AES256GCM_KYBER1024 import HybridEncryption

hybrid = HybridEncryption()
encrypted = hybrid.encrypt_data("данные", use_signature=True)
decrypted = hybrid.decrypt_data(encrypted)
```

## Предупреждение

Некоторые модули (например, RSA-4096) предоставлены только для образовательных целей и не должны использоваться для защиты чувствительных данных в производственной среде. Всегда используйте хорошо проверенные криптографические библиотеки для реальных приложений.

## Лицензия

GPLv3

## Вклад

Не стесняйтесь вносить улучшения или дополнительные криптографические реализации.

