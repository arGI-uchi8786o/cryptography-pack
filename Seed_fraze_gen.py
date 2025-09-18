import os
import hashlib
import secrets

def secure_shuffle(lst):
    """
    Криптографически стойкая перетасовка списка с использованием secrets
    """
    for i in range(len(lst) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        lst[i], lst[j] = lst[j], lst[i]

def load_words_from_file(filename):
    """
    Загружает слова из файла в список
    """
    words_list = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                word = line.strip()
                if word:
                    words_list.append(word)
        return words_list
    except Exception as e:
        print(f"Ошибка загрузки словаря: {e}")
        return []

# Загружаем слова из файла
RUSSIAN_WORDS = load_words_from_file('words.txt')
secure_shuffle(RUSSIAN_WORDS)
def generate_seed_phrase(word_count=12):
    """
    Генерация истинно случайной сид-фразы из русских слов
    """
    if len(RUSSIAN_WORDS) < 2048:
        raise ValueError(f"Словарь должен содержать не менее 2048 слов! Сейчас: {len(RUSSIAN_WORDS)}")
   
    # Генерируем энтропию
    entropy = secrets.token_bytes(16)
    hash_bytes = hashlib.sha256(entropy).digest()
   
    # Преобразуем в биты
    entropy_bits = ''.join([format(byte, '08b') for byte in entropy])
    checksum_bits = format(hash_bytes[0], '08b')[:4]
    total_bits = entropy_bits + checksum_bits
   
    # Разбиваем на группы по 11 бит
    indices = []
    for i in range(0, len(total_bits), 11):
        chunk = total_bits[i:i+11]
        if len(chunk) < 11:
            chunk = chunk.ljust(11, '0')
        index = int(chunk, 2)
        indices.append(index)
   
    # Выбираем слова
    seed_phrase = []
    for index in indices:
        seed_phrase.append(RUSSIAN_WORDS[index % len(RUSSIAN_WORDS)])
   
    return ' '.join(seed_phrase)

def main():
    print(len(RUSSIAN_WORDS))
    print("🇷🇺 ГЕНЕРАТОР СИД-ФРАЗ НА РУССКОМ ЯЗЫКЕ")
    print("=" * 50)
   
    if len(RUSSIAN_WORDS) < 2048:
        print(f"❌ Ошибка: В словаре только {len(RUSSIAN_WORDS)} слов, нужно минимум 2048")
        return
   
    try:
        seed_phrase = generate_seed_phrase()
       
        print("🎲 Ваша сид-фраза:")
        print("=" * 50)
        print(seed_phrase)
        print("=" * 50)
       
        words = seed_phrase.split()
        for i in range(0, len(words), 4):
            group = words[i:i+4]
            print(f"{i+1:2d}-{i+len(group):2d}: {' '.join(group)}")
       
        print("=" * 50)
        print("⚠️  Сохраните в безопасном месте! Никому не показывайте!")
           
    except Exception as e:
        print(f"❌ Ошибка: {e}")

if __name__ == "__main__":
    main()