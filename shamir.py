import secrets
import hashlib
import os

class ShamirSecretSharing:
    def __init__(self, prime=None):
        # Используем большой простое число для поля
        if prime is None:
            # 2^256 - 189 (большое простое)
            self.prime = 2**256 - 189
        else:
            self.prime = prime

    def _mod_inverse(self, a, m):
        """Вычисление обратного элемента по модулю"""
        m0, y, x = m, 0, 1
        if m == 1:
            return 0
        while a > 1:
            q = a // m
            m, a = a % m, m
            y, x = x - q * y, y
        if x < 0:
            x += m0
        return x

    def _eval_polynomial(self, coeffs, x):
        """Вычисление значения полинома в точке x"""
        result = 0
        for coeff in reversed(coeffs):
            result = (result * x + coeff) % self.prime
        return result

    def _interpolate(self, points, x=0):
        """Интерполяция Лагранжа для восстановления секрета"""
        result = 0
        for i, (xi, yi) in enumerate(points):
            term = yi
            for j, (xj, _) in enumerate(points):
                if i != j:
                    # term *= (x - xj) / (xi - xj)
                    numerator = (x - xj) % self.prime
                    denominator = (xi - xj) % self.prime
                    denominator_inv = self._mod_inverse(denominator, self.prime)
                    term = (term * numerator * denominator_inv) % self.prime
            result = (result + term) % self.prime
        return result

    def split_secret(self, secret, n, k):
        """
        Разделение секрета на n долей, для восстановления нужно k долей

        Args:
            secret: Секрет (bytes или str)
            n: Общее количество долей
            k: Минимальное количество долей для восстановления

        Returns:
            Список кортежей (x, share)
        """
        if isinstance(secret, str):
            secret = secret.encode('utf-8')

        # Хешируем секрет для получения числа
        secret_hash = hashlib.sha256(secret).digest()
        secret_int = int.from_bytes(secret_hash, 'big') % self.prime

        if secret_int == 0:
            secret_int = 1  # Избегаем нулевого секрета

        # Генерируем коэффициенты полинома (степень k-1)
        coeffs = [secret_int] + [secrets.randbelow(self.prime) for _ in range(k-1)]

        # Вычисляем доли
        shares = []
        for x in range(1, n+1):
            y = self._eval_polynomial(coeffs, x)
            shares.append((x, y))

        return shares

    def reconstruct_secret(self, shares, original_secret=None):
        """
        Восстановление секрета из долей

        Args:
            shares: Список кортежей (x, share)
            original_secret: Оригинальный секрет для проверки (опционально)

        Returns:
            Восстановленный секрет (bytes)
        """
        if len(shares) < 2:
            raise ValueError("Нужно минимум 2 доли для восстановления")

        # Восстанавливаем секрет
        secret_int = self._interpolate(shares)

        # Преобразуем обратно в bytes
        secret_bytes = secret_int.to_bytes((secret_int.bit_length() + 7) // 8, 'big')

        # Если есть оригинал, проверяем
        if original_secret:
            if isinstance(original_secret, str):
                original_secret = original_secret.encode('utf-8')
            original_hash = hashlib.sha256(original_secret).digest()
            reconstructed_hash = hashlib.sha256(secret_bytes).digest()
            if original_hash != reconstructed_hash:
                raise ValueError("Восстановленный секрет не совпадает с оригиналом")

        return secret_bytes

def main():
    print("🔐 Shamir's Secret Sharing")
    print("=" * 40)
    shamir = ShamirSecretSharing()

    choise = input("Что нужно - востановить секрет/разделить(востановить - 1 разделить - 2)")

    if choise == '1':
        selected_shares = []
        for i in range(k):
            x = int(input(f"Введите x для доли {i+1}: ").strip())
            y = int(input(f"Введите y для доли {i+1}: ").strip())
            selected_shares.append((x, y))


        try:
            reconstructed = shamir.reconstruct_secret(selected_shares, secret)
            print(f"✅ Восстановленный секрет: {reconstructed.decode('utf-8', errors='ignore')}")
        except Exception as e:
            print(f"❌ Ошибка восстановления: {e}")
    
    elif choise == '2':
        secret = input("Введите секрет: ").strip()
        n = int(input("Общее количество долей (n): ").strip())
        k = int(input("Минимальное количество долей для восстановления (k): ").strip())

        if k > n:
            print("❌ k не может быть больше n!")
            return
        

        print("\nГенерация долей...")
        shares = shamir.split_secret(secret, n, k)
        
        print("Доли:")
        for x, y in shares:
            print(f"Доля {x}: {y}")
            print(f"\nДля восстановления нужно минимум {k} долей из {n}")

    

if __name__ == "__main__":
    main()
