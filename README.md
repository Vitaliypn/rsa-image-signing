# Індивідуальне завдання: Основи захисту інформації

## Опис

Я реалізував проєкт цифрового підпису зображення за допомогою RSA-ключів.  
Мета проєкту — навчитися створювати, вбудовувати та перевіряти цифрові підписи в графічних файлах, при цьому забезпечуючи, щоб підписані зображення виглядали і відкривалися як звичайні.

---

## Реалізовані версії

- **Базова версія**: Підпис додано в кінець файлу (JPEG).  
  (файли: `sign_image.py`, `verify_signature.py`)

- **Покращена версія**: Підпис захований у **метаданих PNG-файлу** (без втрат).  
  (файли: `sign_image_exif.py`, `verify_signature_exif.py`)

---

## Використані технології

- Мова програмування: Python 3
- Бібліотеки:
  - `cryptography` — для роботи з RSA-ключами та підписами
  - `Pillow` — для обробки зображень
  - `piexif` — для роботи з EXIF-даними (у базовій версії)
  
Все встановлюється через `pip install`.

---

## Як працює рішення

1. Генерується пара ключів RSA (4096 біт).
2. Оригінальне зображення підписується приватним ключем:
   - У базовій версії підпис дописується в кінець файлу.
   - У покращеній версії підпис вшивається в текстові метадані PNG.
3. При перевірці:
   - Зчитується вбудований підпис.
   - Заново обчислюється хеш зображення.
   - Валідується підпис за допомогою публічного ключа.

Підписані зображення відкриваються стандартними засобами Windows без змін у відображенні.

---

## Огляд потенційного застосування

Цифровий підпис зображень дозволяє підтверджувати їхню справжність і захищати від підробки.  
Такий підхід може використовуватись:
- у медіа-компаніях для захисту авторських прав на зображення;
- в юридичній практиці для фіксації доказів;
- в обміні чутливою інформацією, де важливо гарантувати автентичність файлу.

---

## Структура проєкту

```
OZI/
├── convert_to_png.py              # Конвертація в PNG
├── generate_keys.py                # Генерація ключів RSA
├── private_key.pem                 # Приватний ключ
├── public_key.pem                  # Публічний ключ
├── sign_image.py                   # Підписування файлу, простий варіант (кінець файлу)
├── verify_signature.py             # Перевірка підпису базового варіанту
├── sign_image_exif.py               # Підписування файлу, приховування у метадані PNG
├── verify_signature_exif.py         # Перевірка підпису через метадані PNG
├── test_image.jpg                   # Тестове JPEG-зображення
├── test.jpg                         # Тестове JPEG-зображення
├── test.png                         # Тестове PNG-зображення
├── signed_image_basic.jpg           # Підписане базове зображення
├── signed_image_exif.jpg            # Підписане зображення з EXIF
├── signed_test_exif.jpg             # Підписане тестове JPEG з EXIF
├── signed_test.png                  # Підписане тестове PNG-зображення
└── README.md                        # Документація
```

---

## Приклади команд для запуску

**Генерація ключів:**
```bash
python3 generate_keys.py
```

**Підпис базовим способом:**
```bash
python3 sign_image.py test_image.jpg private_key.pem signed_image_basic.jpg
```

**Перевірка базового підпису:**
```bash
python3 verify_signature.py signed_image_basic.jpg public_key.pem
```

**Підпис покращеним способом через метадані PNG:**
```bash
python3 sign_image_exif.py test.png private_key.pem signed_test.png
```

**Перевірка підпису через метадані PNG:**
```bash
python3 verify_signature_exif.py signed_test.png public_key.pem
```

---

## Додатково

У покращеній версії підпис зберігається у текстових метаданих файлу PNG, що робить його прихованим і практично непомітним для звичайних користувачів.

---

## Автор

Роботу виконав: **Віталій Палійчук**

Дата виконання: **26 квітня 2025 р.**
