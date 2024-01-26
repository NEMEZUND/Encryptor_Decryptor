import PySimpleGUI as sg  # Импорт библиотеки PySimpleGUI для создания графического интерфейса
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Импорт функции для создания ключа
from cryptography.hazmat.primitives import hashes  # Импорт хэш-функций
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Импорт шифровальных алгоритмов
from base64 import urlsafe_b64encode, urlsafe_b64decode  # Импорт функций для работы с Base64
import os  # Импорт библиотеки для работы с операционной системой
import tkinter as tk  # Импорт библиотеки Tkinter для работы с буфером обмена

def get_clipboard_text():
    # Функция для получения текста из буфера обмена
    root = tk.Tk()
    clipboard_text = root.clipboard_get()
    root.destroy()
    return clipboard_text

def derive_key(password, salt):
    # Функция для вычисления ключа на основе пароля и соли
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
    )
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt(text, password):
    # Функция для шифрования текста
    salt = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB8(salt), backend=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
    return urlsafe_b64encode(salt + ciphertext).decode()

def decrypt(ciphertext, password):
    # Функция для дешифрования текста
    data = urlsafe_b64decode(ciphertext.encode())
    salt = data[:16]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB8(salt), backend=None)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(data[16:]) + decryptor.finalize()
    return plaintext.decode()

def main():
    # Определение темы оформления для графического интерфейса
    sg.theme('DarkGrey3')

    # Определение компонентов интерфейса
    layout = [
        [sg.Text('Введите текст для шифрования:')],
        [sg.Multiline(size=(50, 5), key='input_text', enable_events=True, autoscroll=True)],
        [sg.Button('Вставить из буфера обмена'), sg.Button('Очистить')],
        [sg.Text('Введите пароль для шифрования:')],
        [sg.InputText(key='password')],
        [sg.Button('Зашифровать'), sg.Button('Расшифровать')],
        [sg.Text('Результат:')],
        [sg.Multiline(size=(50, 5), key='output_text', enable_events=True, autoscroll=True)],
        [sg.Button('Сохранить в файл')],
    ]

    # Создание окна
    window = sg.Window('AES Шифратор/Дешифратор', layout)

    while True:
        # Обработка событий окна
        event, values = window.read()

        if event == sg.WINDOW_CLOSED:
            break

        if event == 'Вставить из буфера обмена':
            # Вставка текста из буфера обмена в верхнее окно
            clipboard_text = get_clipboard_text()
            if clipboard_text:
                window['input_text'].update(clipboard_text)

        if event == 'Очистить':
            # Очистка верхнего окна
            window['input_text'].update('')

        if event == 'Зашифровать':
            # Получение текста и пароля, шифрование, обновление нижнего окна
            text = values['input_text']
            password = values['password']
            encrypted_text = encrypt(text, password)
            window['output_text'].update(encrypted_text)

        if event == 'Расшифровать':
            # Получение текста и пароля, дешифрование, обновление нижнего окна
            text = values['input_text']
            password = values['password']
            try:
                decrypted_text = decrypt(text, password)
                window['output_text'].update(decrypted_text)
            except Exception as e:
                sg.popup_error(f"Ошибка расшифровки: {str(e)}")

        if event == 'Сохранить в файл':
            # Сохранение расшифрованного текста в файл
            output_text = values['output_text']
            file_path = sg.popup_get_file('Выберите файл для сохранения', save_as=True, default_extension=".txt",
                                          file_types=(("Text Files", "*.txt"),))
            if file_path:
                with open(file_path, 'w') as file:
                    file.write(output_text)

    # Закрытие окна после завершения работы
    window.close()

if __name__ == '__main__':
    main()
