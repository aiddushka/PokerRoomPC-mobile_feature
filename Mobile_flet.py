import flet as ft
import socket
import threading
import pickle
import struct
import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Константы из ваших файлов ---
PORT = 12345
SECRET_KEY_MAX_NUMBER = 99999
LIMIT = 999999999

POKER_MESSAGE_TYPE_INIT = "init"
POKER_MESSAGE_TYPE_PLAY = "play"
POKER_MESSAGE_TYPE_FOLD = "fold"
POKER_MESSAGE_TYPE_UPDATE = "update"
POKER_MESSAGE_TYPE_CARDS = "cards"

class PokerMessage:
    def __init__(self, message_type, username=None, data=None, A=None, order=None):
        self.message_type = message_type
        self.username = username
        self.data = data
        self.A = A
        self.order = order

def send_framed(sock, payload):
    header = struct.pack('!I', len(payload))
    sock.sendall(header + payload)

def receive_framed(sock):
    try:
        header = sock.recv(4)
        if not header: return None
        length = struct.unpack('!I', header)[0]
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk: return None
            data += chunk
        return data
    except:
        return None

# --- Класс для работы с шифрованием ---
class PokerCrypto:
    def __init__(self):
        self.b = os.urandom(16).hex()[:8] # Случайное число для DH
        self.shared_key = None
        self.cipher_key = None

    def generate_A(self, order):
        # Эмуляция вашей логики вычисления A
        from math import sqrt
        val = int(self.b, 16) % SECRET_KEY_MAX_NUMBER
        return pow(val, order) % LIMIT

    def compute_shared_key(self, other_A, order):
        val = int(self.b, 16) % SECRET_KEY_MAX_NUMBER
        self.shared_key = pow(other_A, val) % LIMIT
        # Формируем 32-байтный ключ для AES
        key_str = str(self.shared_key).zfill(32)
        self.cipher_key = key_str.encode('utf-8')[:32]

    def encrypt(self, plaintext):
        if not self.cipher_key: return plaintext
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.cipher_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, ciphertext):
        if not self.cipher_key: return ciphertext
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self.cipher_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(actual_ciphertext) + decryptor.finalize()).decode('utf-8')

def main(page: ft.Page):
    page.title = "Poker Mobile Encrypted"
    page.theme_mode = ft.ThemeMode.DARK
    
    # Состояние приложения
    state = {
        "socket": None,
        "crypto": PokerCrypto(),
        "username": "",
        "connected": False,
        "order": 1
    }

    log_view = ft.ListView(expand=True, spacing=5)
    status_text = ft.Text("Поиск сервера...", color="orange")
    
    def append_log(msg, color="white"):
        log_view.controls.append(ft.Text(f"[{time.strftime('%H:%M')}] {msg}", color=color))
        page.update()

    # --- Логика автоподключения ---
    def connect_worker():
        while not state["connected"]:
            try:
                state["socket"] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                state["socket"].settimeout(5)
                # В реальной мобильной сети тут лучше использовать ввод IP или Discovery
                state["socket"].connect(("127.0.0.1", PORT)) 
                state["connected"] = True
                status_text.value = "Подключено к серверу"
                status_text.color = "green"
                append_log("Соединение установлено. Ожидание авторизации...", "green")
                
                # Запускаем основной цикл прослушивания
                threading.Thread(target=receiver_thread, daemon=True).start()
                break
            except Exception:
                status_text.value = "Сервер не найден. Повтор..."
                page.update()
                time.sleep(3)

    def receiver_thread():
        while True:
            data = receive_framed(state["socket"])
            if not data:
                append_log("Связь с сервером потеряна", "red")
                state["connected"] = False
                connect_worker() # Пробуем переподключиться
                break
            
            msg = pickle.loads(data)
            handle_message(msg)

    def handle_message(msg):
        if msg.message_type == POKER_MESSAGE_TYPE_INIT:
            # Рукопожатие: получаем A от сервера и вычисляем общий ключ
            state["order"] = msg.order if msg.order else 1
            state["crypto"].compute_shared_key(msg.A, state["order"])
            append_log(f"Шифрование установлено (Order: {state['order']})", "blue")
            
        elif msg.message_type == POKER_MESSAGE_TYPE_UPDATE:
            text = state["crypto"].decrypt(msg.data) if isinstance(msg.data, bytes) else msg.data
            append_log(f"Сервер: {text}")

    # --- UI и действия ---
    name_input = ft.TextField(label="Имя игрока", value="MobilePlayer")
    
    def on_join(e):
        state["username"] = name_input.value
        # Отправляем INIT с нашим публичным ключом A
        my_A = state["crypto"].generate_A(state["order"])
        init_msg = PokerMessage(POKER_MESSAGE_TYPE_INIT, username=state["username"], A=my_A)
        send_framed(state["socket"], pickle.dumps(init_msg))
        
        # Переключаем на игровой экран
        game_screen()

    def game_screen():
        page.clean()
        page.add(
            ft.Text(f"Игрок: {state['username']}", size=20, weight="bold"),
            status_text,
            ft.Container(log_view, height=400, border=ft.border.all(1, "grey"), border_radius=10, padding=10),
            ft.Row([
                ft.ElevatedButton("FOLD", on_click=lambda _: send_action(POKER_MESSAGE_TYPE_FOLD), bgcolor="red"),
                ft.ElevatedButton("PLAY", on_click=lambda _: send_action(POKER_MESSAGE_TYPE_PLAY), bgcolor="green")
            ])
        )

    def send_action(m_type):
        # Пример отправки зашифрованного действия
        encrypted_info = state["crypto"].encrypt(f"Action by {state['username']}")
        msg = PokerMessage(m_type, username=state["username"], data=encrypted_info)
        send_framed(state["socket"], pickle.dumps(msg))

    # Начальный экран
    page.add(
        ft.Column([
            ft.Text("Poker Mobile", size=30),
            status_text,
            name_input,
            ft.ElevatedButton("Войти в лобби", on_click=on_join)
        ])
    )

    # Запуск поиска сервера в фоне
    threading.Thread(target=connect_worker, daemon=True).start()

ft.app(target=main)
