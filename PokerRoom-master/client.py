import socket
import time
import threading
import sys
import pickle
import base64
import struct
from random import randrange
from math import ceil, sqrt
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# ============================================================================
# КОНСТАНТЫ (ИСПРАВЛЕНО - без пробелов!)
# ============================================================================
LIMIT = 999999999
SECRET_KEY_MAX_NUMBER = 99999
PORT = 12345
BROADCAST_PORT = 12345
DISCOVERY_TIMEOUT = 3

# Типы сообщений (УДАЛЕНЫ все пробелы!)
POKER_MESSAGE_TYPE_INIT = "init"
POKER_MESSAGE_TYPE_PLAY = "play"
POKER_MESSAGE_TYPE_FOLD = "fold"
POKER_MESSAGE_TYPE_WATCH = "watch"
POKER_MESSAGE_TYPE_UPDATE = "update"
POKER_MESSAGE_TYPE_INVALID_BET = "invalid-bet"
POKER_MESSAGE_TYPE_SPEC = "spectator"
POKER_MESSAGE_TYPE_SIT = "spectator-sit"
POKER_MESSAGE_TYPE_VALID_BET = "valid-bet"
POKER_MESSAGE_TYPE_TABLE = "table"
POKER_MESSAGE_TYPE_TURN = "turn"
POKER_MESSAGE_TYPE_CARDS = "cards"
POKER_MESSAGE_TYPE_CHIPS = "chips"
POKER_MESSAGE_TYPE_INIT_RESPONSE = "init-response"
POKER_MESSAGE_TYPE_ANNOUNCE = "announce"
POKER_MESSAGE_TYPE_CLIENTCAST = "clientcast"
POKER_MESSAGE_TYPE_CHECK = "check"
POKER_MESSAGE_TYPE_CALL = "call"
POKER_MESSAGE_TYPE_RAISE = "raise"
POKER_MESSAGE_TYPE_GAME_END = "game-end"
POKER_MESSAGE_TYPE_WINNER = "winner"

# ============================================================================
# КРИПТОГРАФИЯ (СОВРЕМЕННАЯ - cryptography вместо pyDes)
# ============================================================================
def is_prime(num: int) -> bool:
    if num == 2:
        return True
    if num % 2 == 0 or num < 2:
        return False
    for i in range(3, ceil(sqrt(num)), 2):
        if num % i == 0:
            return False
    return True

def generate_prime(limit: int) -> int:
    while True:
        candidate = randrange(2, limit)
        if is_prime(candidate):
            return candidate

def encrypt_message(data: bytes, key: int) -> bytes:
    """Шифрование AES-256"""
    try:
        key_bytes = str(key).encode().ljust(32, b'\0')[:32]
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # PKCS7 padding
        padding_len = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_len] * padding_len)
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + encrypted)
    except Exception as e:
        print(f"Encryption error: {e}")
        return data

def decrypt_message(data: bytes, key: int) -> bytes:
    """Дешифрование AES-256"""
    try:
        key_bytes = str(key).encode().ljust(32, b'\0')[:32]
        decoded = base64.b64decode(data)
        iv = decoded[:16]
        encrypted = decoded[16:]
        
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        
        # Remove PKCS7 padding
        padding_len = decrypted[-1]
        return decrypted[:-padding_len]
    except Exception as e:
        print(f"Decryption error: {e}")
        return data

# ============================================================================
# TCP ФРЕЙМИНГ (length-prefix), чтобы recv не возвращал "половину" сообщения
# ============================================================================
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed while reading")
        buf.extend(chunk)
    return bytes(buf)

def send_framed(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)

def recv_framed(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length < 0:
        raise ValueError("Negative framed message length")
    return _recv_exact(sock, length)

# ============================================================================
# СЕТЕВЫЕ ФУНКЦИИ
# ============================================================================
def get_local_ip():
    """Получить локальный IP адрес клиента"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_broadcast_address(local_ip):
    """Вычислить broadcast адрес для подсети"""
    try:
        ip_parts = local_ip.split('.')
        broadcast = '.'.join(ip_parts[:3]) + '.255'
        return broadcast
    except:
        return "255.255.255.255"

# ============================================================================
# КЛАССЫ СООБЩЕНИЙ
# ============================================================================
class PokerMessage(object):
    def __init__(self, type, username=None, data=None, g=None, p=None, A=None,
                 table=None, chips=None, order=None, total_bet=None,
                 high_bet=None, spectating=None, key=None, winner=None, 
                 current_bet=None, players=None):
        self.type_ = type
        self.username_ = username
        self.data_ = data
        self.g_ = g
        self.p_ = p
        self.A_ = A
        self.table_ = table
        self.chips_ = chips
        self.order_ = order
        self.total_bet_ = total_bet
        self.high_bet_ = high_bet
        self.spectating_ = spectating
        self.key_ = key
        self.winner_ = winner
        self.current_bet_ = current_bet
        self.players_ = players

    def __str__(self):
        return f"Type: {self.type_}, Username: {self.username_}, Chips: {self.chips_}"

# ============================================================================
# ОБНАРУЖЕНИЕ СЕРВЕРОВ В LAN
# ============================================================================
class ServerDiscovery:
    def __init__(self):
        self.found_servers = []
        self.lock = threading.Lock()
        
    def broadcast_discovery(self, username, timeout=DISCOVERY_TIMEOUT):
        """Отправить UDP broadcast для поиска серверов"""
        with self.lock:
            self.found_servers = []
        local_ip = get_local_ip()
        broadcast_addr = get_broadcast_address(local_ip)
        
        print(f"🔍 Локальный IP: {local_ip}")
        print(f"📡 Broadcast адрес: {broadcast_addr}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(1)

        msg = PokerMessage(POKER_MESSAGE_TYPE_CLIENTCAST, username=username)
        data = pickle.dumps(msg)

        addresses = [
            (broadcast_addr, BROADCAST_PORT),
            ('255.255.255.255', BROADCAST_PORT),
            ('127.0.0.1', BROADCAST_PORT)
        ]
        
        for addr in addresses:
            try:
                sock.sendto(data, addr)
                print(f"📤 Отправлен запрос на {addr[0]}")
            except Exception as e:
                print(f"❌ Ошибка отправки: {e}")

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response, addr = sock.recvfrom(4096)
                server_msg = pickle.loads(response)
                if server_msg.type_ == POKER_MESSAGE_TYPE_ANNOUNCE:
                    with self.lock:
                        server_ip = addr[0]
                        if server_ip not in [s['ip'] for s in self.found_servers]:
                            self.found_servers.append({
                                'ip': server_ip,
                                'port': BROADCAST_PORT,
                                'time': time.time()
                            })
                            print(f"✅ Найден сервер: {server_ip}:{BROADCAST_PORT}")
            except socket.timeout:
                break
            except Exception as e:
                continue

        sock.close()
        return self.found_servers
    
    def connect_to_server(self, ip, port):
        """Проверка подключения к серверу"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.close()
            return True
        except:
            return False

# ============================================================================
# GUI КЛИЕНТ С ИСПРАВЛЕННОЙ ЛОГИКОЙ
# ============================================================================
class PokerClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🎰 Poker Room - LAN Client")
        self.root.geometry("1100x800")
        self.root.configure(bg='#1a1a2e')
        self.root.resizable(True, True)
        
        # Сетевые переменные
        self.socket = None
        self.username = "player1"
        self.server_ip = "127.0.0.1"
        self.server_port = PORT
        self.key = None
        self.encrypted_data = None
        self.chips = 10000
        self.current_bet = 0
        self.order = 0
        self.cards = []
        self.cards_on_table = []
        self.game_started = False
        self.my_turn = False
        self.private_a = None
        self.server_g = None
        self.server_p = None
        self.high_bet = 0
        self.total_pot = 0
        self.players_count = 0
        self.round_number = 0
        self.game_active = False
        self.consecutive_checks = 0
        self.check_turns_into_fold = False
        self.players_snapshot = []
        
        # Discovery
        self.discovery = ServerDiscovery()
        self.local_ip = get_local_ip()
        
        # Состояние игры
        self.game_state = {
            'phase': 'waiting',
            'can_check': False,
            'can_call': False,
            'min_bet': 0,
            'max_bet': 0
        }
        
        # Создание интерфейса
        self.create_main_menu()
        self.create_combinations_reference()
        self.create_game_interface()
        self.show_main_menu()
        
    def create_main_menu(self):
        """Создание главного меню"""
        self.main_frame = tk.Frame(self.root, bg='#1a1a2e')
        
        title = tk.Label(self.main_frame, text="🎰 POKER ROOM", 
                        font=("Arial", 36, "bold"), bg='#1a1a2e', fg='#00d9ff')
        title.pack(pady=30)
        
        ip_info = tk.Label(self.main_frame, text=f"🖥️ Ваш IP: {self.local_ip}", 
                          font=("Arial", 12), bg='#1a1a2e', fg='#888888')
        ip_info.pack(pady=5)
        
        name_frame = tk.Frame(self.main_frame, bg='#1a1a2e')
        name_frame.pack(pady=15)
        
        tk.Label(name_frame, text="Имя игрока:", font=("Arial", 13), 
                bg='#1a1a2e', fg='white').pack(side=tk.LEFT, padx=5)
        
        self.name_entry = tk.Entry(name_frame, font=("Arial", 13), width=20)
        self.name_entry.insert(0, "player1")
        self.name_entry.pack(side=tk.LEFT, padx=5)
        
        btn_frame = tk.Frame(self.main_frame, bg='#1a1a2e')
        btn_frame.pack(pady=30)
        
        self.auto_connect_btn = tk.Button(btn_frame, text="🔍 Авто-поиск серверов", 
                                          font=("Arial", 14, "bold"), bg='#00d9ff', fg='#1a1a2e',
                                          width=28, command=self.auto_discover_servers,
                                          relief=tk.RAISED, bd=3)
        self.auto_connect_btn.pack(pady=10)
        
        self.manual_connect_btn = tk.Button(btn_frame, text="📡 Подключиться вручную", 
                                            font=("Arial", 14, "bold"), bg='#ff6b6b', fg='white',
                                            width=28, command=self.show_manual_connect,
                                            relief=tk.RAISED, bd=3)
        self.manual_connect_btn.pack(pady=10)

        self.rules_btn = tk.Button(
            btn_frame,
            text="📚 Справочник комбинаций",
            font=("Arial", 14, "bold"),
            bg='#2ed573',
            fg='white',
            width=28,
            command=self.show_combinations_reference,
            relief=tk.RAISED,
            bd=3
        )
        self.rules_btn.pack(pady=10)
        
        self.status_label = tk.Label(self.main_frame, text="Готов к подключению", 
                                    font=("Arial", 11), bg='#1a1a2e', fg='#888888')
        self.status_label.pack(pady=20)
        
        log_frame = tk.LabelFrame(self.main_frame, text="📋 События подключения", 
                                 font=("Arial", 11, "bold"), bg='#16213e', fg='#00d9ff')
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, 
                                                  font=("Consolas", 10), bg='#0f0f23', fg='#00ff00',
                                                  wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_combinations_reference(self):
        """Отдельная страница-справочник покерных комбинаций."""
        self.reference_frame = tk.Frame(self.root, bg='#1a1a2e')

        title = tk.Label(
            self.reference_frame,
            text="📚 Справочник покерных комбинаций",
            font=("Arial", 28, "bold"),
            bg='#1a1a2e',
            fg='#00d9ff'
        )
        title.pack(pady=20)

        subtitle = tk.Label(
            self.reference_frame,
            text="Комбинации перечислены от сильнейшей к слабейшей",
            font=("Arial", 12),
            bg='#1a1a2e',
            fg='#bbbbbb'
        )
        subtitle.pack(pady=5)

        ref_text = scrolledtext.ScrolledText(
            self.reference_frame,
            font=("Consolas", 12),
            bg='#0f0f23',
            fg='#ffffff',
            wrap=tk.WORD
        )
        ref_text.pack(fill=tk.BOTH, expand=True, padx=25, pady=15)

        combinations_help = (
            "1) Royal Flush (Роял-флеш)\n"
            "   A K Q J T одной масти. Самая сильная комбинация.\n\n"
            "2) Straight Flush (Стрит-флеш)\n"
            "   Пять последовательных карт одной масти.\n\n"
            "3) Four of a Kind (Каре)\n"
            "   Четыре карты одного ранга.\n\n"
            "4) Full House (Фулл-хаус)\n"
            "   Тройка + пара.\n\n"
            "5) Flush (Флеш)\n"
            "   Пять карт одной масти (не по порядку).\n\n"
            "6) Straight (Стрит)\n"
            "   Пять последовательных карт разных мастей.\n\n"
            "7) Three of a Kind (Сет / Тройка)\n"
            "   Три карты одного ранга.\n\n"
            "8) Two Pair (Две пары)\n"
            "   Две разные пары.\n\n"
            "9) One Pair (Одна пара)\n"
            "   Две карты одного ранга.\n\n"
            "10) High Card (Старшая карта)\n"
            "    Если комбинаций выше нет, сравнивается старшая карта.\n\n"
            "Подсказка:\n"
            "- При одинаковом типе комбинации побеждает больший ранг/кикер.\n"
            "- В этой игре учитывается лучшая комбинация из 5 карт из доступных 7."
        )
        ref_text.insert(tk.END, combinations_help)
        ref_text.config(state=tk.DISABLED)

        back_btn = tk.Button(
            self.reference_frame,
            text="← Назад в меню",
            font=("Arial", 12, "bold"),
            bg='#57606f',
            fg='white',
            command=self.show_main_menu,
            relief=tk.RAISED,
            bd=2
        )
        back_btn.pack(pady=10)
        
    def create_game_interface(self):
        """Создание игрового интерфейса"""
        self.game_frame = tk.Frame(self.root, bg='#1a1a2e')
        
        top_frame = tk.Frame(self.game_frame, bg='#16213e', height=70)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        info_left = tk.Frame(top_frame, bg='#16213e')
        info_left.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.info_label = tk.Label(info_left, text="⏳ Ожидание начала игры...", 
                                  font=("Arial", 13, "bold"), bg='#16213e', fg='#00d9ff')
        self.info_label.pack(anchor=tk.W)
        
        self.pot_label = tk.Label(info_left, text="💰 Банк: $0", 
                                 font=("Arial", 12), bg='#16213e', fg='#ffd700')
        self.pot_label.pack(anchor=tk.W)
        
        info_right = tk.Frame(top_frame, bg='#16213e')
        info_right.pack(side=tk.RIGHT, padx=10, pady=10)
        
        self.chips_label = tk.Label(info_right, text="💵 Ваши фишки: $10000", 
                                   font=("Arial", 14, "bold"), bg='#16213e', fg='#2ed573')
        self.chips_label.pack(anchor=tk.E)
        
        self.bet_label = tk.Label(info_right, text="🎲 Текущая ставка: $0", 
                                 font=("Arial", 12), bg='#16213e', fg='#ffa502')
        self.bet_label.pack(anchor=tk.E)

        players_frame = tk.LabelFrame(
            self.game_frame,
            text="👥 Игроки и фишки",
            font=("Arial", 11, "bold"),
            bg='#16213e',
            fg='#00d9ff'
        )
        players_frame.pack(fill=tk.X, padx=10, pady=5)

        self.players_table = ttk.Treeview(
            players_frame,
            columns=("player", "chips", "bet", "status"),
            show="headings",
            height=4
        )
        self.players_table.heading("player", text="Игрок")
        self.players_table.heading("chips", text="Фишки")
        self.players_table.heading("bet", text="Ставка")
        self.players_table.heading("status", text="Статус")
        self.players_table.column("player", width=180, anchor=tk.W)
        self.players_table.column("chips", width=120, anchor=tk.CENTER)
        self.players_table.column("bet", width=120, anchor=tk.CENTER)
        self.players_table.column("status", width=180, anchor=tk.CENTER)
        self.players_table.pack(fill=tk.X, padx=5, pady=5)
        
        table_frame = tk.LabelFrame(self.game_frame, text="🃏 Игровой стол", 
                                   font=("Arial", 13, "bold"), bg='#0f3460', fg='#00d9ff')
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.table_cards_frame = tk.Frame(table_frame, bg='#0f3460')
        self.table_cards_frame.pack(pady=15)
        
        self.table_cards_labels = []
        for i in range(5):
            label = tk.Label(self.table_cards_frame, text="🂠", 
                           font=("Arial", 28), bg='#1a1a2e', width=4, height=3,
                           relief=tk.RAISED, bd=3, fg='#ffffff')
            label.pack(side=tk.LEFT, padx=8)
            self.table_cards_labels.append(label)
        
        separator = tk.Frame(table_frame, height=2, bg='#00d9ff')
        separator.pack(fill=tk.X, padx=20, pady=10)
        
        self.player_cards_frame = tk.Frame(table_frame, bg='#0f3460')
        self.player_cards_frame.pack(pady=15)
        
        tk.Label(self.player_cards_frame, text="🎴 Ваши карты:", 
                font=("Arial", 12, "bold"), bg='#0f3460', fg='#00d9ff').pack(pady=5)
        
        self.player_card_labels = []
        for i in range(2):
            label = tk.Label(self.player_cards_frame, text="🂠", 
                           font=("Arial", 40), bg='#1a1a2e', width=4, height=3,
                           relief=tk.RAISED, bd=3, fg='#ffffff')
            label.pack(side=tk.LEFT, padx=15)
            self.player_card_labels.append(label)
        
        action_frame = tk.Frame(self.game_frame, bg='#16213e')
        action_frame.pack(fill=tk.X, padx=10, pady=10)
        
        bet_frame = tk.LabelFrame(action_frame, text="💸 Сделать ставку", 
                                 font=("Arial", 11, "bold"), bg='#16213e', fg='#ffffff')
        bet_frame.pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        tk.Label(bet_frame, text="Сумма:", font=("Arial", 11), 
                bg='#16213e', fg='white').pack(pady=3)
        
        self.bet_entry = tk.Entry(bet_frame, font=("Arial", 12), width=10, 
                                 justify=tk.CENTER)
        self.bet_entry.pack(pady=3)
        self.bet_entry.insert(0, "100")
        
        quick_bet_frame = tk.Frame(bet_frame, bg='#16213e')
        quick_bet_frame.pack(pady=5)
        
        tk.Button(quick_bet_frame, text="Min", width=5, 
                 command=lambda: self.set_quick_bet('min')).pack(side=tk.LEFT, padx=2)
        tk.Button(quick_bet_frame, text="1/2", width=5, 
                 command=lambda: self.set_quick_bet('half')).pack(side=tk.LEFT, padx=2)
        tk.Button(quick_bet_frame, text="Max", width=5, 
                 command=lambda: self.set_quick_bet('max')).pack(side=tk.LEFT, padx=2)
        
        buttons_frame = tk.Frame(action_frame, bg='#16213e')
        buttons_frame.pack(side=tk.RIGHT, padx=10)
        
        self.check_btn = tk.Button(buttons_frame, text="✓ Check\n(Пропуск)", 
                                 font=("Arial", 11, "bold"), bg='#3498db', fg='white',
                                 width=12, height=2, command=self.check_action,
                                 relief=tk.RAISED, bd=3)
        self.check_btn.pack(pady=3)
        
        self.call_btn = tk.Button(buttons_frame, text="📞 Call\n(Уравнять)", 
                                 font=("Arial", 11, "bold"), bg='#f39c12', fg='white',
                                 width=12, height=2, command=self.call_action,
                                 relief=tk.RAISED, bd=3)
        self.call_btn.pack(pady=3)
        
        self.bet_btn = tk.Button(buttons_frame, text="💰 Bet/Raise\n(Ставка)", 
                                font=("Arial", 11, "bold"), bg='#27ae60', fg='white',
                                width=12, height=2, command=self.place_bet,
                                relief=tk.RAISED, bd=3)
        self.bet_btn.pack(pady=3)
        
        self.fold_btn = tk.Button(buttons_frame, text="❌ Fold\n(Сброс)", 
                                 font=("Arial", 11, "bold"), bg='#e74c3c', fg='white',
                                 width=12, height=2, command=self.fold_card,
                                 relief=tk.RAISED, bd=3)
        self.fold_btn.pack(pady=3)
        
        self.disable_game_buttons()
        
        game_log_frame = tk.LabelFrame(self.game_frame, text="📝 Лог игры", 
                                      font=("Arial", 11, "bold"), bg='#16213e', fg='#00d9ff')
        game_log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.game_log = scrolledtext.ScrolledText(game_log_frame, height=8, 
                                                  font=("Consolas", 10), bg='#0f0f23', fg='#00ff00',
                                                  wrap=tk.WORD)
        self.game_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.back_btn = tk.Button(self.game_frame, text="← В главное меню", 
                                 font=("Arial", 11), bg='#57606f', fg='white',
                                 command=self.show_main_menu,
                                 relief=tk.RAISED, bd=2)
        self.back_btn.pack(pady=5)

    def reset_check_button(self):
        self.check_turns_into_fold = False
        self.check_btn.config(
            text="✓ Check\n(Пропуск)",
            bg='#3498db',
            command=self.check_action
        )

    def switch_check_to_fold(self):
        self.check_turns_into_fold = True
        self.check_btn.config(
            text="❌ Fold\n(Сброс)",
            bg='#e74c3c',
            command=self.fold_card
        )
        
    def log_event(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()
        
    def log_game(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.game_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.game_log.see(tk.END)
        self.game_log.update_idletasks()

    def update_players_table(self, players, winner_name=None):
        if not players:
            return

        self.players_snapshot = players
        for item in self.players_table.get_children():
            self.players_table.delete(item)

        for p in players:
            name = p.get("name", "unknown")
            chips = p.get("chips", 0)
            current_bet = p.get("current_bet", 0)
            folded = p.get("folded", False)
            status = "Сбросил" if folded else "В игре"
            if winner_name and name == winner_name:
                status = "Победитель"

            self.players_table.insert(
                "",
                tk.END,
                values=(name, f"${chips}", f"${current_bet}", status)
            )
        
    def show_main_menu(self):
        self.game_frame.pack_forget()
        self.reference_frame.pack_forget()
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
    def show_game_interface(self):
        self.main_frame.pack_forget()
        self.reference_frame.pack_forget()
        self.game_frame.pack(fill=tk.BOTH, expand=True)

    def show_combinations_reference(self):
        self.main_frame.pack_forget()
        self.game_frame.pack_forget()
        self.reference_frame.pack(fill=tk.BOTH, expand=True)
        
    def show_manual_connect(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Подключение к серверу")
        dialog.geometry("450x250")
        dialog.configure(bg='#1a1a2e')
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (450 // 2)
        y = (dialog.winfo_screenheight() // 2) - (250 // 2)
        dialog.geometry(f"+{x}+{y}")
        
        tk.Label(dialog, text="IP адрес сервера:", font=("Arial", 11, "bold"), 
                bg='#1a1a2e', fg='white').pack(pady=8)
        
        ip_entry = tk.Entry(dialog, font=("Arial", 12), width=30)
        ip_entry.insert(0, "127.0.0.1")
        ip_entry.pack(pady=5)
        self.bind_entry_shortcuts(ip_entry)
        
        tk.Label(dialog, text="Порт:", font=("Arial", 11, "bold"), 
                bg='#1a1a2e', fg='white').pack(pady=8)
        
        port_entry = tk.Entry(dialog, font=("Arial", 12), width=10)
        port_entry.insert(0, "12345")
        port_entry.pack(pady=5)
        self.bind_entry_shortcuts(port_entry)
        
        def connect():
            self.server_ip = ip_entry.get().strip()
            try:
                self.server_port = int(port_entry.get().strip())
            except:
                messagebox.showerror("Ошибка", "Неверный порт!")
                return
            
            if not self.server_ip:
                messagebox.showerror("Ошибка", "Введите IP адрес!")
                return
            
            self.username = self.name_entry.get().strip() or "player1"
            self.connect_to_server()
            dialog.destroy()
        
        btn_frame = tk.Frame(dialog, bg='#1a1a2e')
        btn_frame.pack(pady=15)
        
        tk.Button(btn_frame, text="Подключиться", font=("Arial", 11, "bold"), 
                 bg='#00d9ff', fg='#1a1a2e', width=15, command=connect,
                 relief=tk.RAISED, bd=2).pack(side=tk.LEFT, padx=10)
        
        tk.Button(btn_frame, text="Отмена", font=("Arial", 11), 
                 bg='#57606f', fg='white', width=10, command=dialog.destroy,
                 relief=tk.RAISED, bd=2).pack(side=tk.LEFT, padx=10)

    def bind_entry_shortcuts(self, entry: tk.Entry):
        """Явные горячие клавиши буфера обмена для Windows/Linux."""
        entry.bind("<Control-a>", lambda e: (e.widget.select_range(0, tk.END), "break")[1])
        entry.bind("<Control-A>", lambda e: (e.widget.select_range(0, tk.END), "break")[1])
        entry.bind("<Control-c>", lambda e: (e.widget.event_generate("<<Copy>>"), "break")[1])
        entry.bind("<Control-C>", lambda e: (e.widget.event_generate("<<Copy>>"), "break")[1])
        entry.bind("<Control-v>", lambda e: (e.widget.event_generate("<<Paste>>"), "break")[1])
        entry.bind("<Control-V>", lambda e: (e.widget.event_generate("<<Paste>>"), "break")[1])
        entry.bind("<Control-x>", lambda e: (e.widget.event_generate("<<Cut>>"), "break")[1])
        entry.bind("<Control-X>", lambda e: (e.widget.event_generate("<<Cut>>"), "break")[1])
        entry.bind("<Shift-Insert>", lambda e: (e.widget.event_generate("<<Paste>>"), "break")[1])
        
    def auto_discover_servers(self):
        self.username = self.name_entry.get().strip() or "player1"
        self.log_event("🔍 Запуск поиска серверов в локальной сети...")
        self.status_label.config(text="🔍 Поиск серверов...")
        self.auto_connect_btn.config(state=tk.DISABLED)
        
        def discover():
            servers = self.discovery.broadcast_discovery(self.username)
            
            if servers:
                self.log_event(f"✅ Найдено серверов: {len(servers)}")
                for server in servers:
                    self.log_event(f"  → {server['ip']}:{server['port']}")
                
                for server in servers:
                    if self.discovery.connect_to_server(server['ip'], server['port']):
                        self.server_ip = server['ip']
                        self.server_port = server['port']
                        self.root.after(0, lambda: self.connect_to_server())
                        return
                
                self.root.after(0, lambda: messagebox.showwarning(
                    "Внимание", "Серверы найдены, но подключение не удалось"))
            else:
                self.root.after(0, lambda: messagebox.showinfo(
                    "Результат", "Серверы не найдены.\nПопробуйте ручное подключение."))
            
            self.root.after(0, lambda: self.auto_connect_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.status_label.config(text="Готов к подключению"))
        
        thread = threading.Thread(target=discover, daemon=True)
        thread.start()
        
    def connect_to_server(self):
        self.username = self.name_entry.get().strip() or "player1"
        
        def connect():
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(5)
                self.socket.connect((self.server_ip, self.server_port))
                self.socket.settimeout(None)
                
                self.log_event(f"✅ Подключено к {self.server_ip}:{self.server_port}")
                self.status_label.config(text=f"✅ Подключено: {self.server_ip}")
                
                recv_thread = threading.Thread(target=self.receive_messages, daemon=True)
                recv_thread.start()
                
                self.send_init_message()
                
            except ConnectionRefusedError:
                self.root.after(0, lambda: messagebox.showerror(
                    "Ошибка", "Сервер отклонил подключение"))
                self.log_event("❌ Подключение отклонено")
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    "Ошибка", f"Ошибка подключения: {str(e)}"))
                self.log_event(f"❌ Ошибка: {str(e)}")
        
        thread = threading.Thread(target=connect, daemon=True)
        thread.start()
        
    def send_init_message(self):
        g = generate_prime(LIMIT)
        p = generate_prime(LIMIT)
        a = randrange(SECRET_KEY_MAX_NUMBER)
        A = g ** a % p
        
        self.private_a = a
        self.server_g = g
        self.server_p = p
        
        msg = PokerMessage(POKER_MESSAGE_TYPE_INIT, 
                          username=self.username, g=g, p=p, A=A)
        send_framed(self.socket, pickle.dumps(msg))
        self.log_event("📤 Отправлена инициализация")
        
    def receive_messages(self):
        while True:
            try:
                data = recv_framed(self.socket)
                    
                try:
                    msg = pickle.loads(data)
                except:
                    if self.key:
                        try:
                            decrypted = decrypt_message(data, self.key)
                            msg = pickle.loads(decrypted)
                        except:
                            continue
                    else:
                        continue
                
                self.root.after(0, lambda m=msg: self.process_message(m))
                
            except Exception as e:
                self.log_event(f"❌ Ошибка получения: {str(e)}")
                break
        
        self.root.after(0, lambda: self.on_disconnect())
        
    def process_message(self, msg):
        self.log_game(f"📥 {msg.type_}: {msg}")
        
        if msg.type_ == POKER_MESSAGE_TYPE_INIT_RESPONSE:
            self.key = msg.A_ ** self.private_a % self.server_p
            self.log_event(f"🔑 Ключ сессии установлен")
            
            priv_data = "encrypt me"
            self.encrypted_data = encrypt_message(priv_data.encode(), self.key)
            play_msg = PokerMessage(POKER_MESSAGE_TYPE_PLAY, 
                                   username=self.username, data=self.encrypted_data)
            send_framed(self.socket, pickle.dumps(play_msg))
            
        elif msg.type_ == POKER_MESSAGE_TYPE_CARDS:
            # СБРОС СТАВОК НОВОЙ РУКИ
            self.current_bet = 0
            self.high_bet = 0
            self.consecutive_checks = 0
            self.reset_check_button()
            self.cards = msg.table_ if msg.table_ else []
            self.chips = msg.chips_ if msg.chips_ else 10000
            self.order = msg.order_ if msg.order_ else 0
            self.game_active = True
            self.update_player_cards()
            self.update_chips_display()
            self.bet_label.config(text="🎲 Текущая ставка: $0")
            self.log_game(f"🃏 Ваши карты: {self.cards}")
            self.log_game(f"💰 Фишки: {self.chips}, Позиция: {self.order}")
            self.show_game_interface()
            self.game_state['phase'] = 'waiting'
            
        elif msg.type_ == POKER_MESSAGE_TYPE_TABLE:
            self.cards_on_table = msg.table_ if msg.table_ else []
            self.update_table_cards()
            # Новая торговая улица (появились общие карты) => начинаем ставить "с нуля"
            # в рамках текущего betting round.
            self.current_bet = 0
            self.high_bet = 0
            self.consecutive_checks = 0
            self.reset_check_button()
            self.bet_label.config(text="🎲 Текущая ставка: $0")
            self.log_game(f"📋 Карты на столе: {self.cards_on_table}")
            
        elif msg.type_ == POKER_MESSAGE_TYPE_TURN:
            self.my_turn = True
            self.game_state['phase'] = 'betting'
            self.high_bet = msg.high_bet_ if msg.high_bet_ else 0
            self.update_game_state()
            self.enable_game_buttons()
            self.info_label.config(text="🎯 ВАШ ХОД! Сделайте ставку")
            self.info_label.config(fg='#2ed573')
            self.log_game("⏰ Ваш ход!")
            
            if self.high_bet > self.current_bet:
                call_amount = self.high_bet - self.current_bet
                self.bet_entry.delete(0, tk.END)
                self.bet_entry.insert(0, str(call_amount))
            
        elif msg.type_ == POKER_MESSAGE_TYPE_UPDATE:
            self.total_pot = msg.total_bet_ if msg.total_bet_ else 0
            self.pot_label.config(text=f"💰 Банк: ${self.total_pot}")
            if msg.players_:
                self.update_players_table(msg.players_)
            
            # Служебное обновление от сервера каждую секунду: обновляем только UI,
            # без шума в логе ставок.
            if msg.username_ == "SERVER_HEARTBEAT":
                return

            self.log_game(f"🎲 {msg.username_} сделал ставку: ${msg.chips_}")
            self.info_label.config(text=f"🎲 {msg.username_}: ${msg.chips_} | Банк: ${self.total_pot}")
            self.info_label.config(fg='#00d9ff')
            
        elif msg.type_ == POKER_MESSAGE_TYPE_VALID_BET:
            bet_amount = msg.chips_ if msg.chips_ else 0
            self.current_bet += bet_amount
            self.chips -= bet_amount
            if bet_amount > 0:
                self.consecutive_checks = 0
                self.reset_check_button()
            self.update_chips_display()
            self.bet_label.config(text=f"🎲 Ваша ставка: ${self.current_bet}")
            self.log_game(f"✅ Ставка принята: ${bet_amount}")
            
        elif msg.type_ == POKER_MESSAGE_TYPE_INVALID_BET:
            min_bet = (msg.high_bet_ - self.current_bet) if msg.high_bet_ else 0
            self.log_game(f"❌ Неверная ставка! Минимум: ${min_bet}")
            messagebox.showwarning("Ставка", f"Неверная ставка!\nНужно минимум ${min_bet}")
            self.my_turn = True
            self.enable_game_buttons()
            
        elif msg.type_ == POKER_MESSAGE_TYPE_FOLD:
            self.log_game(f"🚫 {msg.username_} сбросил карты")
            
        elif msg.type_ == POKER_MESSAGE_TYPE_GAME_END:
            self.game_active = False
            self.my_turn = False
            self.consecutive_checks = 0
            self.reset_check_button()
            self.disable_game_buttons()
            self.info_label.config(text="🏁 Раунд завершён")
            self.log_game("🏁 Раунд завершён")
            
        elif msg.type_ == POKER_MESSAGE_TYPE_WINNER:
            winner_name = msg.winner_ if msg.winner_ else "Неизвестно"
            prize = msg.chips_ if msg.chips_ else 0
            self.my_turn = False
            self.consecutive_checks = 0
            self.reset_check_button()
            self.disable_game_buttons()
            self.log_game(f"🏆 Победитель: {winner_name} выиграл ${prize}")
            # Не используем блокирующее messagebox, чтобы UI не "замирал"
            # и не терял синхронизацию перед следующей раздачей.
            self.info_label.config(text=f"🏆 Победитель: {winner_name} (+${prize})")
            self.info_label.config(fg='#ffd700')
            self.log_event(f"🏁 Раунд завершён. Победитель: {winner_name}, выигрыш: ${prize}")
            if msg.players_:
                self.update_players_table(msg.players_, winner_name=winner_name)
            
            # СБРОС КАРТ ПОСЛЕ РАУНДА
            self.cards = []
            self.cards_on_table = []
            self.current_bet = 0
            self.high_bet = 0
            self.total_pot = 0
            self.update_player_cards()
            self.update_table_cards()
            
    def update_player_cards(self):
        card_symbols = {'S': '♠', 'H': '♥', 'C': '♣', 'D': '♦'}
        
        for i, label in enumerate(self.player_card_labels):
            if i < len(self.cards) and self.cards[i]:
                card = self.cards[i]
                if isinstance(card, list) and len(card) >= 2:
                    rank = str(card[0])
                    suit = card[1]
                    suit_symbol = card_symbols.get(suit, suit)
                    label.config(text=f"{rank}{suit_symbol}", 
                               fg='#e74c3c' if suit in ['H', 'D'] else '#ffffff')
                else:
                    label.config(text="🂠", fg='#ffffff')
            else:
                label.config(text="🂠", fg='#ffffff')
                
    def update_table_cards(self):
        card_symbols = {'S': '♠', 'H': '♥', 'C': '♣', 'D': '♦'}
        
        for i, label in enumerate(self.table_cards_labels):
            if i < len(self.cards_on_table) and self.cards_on_table[i]:
                card = self.cards_on_table[i]
                if isinstance(card, list) and len(card) >= 2:
                    rank = str(card[0])
                    suit = card[1]
                    suit_symbol = card_symbols.get(suit, suit)
                    label.config(text=f"{rank}{suit_symbol}",
                               fg='#e74c3c' if suit in ['H', 'D'] else '#ffffff')
                else:
                    label.config(text="🂠", fg='#ffffff')
            else:
                label.config(text="🂠", fg='#ffffff')
                
    def update_chips_display(self):
        self.chips_label.config(text=f"💵 Ваши фишки: ${self.chips}")
        
    def update_game_state(self):
        self.game_state['can_check'] = (self.current_bet >= self.high_bet)
        self.game_state['can_call'] = (self.current_bet < self.high_bet)
        self.game_state['min_bet'] = max(1, self.high_bet - self.current_bet)
        self.game_state['max_bet'] = self.chips
        
        # Режим "есть чужое повышение": игрок может только принять/повысить/сбросить.
        if self.game_state['can_call']:
            self.check_btn.config(state=tk.DISABLED)
            self.call_btn.config(
                state=tk.NORMAL,
                text="✅ Принять\n(Ставку)",
                bg='#2980b9'
            )
            self.bet_btn.config(
                text="💚 Увеличить\n(Ставку)",
                bg='#27ae60'
            )
            self.info_label.config(text="⚠ Есть повышение: примите или увеличьте ставку")
            self.info_label.config(fg='#f39c12')
        else:
            self.check_btn.config(state=tk.NORMAL if self.game_state['can_check'] else tk.DISABLED)
            self.call_btn.config(
                state=tk.DISABLED,
                text="📞 Call\n(Уравнять)",
                bg='#f39c12'
            )
            self.bet_btn.config(
                text="💰 Bet/Raise\n(Ставка)",
                bg='#27ae60'
            )
        
    def enable_game_buttons(self):
        self.update_game_state()
        self.bet_btn.config(state=tk.NORMAL)
        self.fold_btn.config(state=tk.NORMAL)
        self.bet_entry.config(state=tk.NORMAL)
        
    def disable_game_buttons(self):
        self.bet_btn.config(state=tk.DISABLED)
        self.call_btn.config(state=tk.DISABLED)
        self.check_btn.config(state=tk.DISABLED)
        self.fold_btn.config(state=tk.DISABLED)
        self.bet_entry.config(state=tk.DISABLED)
        
    def set_quick_bet(self, bet_type):
        if not self.my_turn:
            return
            
        min_bet = self.game_state['min_bet']
        max_bet = self.game_state['max_bet']
        
        if bet_type == 'min':
            amount = min_bet
        elif bet_type == 'half':
            amount = min_bet + (max_bet - min_bet) // 2
        elif bet_type == 'max':
            amount = max_bet
        else:
            amount = min_bet
            
        self.bet_entry.delete(0, tk.END)
        self.bet_entry.insert(0, str(amount))
        
    def place_bet(self):
        if not self.my_turn:
            messagebox.showwarning("Ход", "Сейчас не ваш ход!")
            return
            
        try:
            bet = int(self.bet_entry.get().strip())
            min_bet = self.game_state['min_bet']
            max_bet = self.game_state['max_bet']
            
            if bet < min_bet:
                messagebox.showwarning("Ставка", f"Минимальная ставка: ${min_bet}")
                return
                
            if bet > max_bet:
                messagebox.showwarning("Ставка", f"Максимальная ставка: ${max_bet}")
                return

            # Если есть чужое повышение, зелёная кнопка считается именно "увеличить ставку",
            # а не "принять". Принятие должно идти через кнопку Call.
            required_to_call = self.high_bet - self.current_bet
            if required_to_call > 0 and bet <= required_to_call:
                messagebox.showwarning(
                    "Увеличить ставку",
                    f"Для увеличения введите сумму больше ${required_to_call}.\n"
                    f"Чтобы принять текущую ставку, нажмите «Принять ставку»."
                )
                return
                
            msg = PokerMessage(POKER_MESSAGE_TYPE_TURN,
                              username=self.username, data=self.encrypted_data,
                              chips=bet, order=self.order)
            send_framed(self.socket, pickle.dumps(msg))
            self.consecutive_checks = 0
            self.reset_check_button()
            self.my_turn = False
            self.disable_game_buttons()
            self.info_label.config(text="⏳ Ожидание других игроков...")
            self.info_label.config(fg='#ffa502')
            self.log_game(f"💰 Ставка ${bet} отправлена")
            
        except ValueError:
            messagebox.showerror("Ошибка", "Введите число!")
            
    def call_action(self):
        if not self.my_turn:
            return
            
        call_amount = self.high_bet - self.current_bet
        if call_amount <= 0:
            self.check_action()
            return

        # "Принять ставку" должно работать независимо от ограничений кнопки
        # "Увеличить ставку" (place_bet), поэтому отправляем call напрямую.
        msg = PokerMessage(
            POKER_MESSAGE_TYPE_TURN,
            username=self.username,
            data=self.encrypted_data,
            chips=call_amount,
            order=self.order
        )
        send_framed(self.socket, pickle.dumps(msg))
        self.consecutive_checks = 0
        self.reset_check_button()
        self.my_turn = False
        self.disable_game_buttons()
        self.info_label.config(text="⏳ Ожидание других игроков...")
        self.info_label.config(fg='#ffa502')
        self.log_game(f"✅ Вы приняли ставку: ${call_amount}")
        
    def check_action(self):
        if not self.my_turn:
            return
            
        if self.current_bet < self.high_bet:
            messagebox.showwarning("Check", "Нельзя проверить - есть ставка!")
            self.call_action()
            return
            
        msg = PokerMessage(POKER_MESSAGE_TYPE_TURN,
                          username=self.username, data=self.encrypted_data,
                          chips=0, order=self.order)
        send_framed(self.socket, pickle.dumps(msg))
        self.consecutive_checks += 1
        if self.consecutive_checks >= 2:
            self.switch_check_to_fold()
        self.my_turn = False
        self.disable_game_buttons()
        self.info_label.config(text="⏳ Ожидание других игроков...")
        self.info_label.config(fg='#ffa502')
        self.log_game("✓ Вы пропустили ход (Check)")
        
    def fold_card(self):
        if not self.my_turn:
            return
            
        if messagebox.askyesno("Fold", "Вы уверены, что хотите сбросить карты?"):
            msg = PokerMessage(POKER_MESSAGE_TYPE_FOLD,
                              username=self.username, data=self.encrypted_data, order=self.order)
            send_framed(self.socket, pickle.dumps(msg))
            self.consecutive_checks = 0
            self.reset_check_button()
            self.my_turn = False
            self.disable_game_buttons()
            self.log_game("🚫 Вы сбросили карты")
            self.info_label.config(text="❌ Вы сбросили карты")
            self.info_label.config(fg='#e74c3c')
        
    def on_disconnect(self):
        self.log_event("❌ Отключено от сервера")
        self.status_label.config(text="❌ Отключено")
        self.disable_game_buttons()
        messagebox.showinfo("Отключено", "Соединение с сервером разорвано")
        self.show_main_menu()

# ============================================================================
# ЗАПУСК ПРИЛОЖЕНИЯ
# ============================================================================
def main():
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use('clam')
    app = PokerClientGUI(root)
    
    def on_closing():
        if app.socket:
            try:
                app.socket.close()
            except:
                pass
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == '__main__':
    main()