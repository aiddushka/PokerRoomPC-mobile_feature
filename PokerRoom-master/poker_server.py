import sys
import socket
import struct
import threading
import time
import argparse
import re
import select
from math import sqrt, log, ceil
from random import randrange
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import pickle
import os
import game_utils
from itertools import combinations

SIZE = 4096
PORT = 12345
LIMIT = 999999999
SECRET_KEY_MAX_NUMBER = 99999

# ============================================================================
# КОНСТАНТЫ (ИСПРАВЛЕНО - без пробелов!)
# ============================================================================
POKER_MESSAGE_TYPE_INIT = "init"
POKER_MESSAGE_TYPE_PLAY = "play"
POKER_MESSAGE_TYPE_FOLD = "fold"
POKER_MESSAGE_TYPE_UPDATE = "update"
POKER_MESSAGE_TYPE_INVALID_BET = "invalid-bet"
POKER_MESSAGE_TYPE_VALID_BET = "valid-bet"
POKER_MESSAGE_TYPE_WATCH = "watch"
POKER_MESSAGE_TYPE_SPEC = "spectator"
POKER_MESSAGE_TYPE_SIT = "spectator-sit"
POKER_MESSAGE_TYPE_TURN = "turn"
POKER_MESSAGE_TYPE_TABLE = "table"
POKER_MESSAGE_TYPE_CARDS = "cards"
POKER_MESSAGE_TYPE_CHIPS = "chips"
POKER_MESSAGE_TYPE_INIT_RESPONSE = "init-response"
POKER_MESSAGE_TYPE_ANNOUNCE = "announce"
POKER_MESSAGE_TYPE_CLIENTCAST = "clientcast"
POKER_MESSAGE_TYPE_GAME_END = "game-end"
POKER_MESSAGE_TYPE_WINNER = "winner"
POKER_MESSAGE_TYPE_CHECK = "check"
POKER_MESSAGE_TYPE_CALL = "call"

IS_WINDOWS = (len(re.findall('[Ww]in', sys.platform)) != 0)

# ============================================================================
# КРИПТОГРАФИЯ (СОВРЕМЕННАЯ - AES вместо pyDes)
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
    try:
        key_bytes = str(key).encode().ljust(32, b'\0')[:32]
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padding_len = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_len] * padding_len)
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + encrypted)
    except Exception as e:
        print(f"Encryption error: {e}")
        return data

def decrypt_message(data: bytes, key: int) -> bytes:
    try:
        key_bytes = str(key).encode().ljust(32, b'\0')[:32]
        decoded = base64.b64decode(data)
        iv = decoded[:16]
        encrypted = decoded[16:]
        
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        
        padding_len = decrypted[-1]
        return decrypted[:-padding_len]
    except Exception as e:
        print(f"Decryption error: {e}")
        return data

# ============================================================================
# TCP ФРЕЙМИНГ (length-prefix)
# ============================================================================
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed while reading")
        buf.extend(chunk)
    return bytes(buf)

def send_payload(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)

def recv_payload(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length < 0:
        raise ValueError("Negative framed message length")
    return _recv_exact(sock, length)

# ============================================================================
# КЛАССЫ СООБЩЕНИЙ
# ============================================================================
class PokerMessage(object):
    def __init__(self, type, username=None, data=None, g=None, p=None, A=None, 
                 table=None, chips=None, active=None, order=None, total_bet=None, 
                 high_bet=None, key=None, winner=None, current_bet=None, players=None):
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
        self.key_ = key
        self.winner_ = winner
        self.current_bet_ = current_bet
        self.players_ = players

    def __str__(self):
        return "Type: {}, Username: {}, Chips: {}, Order: {}".format(
            self.type_, self.username_, self.chips_, self.order_)

# ============================================================================
# КЛАСС ИГРОКА
# ============================================================================
class Player(object):
    def __init__(self, name: str, ip: str, g=None, p=None, B=None, spectating=None, 
                 order=None, chips=None, high_bet=None, folded=None):
        self.name_ = name
        self.ip_ = ip
        self.g_ = g if g is not None else generate_prime(LIMIT)
        self.p_ = p if p is not None else generate_prime(LIMIT)
        self.a_ = randrange(SECRET_KEY_MAX_NUMBER)
        self.B_ = B
        self.calculate_A()
        self.cards = []
        self.socket_ = None
        self.chips_ = chips if chips is not None else 10000
        self.order_ = order
        self.table_id = None
        self.high_bet_ = high_bet if high_bet is not None else 0
        self.folded_ = folded if folded is not None else False
        self.spectating_ = spectating if spectating is not None else False
        self.current_bet_ = 0
        if self.B_ is not None:
            self.calculate_key()

    def calculate_A(self):
        self.A_ = self.g_ ** self.a_ % self.p_

    def calculate_key(self):
        self.key_ = self.B_ ** self.a_ % self.p_

    def reset_round(self):
        """Сброс состояния для нового раунда"""
        self.cards = []
        self.folded_ = False
        self.high_bet_ = 0
        self.current_bet_ = 0

    def __str__(self):
        return "Player: uname: {}, ip: {}, chips: {}".format(
            self.name_, self.ip_, self.chips_)

# ============================================================================
# КЛАСС ЗРИТЕЛЯ
# ============================================================================
class Spectator(object):
    def __init__(self, name: str, ip: str):
        self.name_ = name
        self.ip_ = ip
        self.socket_ = None

# ============================================================================
# КЛАСС ИГРЫ
# ============================================================================
class Game(object):
    def __init__(self, table_id, nbr_of_players: int = 0):
        self.table_id_ = table_id
        self.deck_ = game_utils.get_deck(shuffle_deck=True)
        self.player_dict_ = {}
        self.spect_dict_ = {}
        self.player_order_list_ = []
        self.table_ = []
        self.is_started_ = False
        self.waiting_list_ = []
        self.max_active_players_ = 4
        self.CAN_START_GAME = False
        self.PLAYER_COUNT = 0
        self.TOTAL_PLAYERS = 0
        self.LOCK_WAIT = False
        self.current_round = 0
        self.total_pot = 0
        self.high_bet = 0
        self.heartbeat_period_sec = 1

        # Периодическая отправка состояния клиентам (heartbeat update).
        self._heartbeat_thread = threading.Thread(target=self.state_heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

    def seat_available(self):
        return len(self.player_order_list_) < self.max_active_players_

    def parse_raw_msg(self, payload: bytes) -> PokerMessage:
        return pickle.loads(payload)

    def get_players_snapshot(self):
        snapshot = []
        for uname in self.player_order_list_:
            if uname in self.player_dict_:
                p = self.player_dict_[uname]
                snapshot.append({
                    "name": p.name_,
                    "chips": p.chips_,
                    "folded": p.folded_,
                    "current_bet": p.current_bet_,
                    "status": "В игре" if not p.folded_ else "Сбросил",
                })

        for wp in self.waiting_list_:
            snapshot.append({
                "name": wp.name_,
                "chips": wp.chips_,
                "folded": False,
                "current_bet": 0,
                "status": "В очереди",
            })

        for sname in self.spect_dict_:
            sp = self.spect_dict_[sname]
            snapshot.append({
                "name": sp.name_,
                "chips": getattr(sp, "chips_", 0),
                "folded": False,
                "current_bet": 0,
                "status": "Зритель",
            })
        return snapshot

    def promote_waiting_players(self):
        """Пересадить игроков из очереди за стол, если есть места."""
        while self.seat_available() and len(self.waiting_list_) > 0:
            player = self.waiting_list_.pop(0)
            if player.name_ in self.player_dict_:
                continue
            self.player_dict_[player.name_] = player
            self.player_order_list_.append(player.name_)
            self.PLAYER_COUNT = len(self.player_dict_)
            print("Promoted from queue: {}".format(player.name_))

    def state_heartbeat_loop(self):
        """Раз в секунду отправляет клиентам текущее состояние стола."""
        while True:
            try:
                if len(self.player_dict_) > 0:
                    hb_msg = PokerMessage(
                        POKER_MESSAGE_TYPE_UPDATE,
                        username="SERVER_HEARTBEAT",
                        chips=0,
                        total_bet=self.total_pot,
                        high_bet=self.high_bet,
                        players=self.get_players_snapshot(),
                    )
                    self.broadcast_to_all(hb_msg)
            except Exception as e:
                print("Heartbeat error: {}".format(e))
            time.sleep(self.heartbeat_period_sec)

    def add_player(self, player: Player):
        if player.spectating_:
            self.spect_dict_[player.name_] = player
            print("Added spectator {}".format(player.name_))
            return

        if self.PLAYER_COUNT == 0 and len(self.waiting_list_) == 0:
            StartGame = threading.Thread(target=self.StartGameThread)
            StartGame.daemon = True
            StartGame.start()

        if self.is_started_ or not self.seat_available():
            if player.name_ not in [p.name_ for p in self.waiting_list_]:
                self.waiting_list_.append(player)
                print("Queued player {}".format(player.name_))
            return

        print("Adding player {}".format(player.name_))
        self.player_dict_[player.name_] = player
        self.player_order_list_.append(player.name_)
        self.PLAYER_COUNT = len(self.player_dict_)
        
        if not self.is_started_:
            # Раздача карт новому игроку
            self.deck_, player.cards = game_utils.draw_cards_from_deck(self.deck_, 2)
            player.chips_ = 10000
            player.order_ = self.PLAYER_COUNT - 1
            player.folded_ = False
            player.current_bet_ = 0
            player.high_bet_ = 0
            
            print("Drawn cards for {} => {}".format(player.name_, player.cards))
            
            # Отправка карт игроку
            cards_msg = PokerMessage(POKER_MESSAGE_TYPE_CARDS, 
                                    table=player.cards, 
                                    chips=player.chips_, 
                                    order=player.order_)
            cards_msg_bin = pickle.dumps(cards_msg)
            encrypted_msg = encrypt_message(cards_msg_bin, player.key_)
            send_payload(player.socket_, encrypted_msg)
            
            # Уведомление зрителей
            for sname in self.spect_dict_:
                spectator = self.spect_dict_[sname]
                spec_msg = PokerMessage(POKER_MESSAGE_TYPE_CARDS, 
                                       username=player.name_, 
                                       table=player.cards)
                send_payload(spectator.socket_, pickle.dumps(spec_msg))
        
        if len(self.player_order_list_) >= 2 and not self.is_started_:
            print("Game has {} players. Ready to start.".format(self.PLAYER_COUNT))
            self.TOTAL_PLAYERS = len(self.player_order_list_)
            self.CAN_START_GAME = True

    def StartGameThread(self):
        while True:
            # Автозапуск нового раунда, пока за столом минимум 2 игрока.
            # Это позволяет игре идти непрерывно, а не останавливаться после 1 раздачи.
            if len(self.player_order_list_) >= 2 and not self.is_started_:
                self.start_game()
            time.sleep(1)

    def table_update(self):
        """Отправить обновление карт на столе"""
        table_msg = PokerMessage(POKER_MESSAGE_TYPE_TABLE, table=self.table_)
        table_msg_bin = pickle.dumps(table_msg)
        
        for uname in self.player_dict_:
            player = self.player_dict_[uname]
            if not player.folded_:
                send_payload(player.socket_, table_msg_bin)
        
        for sname in self.spect_dict_:
            spectator = self.spect_dict_[sname]
            send_payload(spectator.socket_, table_msg_bin)

    def start_game(self):
        """Начать новый раунд игры"""
        print("\n========== НОВЫЙ РАУНД ==========")
        
        self.is_started_ = True
        self.current_round = 0
        self.total_pot = 0
        self.high_bet = 0
        self.table_ = []
        
        # Сброс состояния игроков
        for uname in self.player_dict_:
            player = self.player_dict_[uname]
            player.reset_round()
            player.current_bet_ = 0
            
            # Раздача новых карт
            self.deck_, player.cards = game_utils.draw_cards_from_deck(self.deck_, 2)
            print("Player {} got cards: {}".format(player.name_, player.cards))
            
            # Отправка карт
            cards_msg = PokerMessage(POKER_MESSAGE_TYPE_CARDS, 
                                    table=player.cards, 
                                    chips=player.chips_, 
                                    order=player.order_)
            cards_msg_bin = pickle.dumps(cards_msg)
            encrypted_msg = encrypt_message(cards_msg_bin, player.key_)
            send_payload(player.socket_, encrypted_msg)
        
        # Раунды торговли (3 раунда)
        cards_on_table = []
        for round_num in range(3):
            self.current_round = round_num
            
            # Выкладка карт на стол
            if round_num == 0:
                self.deck_, new_cards = game_utils.draw_cards_from_deck(self.deck_, 3)
                self.table_.extend(new_cards)
                cards_on_table.extend(new_cards)
            else:
                self.deck_, new_cards = game_utils.draw_cards_from_deck(self.deck_, 1)
                self.table_.extend(new_cards)
                cards_on_table.extend(new_cards)
            
            print("Карты на столе: {}".format(self.table_))
            self.table_update()

            # Перед каждой торговой улицей (flop/turn/river) сбрасываем размер текущей ставки
            # у игроков. `total_pot` при этом накапливается, а `high_bet` внутри betting_round
            # будет пересчитан заново.
            for uname in self.player_dict_:
                player = self.player_dict_[uname]
                player.current_bet_ = 0
            
            # Торговля
            if not self.betting_round():
                break
        
        # Определение победителя
        self.determine_winner()
        
        # Подготовка к следующему раунду
        self.is_started_ = False
        self.table_ = []
        self.deck_ = game_utils.get_deck(shuffle_deck=True)
        
        print("========== РАУНД ЗАВЕРШЁН ==========\n")

    def betting_round(self):
        """Раунд торговли"""
        players_active = [p for p in self.player_dict_.values() if not p.folded_]
        if len(players_active) <= 1:
            return False

        # Максимальная ставка в текущем торговом раунде (в терминах "текущей ставки игрока").
        # Важно: `TURN` обязано прийти даже при high_bet == 0,
        # иначе раунд закончится без торговли.
        self.high_bet = 0

        first_pass = True
        while True:
            for uname in list(self.player_dict_.keys()):
                player = self.player_dict_[uname]
                if player.folded_:
                    continue

                # Первый проход просим всех (даже если current_bet == high_bet),
                # дальше - только тех, кто отстаёт.
                if first_pass or player.current_bet_ < self.high_bet:
                    turn_msg = PokerMessage(
                        POKER_MESSAGE_TYPE_TURN,
                        username=uname,
                        high_bet=self.high_bet,
                    )
                    print(f"[TURN]: send to {player.name_} high_bet={self.high_bet} curr_bet={player.current_bet_}")
                    send_payload(player.socket_, pickle.dumps(turn_msg))

                    self.LOCK_WAIT = True
                    while self.LOCK_WAIT:
                        try:
                            data = recv_payload(player.socket_)
                            client_msg = self.parse_raw_msg(data)
                            print(f"[TURN]: recv from {player.name_} type={client_msg.type_} chips={client_msg.chips_}")
                            self.process_bet(player, client_msg)
                        except Exception as e:
                            print("Error receiving bet: {}".format(e))
                            self.LOCK_WAIT = False
                            break

                    if player.folded_:
                        self.broadcast_fold(player)
                        players_active = [p for p in self.player_dict_.values() if not p.folded_]
                        if len(players_active) <= 1:
                            return False

            players_active = [p for p in self.player_dict_.values() if not p.folded_]
            # Завершаем торговлю, когда все активные игроки сравнялись с high_bet.
            if players_active and all(p.current_bet_ == self.high_bet for p in players_active):
                return True

            first_pass = False

    def process_bet(self, player, msg):
        """Обработка ставки игрока"""
        print(f"[BET]: from {player.name_} msg={msg.type_} chips={msg.chips_} order={getattr(msg, 'order_', None)} high_bet={self.high_bet} curr_bet={player.current_bet_}")
        if msg.type_ == POKER_MESSAGE_TYPE_TURN:
            bet_amount = msg.chips_ if msg.chips_ else 0
            
            if bet_amount == 0:  # Check
                if player.current_bet_ >= self.high_bet:
                    self.LOCK_WAIT = False
                    return
                else:
                    # Нельзя проверить, нужно уравнять
                    bet_amount = self.high_bet - player.current_bet_
            
            # Серверная проверка минимума ставки (только когда игрок отстаёт).
            # Здесь `bet_amount` трактуется как "добавить сверх текущей ставки игрока".
            required_to_call = self.high_bet - player.current_bet_
            if required_to_call > 0 and bet_amount < required_to_call:
                print(f"[BET]: invalid (too small) player={player.name_} add={bet_amount} required={required_to_call}")
                invalid_msg = PokerMessage(
                    POKER_MESSAGE_TYPE_INVALID_BET,
                    high_bet=self.high_bet,
                    chips=0,
                )
                send_payload(player.socket_, pickle.dumps(invalid_msg))

                turn_msg = PokerMessage(
                    POKER_MESSAGE_TYPE_TURN,
                    username=player.name_,
                    high_bet=self.high_bet,
                )
                send_payload(player.socket_, pickle.dumps(turn_msg))
                return

            # Проверка валидности ставки
            if bet_amount > player.chips_:
                print(f"[BET]: invalid (not enough chips) player={player.name_} add={bet_amount} chips={player.chips_}")
                invalid_msg = PokerMessage(POKER_MESSAGE_TYPE_INVALID_BET, 
                                          high_bet=self.high_bet,
                                          chips=0)
                send_payload(player.socket_, pickle.dumps(invalid_msg))
                
                turn_msg = PokerMessage(POKER_MESSAGE_TYPE_TURN, 
                                       username=player.name_,
                                       high_bet=self.high_bet)
                send_payload(player.socket_, pickle.dumps(turn_msg))
                return
            
            # Применение ставки
            player.chips_ -= bet_amount
            player.current_bet_ += bet_amount
            self.total_pot += bet_amount
            
            if player.current_bet_ > self.high_bet:
                self.high_bet = player.current_bet_
                print(f"[BET]: new high_bet={self.high_bet} by {player.name_}")
            
            # Подтверждение ставки
            valid_msg = PokerMessage(POKER_MESSAGE_TYPE_VALID_BET, 
                                    username=player.name_,
                                    chips=bet_amount,
                                    total_bet=self.total_pot,
                                    players=self.get_players_snapshot())
            send_payload(player.socket_, pickle.dumps(valid_msg))
            
            # Уведомление других игроков
            update_msg = PokerMessage(POKER_MESSAGE_TYPE_UPDATE, 
                                     username=player.name_,
                                     chips=bet_amount,
                                     total_bet=self.total_pot,
                                     players=self.get_players_snapshot())
            self.broadcast_to_all(update_msg)
            print(f"[BET]: accepted {player.name_} add={bet_amount} curr_bet={player.current_bet_} pot={self.total_pot}")
            
            self.LOCK_WAIT = False
            
        elif msg.type_ == POKER_MESSAGE_TYPE_FOLD:
            player.folded_ = True
            self.LOCK_WAIT = False
            print(f"[FOLD]: {player.name_} folded")

    def broadcast_fold(self, player):
        """Уведомить всех о сбросе карт"""
        fold_msg = PokerMessage(POKER_MESSAGE_TYPE_FOLD, username=player.name_)
        self.broadcast_to_all(fold_msg)

    def broadcast_to_all(self, msg):
        """Отправить сообщение всем игрокам и зрителям"""
        msg_bin = pickle.dumps(msg)
        
        for uname in self.player_dict_:
            p = self.player_dict_[uname]
            if not p.folded_:
                send_payload(p.socket_, msg_bin)
        
        for sname in self.spect_dict_:
            spectator = self.spect_dict_[sname]
            send_payload(spectator.socket_, msg_bin)

    def determine_winner(self):
        """Определить победителя раунда"""
        players_active = [p for p in self.player_dict_.values() if not p.folded_]
        
        if len(players_active) == 1:
            # Все сбросили кроме одного
            winner = players_active[0]
            winner.chips_ += self.total_pot
            print("Победитель (fold): {} выиграл ${}".format(winner.name_, self.total_pot))
        else:
            # Сравнение комбинаций
            winner = self.compare_hands(players_active)
            winner.chips_ += self.total_pot
            print("Победитель (hands): {} выиграл ${}".format(winner.name_, self.total_pot))
        
        # Уведомление о победителе
        winner_msg = PokerMessage(POKER_MESSAGE_TYPE_WINNER, 
                                 username=winner.name_,
                                 winner=winner.name_,
                                 chips=self.total_pot,
                                 players=self.get_players_snapshot())
        self.broadcast_to_all(winner_msg)
        
        # Уведомление о конце раунда
        end_msg = PokerMessage(POKER_MESSAGE_TYPE_GAME_END)
        self.broadcast_to_all(end_msg)

    def compare_hands(self, players):
        """Сравнить комбинации карт игроков"""
        best_player = players[0] if players else None
        best_hand = None

        for player in players:
            all_cards = player.cards + self.table_
            player_best_hand = None

            # Hold'em: у игрока 2 карты + 5 карт на столе (всего 7),
            # победа считается по лучшей комбинации из любых 5 карт.
            for combo in combinations(all_cards, 5):
                hand_rank = game_utils.check_hand_rank(list(combo))
                if player_best_hand is None:
                    player_best_hand = hand_rank
                    continue

                if hand_rank["rank"] > player_best_hand["rank"] or (
                    hand_rank["rank"] == player_best_hand["rank"]
                    and hand_rank["score"] > player_best_hand["score"]
                ):
                    player_best_hand = hand_rank

            if player_best_hand is None:
                continue

            if best_hand is None:
                best_hand = player_best_hand
                best_player = player
                continue

            if player_best_hand["rank"] > best_hand["rank"] or (
                player_best_hand["rank"] == best_hand["rank"]
                and player_best_hand["score"] > best_hand["score"]
            ):
                best_hand = player_best_hand
                best_player = player

        return best_player if best_player is not None else players[0]

# ============================================================================
# КЛАСС СЕРВЕРА
# ============================================================================
class GameServer(object):
    def __init__(self, host, port, uname, targetport):
        ip = socket.gethostbyname(socket.gethostname())
        HOST = ip
        print("Server host: " + HOST)
        
        self.host_ = host if host else '0.0.0.0'
        self.port_ = port
        self.targetport_ = targetport
        self.uname_ = uname
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.sock.bind((self.host_, self.port_))
            print("Bound to {}:{}".format(self.host_, self.port_))
        except OSError as osErr:
            if osErr.errno == 99:
                print("[ERROR]: Cannot assign requested address.")
                sys.exit(1)
        
        self.sock.settimeout(.3)
        
        self.broadcast_listener_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.broadcast_listener_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.broadcast_listener_sock.bind(('', self.port_))
        except OSError as osErr:
            if osErr.errno == 99:
                print("[ERROR]: Cannot assign requested address.")
                sys.exit(1)

        self.running_ = False
        self.main_thread_ = None
        self.bcast_listener_thread_ = None
        self.game_dict_ = {}
        self.user_dict_ = {}
        self.player_dict_ = {}
        self.spectator_dict_ = {}
        self.broadcast_period_ = 30

    def start(self):
        self.stop()
        print("[INFO]: Launching gameserver listener...")
        self.running_ = True
        
        self.bcast_listener_thread_ = threading.Thread(target=self.bcast_listener)
        self.bcast_listener_thread_.daemon = True
        self.bcast_listener_thread_.start()
        
        self.main_thread_ = threading.Thread(target=self.listen)
        self.main_thread_.daemon = True
        self.main_thread_.start()
        
        self.broadcast()

    def stop(self):
        if self.running_:
            print("[INFO]: Halting gameserver...")
            self.running_ = False
            if self.main_thread_:
                self.main_thread_.join(timeout=2)
            if self.bcast_listener_thread_:
                self.bcast_listener_thread_.join(timeout=2)

    def broadcast(self):
        print("[INFO]: Broadcasting...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        announce_message = self.construct_message(POKER_MESSAGE_TYPE_ANNOUNCE)

        try:
            sock.sendto(announce_message, ('<broadcast>', self.port_))
            sock.sendto(announce_message, ('255.255.255.255', self.port_))
        except Exception as e:
            print("Broadcast error: {}".format(e))
        
        if self.running_:
            thr = threading.Timer(self.broadcast_period_, self.broadcast)
            thr.daemon = True
            thr.start()

    def bcast_listener(self):
        print("[INFO]: Broadcast listener started.")
        self.broadcast_listener_sock.setblocking(0)
        
        while self.running_:
            try:
                result = select.select([self.broadcast_listener_sock], [], [], 1)
                if result[0]:
                    (msg, address) = self.broadcast_listener_sock.recvfrom(SIZE)
                    peer_ip = address[0]
                    
                    poker_message = self.parse_raw_msg(msg)
                    
                    if peer_ip == self.host_:
                        continue
                    
                    if poker_message.type_ == POKER_MESSAGE_TYPE_CLIENTCAST:
                        try:
                            # Ответ должен быть UDP (клиент ждёт recvfrom на том же сокете).
                            response = self.construct_message(POKER_MESSAGE_TYPE_ANNOUNCE)
                            self.broadcast_listener_sock.sendto(response, address)
                            print("[INFO]: Sent UDP announce to {}:{}".format(address[0], address[1]))
                        except Exception as e:
                            print("[ERROR]: UDP announce failed: {}".format(e))
            except Exception as e:
                pass

    def listen(self):
        print("[INFO]: GameServer listener started.")
        self.sock.listen(5)
        
        while self.running_:
            try:
                sock, address = self.sock.accept()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running_:
                    print("Accept error: {}".format(e))
                continue
            
            print("Connected to {}".format(address))
            sock.settimeout(None)
            
            thread = threading.Thread(target=self.listen_to_client, args=(sock, address))
            thread.daemon = True
            thread.start()

    def listen_to_client(self, sock, address):
        print("Talking to client @{}".format(address))
        
        while self.running_:
            try:
                data = recv_payload(sock)
                client_msg = self.parse_raw_msg(data)
                
                if client_msg.type_ == POKER_MESSAGE_TYPE_INIT:
                    player = self.add_user(client_msg, address[0])
                    if player is False:
                        sock.close()
                        return
                    
                    response_message = self.construct_message(
                        POKER_MESSAGE_TYPE_INIT_RESPONSE, player.A_)
                    send_payload(sock, response_message)
                    
                elif client_msg.type_ == POKER_MESSAGE_TYPE_PLAY:
                    player = self.add_player(client_msg, address[0])
                    if player is False:
                        sock.close()
                        return
                    
                    player.socket_ = sock
                    game = self.get_available_game()
                    game.add_player(player)
                    break

                elif client_msg.type_ == POKER_MESSAGE_TYPE_SPEC:
                    player = self.add_user(client_msg, address[0])
                    if player is False:
                        sock.close()
                        return
                    
                    response_message = self.construct_message(
                        POKER_MESSAGE_TYPE_INIT_RESPONSE, player.A_)
                    send_payload(sock, response_message)

                elif client_msg.type_ == POKER_MESSAGE_TYPE_SIT:
                    player = self.add_player(client_msg, address[0])
                    if player is False:
                        sock.close()
                        return
                    
                    player.spectating_ = True
                    player.socket_ = sock
                    game = self.get_available_game()
                    game.add_player(player)
                    break

            except Exception as e:
                print("Client error @{}: {}".format(address, e))
                return

    def add_user(self, client_message: PokerMessage, ip) -> Player or bool:
        if client_message.username_ in [None, ""]:
            return False
        
        key = str(ip + "-" + client_message.username_)
        if key in self.user_dict_:
            return self.user_dict_[key]
        
        user = Player(client_message.username_, ip,
                     client_message.g_, client_message.p_, client_message.A_, 
                     client_message.spectating_)
        self.user_dict_[key] = user
        return user

    def add_player(self, client_message: PokerMessage, ip) -> Player or bool:
        if client_message.username_ in [None, ""]:
            return False
        
        key = str(ip + "-" + client_message.username_)
        if key in self.player_dict_:
            print("[WARNING]: {} already in player list.".format(key))
            return False
        
        if key in self.user_dict_:
            self.player_dict_[key] = self.user_dict_[key]
            return self.player_dict_[key]
        
        return False

    def construct_message(self, message_type: str, data=None) -> bytes:
        if message_type == POKER_MESSAGE_TYPE_INIT_RESPONSE:
            message = PokerMessage(message_type, A=data)
        else:
            message = PokerMessage(message_type, data=data)
        return pickle.dumps(message)

    def parse_raw_msg(self, payload: bytes) -> PokerMessage:
        return pickle.loads(payload)

    def get_available_game(self):
        for table_id in self.game_dict_:
            if self.game_dict_[table_id].seat_available():
                return self.game_dict_[table_id]
        
        game = Game(len(self.game_dict_))
        self.game_dict_[len(self.game_dict_)] = game
        return game

# ============================================================================
# ЗАПУСК
# ============================================================================
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--host", type=str, default='')
    parser.add_argument("-p", "--port", type=int, default=PORT)
    parser.add_argument("-u", "--uname", type=str, default='server1')
    parser.add_argument("-tp", "--targetport", type=str, default='12345')
    args = vars(parser.parse_args())

    host, port, uname, tport = args['host'], args['port'], args['uname'], int(args['targetport'])

    gameserver = GameServer(host, port, uname, tport)
    gameserver.start()
    
    print("Server running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down server...")
        gameserver.stop()