import json
import logging
import os
import requests
import base64
from telebot import TeleBot, types
import html
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

# --- Настройки ---
BOT_TOKEN = "{{token}}"
TMP_DIR = "/tmp/postman_collections"
TEMPLATES_DIR = "/home/**/templates"
APILAYER_API_KEY = "{{APILAYER-KEY}}"
LOG_FILE = "/home/**/postman_bot.log"
PRIVATE_KEY_PATH = "/**/private_key.pem"
# --- Конец настроек ---

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# Создаем бота
bot = TeleBot(BOT_TOKEN)
user_states = {}

class SBPValidator:
    def __init__(self):
        self.field_order = [
            'merchantId', 'account', 'amount', 'currency', 'ttl',
            'additionalData', 'paymentPurpose', 'paymentDetails',
            'redirectUrl', 'callbackMerchantNotifications', 'paymentPageUrl',
            'paymentMethodData'
        ]
    
    def build_sign_string(self, request_data: dict, method: str = 'order') -> str:
        """Собирает строку для подписи"""
        if method == 'order':
            return self._build_by_order(request_data)
        elif method == 'alphabet':
            return self._build_by_alphabet_corrected(request_data)
        else:
            raise ValueError("Метод должен быть 'order' или 'alphabet'")
    
    def _build_by_order(self, data: dict) -> str:
        """Сбор строки в порядке следования полей"""
        parts = []
        
        for field in self.field_order:
            if field in data and data[field] is not None:
                value = data[field]
                
                if field == 'paymentMethodData':
                    parts.append(self._process_payment_method_data(value))
                else:
                    parts.append(self._process_value_for_order(value))
        
        return ''.join(parts)
    
    def _build_by_alphabet_corrected(self, data: dict) -> str:
        """Сбор строки в алфавитном порядке"""
        values = {}
        
        for key, value in data.items():
            if key == 'sign':
                continue
                
            if value is None:
                continue
                
            if key == 'paymentMethodData':
                values[key] = self._process_payment_method_data_for_alphabet(value)
            elif isinstance(value, dict):
                values[key] = self._process_nested_dict_alphabet(value)
            elif isinstance(value, list):
                values[key] = self._process_array_alphabet(value)
            else:
                values[key] = str(value)
        
        sorted_keys = sorted(values.keys())
        return ''.join(values[key] for key in sorted_keys)
    
    def _process_payment_method_data_for_alphabet(self, payment_methods: list) -> str:
        """Особая обработка paymentMethodData для алфавитного порядка"""
        result = []
        for method in payment_methods:
            if 'paymentServiceId' in method and method['paymentServiceId'] is not None:
                result.append(str(method['paymentServiceId']))
            
            if 'additionalData' in method and method['additionalData'] is not None:
                additional_data = method['additionalData']
                if 'receiverAccount' in additional_data and additional_data['receiverAccount'] is not None:
                    result.append(str(additional_data['receiverAccount']))
            
            if 'version' in method and method['version'] is not None:
                result.append(str(method['version']))
        
        return ''.join(result)
    
    def _process_nested_dict_alphabet(self, data: dict) -> str:
        """Обработка вложенного словаря для алфавитного порядка"""
        result = []
        for key in sorted(data.keys()):
            value = data[key]
            if value is None:
                continue
                
            if isinstance(value, dict):
                result.append(self._process_nested_dict_alphabet(value))
            elif isinstance(value, list):
                result.append(self._process_array_alphabet(value))
            else:
                result.append(str(value))
        
        return ''.join(result)
    
    def _process_array_alphabet(self, data: list) -> str:
        """Обработка массива для алфавитного порядка"""
        result = []
        for item in data:
            if item is None:
                continue
                
            if isinstance(item, dict):
                result.append(self._process_nested_dict_alphabet(item))
            elif isinstance(item, list):
                result.append(self._process_array_alphabet(item))
            else:
                result.append(str(item))
        
        return ''.join(result)
    
    def _process_value_for_order(self, value) -> str:
        """Обработка значения поля для режима 'порядок следования'"""
        if isinstance(value, (int, float)):
            return str(value)
        elif isinstance(value, str):
            return value
        elif isinstance(value, dict):
            result = []
            for k, v in value.items():
                if v is not None:
                    result.append(self._process_value_for_order(v))
            return ''.join(result)
        elif isinstance(value, list):
            result = []
            for item in value:
                if item is not None:
                    result.append(self._process_value_for_order(item))
            return ''.join(result)
        else:
            return str(value) if value is not None else ''
    
    def _process_payment_method_data(self, payment_methods: list) -> str:
        """Обработка массива paymentMethodData для порядка следования"""
        result = []
        for method in payment_methods:
            if 'paymentServiceId' in method and method['paymentServiceId'] is not None:
                result.append(str(method['paymentServiceId']))
            if 'version' in method and method['version'] is not None:
                result.append(str(method['version']))
            if 'additionalData' in method and method['additionalData'] is not None:
                result.append(self._process_value_for_order(method['additionalData']))
        return ''.join(result)
    
    def sign_request(self, request_data: dict, method: str = 'alphabet') -> dict:
        """Подписывает запрос и добавляет поле sign"""
        data_to_sign = request_data.copy()
        
        if 'sign' in data_to_sign:
            del data_to_sign['sign']
        
        sign_string = self.build_sign_string(data_to_sign, method)
        
        # Только важная информация в логах
        logging.info(f"Метод формирования: {method}")
        logging.info(f"Строка для подписи ({len(sign_string)} символов): {sign_string}")
        
        signature = self._sign_data(sign_string)
        
        result_data = request_data.copy()
        result_data['sign'] = signature
        return result_data
    
    def _sign_data(self, data: str) -> str:
        """Подписывает данные приватным ключом по алгоритму SHA256withRSA"""
        try:
            with open(PRIVATE_KEY_PATH, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            
            signature = private_key.sign(
                data.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Ошибка подписания: {e}")
    
    def generate_key_pair(self, key_size: int = 2048):
        """Генерирует пару RSA ключей"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')
    
    def verify_signature(self, data: dict, signature: str, method: str = 'alphabet') -> bool:
        """Проверяет подпись с помощью приватного ключа (для самопроверки)"""
        try:
            data_for_verification = data.copy()
            if 'sign' in data_for_verification:
                del data_for_verification['sign']
            
            sign_string = self.build_sign_string(data_for_verification, method)
            
            with open(PRIVATE_KEY_PATH, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
                public_key = private_key.public_key()
            
            signature_bytes = base64.b64decode(signature)
            
            public_key.verify(
                signature_bytes,
                sign_string.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
            
        except Exception as e:
            logging.error(f"Ошибка проверки подписи: {e}")
            return False

def clean_json_input(json_input):
    """Очищает и исправляет JSON ввод"""
    json_input = json_input.replace('\\"', '"')
    json_input = json_input.replace('\\/', '/')
    json_input = '\n'.join(line.strip() for line in json_input.split('\n'))
    
    open_braces = json_input.count('{')
    close_braces = json_input.count('}')
    open_brackets = json_input.count('[')
    close_brackets = json_input.count(']')
    
    if open_braces > close_braces:
        json_input += '}' * (open_braces - close_braces)
    if open_brackets > close_brackets:
        json_input += ']' * (open_brackets - close_brackets)
    
    return json_input

def parse_json_flexible(json_input):
    """Гибкий парсинг JSON"""
    attempts = [
        lambda: json.loads(json_input),
        lambda: json.loads(clean_json_input(json_input)),
        lambda: json.loads(json_input.strip('"')),
        lambda: json.loads('{' + json_input + '}'),
    ]
    
    for i, attempt in enumerate(attempts):
        try:
            return attempt()
        except json.JSONDecodeError as e:
            if i == len(attempts) - 1:
                raise e
            continue
    
    raise json.JSONDecodeError("Не удалось распарсить JSON", json_input, 0)

def escape_html(text):
    """Экранирует HTML-специальные символы."""
    return html.escape(text)

def get_payment_status(instance, token):
    """Выполняет запрос к API и возвращает результат."""
    instance_urls = {
        "test": "5BAE2814BB16ED0AA4A146AA4A4E168D",
        "1": "4246218C81AF2F5E6DF9742C494ADF22",
        "2": "43401363673313FAECAF9C16AC1218FC",
        "3": "335669F12B0B08FCD0AA1F6CBC113733",
    }
    if instance not in instance_urls:
        raise ValueError("Недопустимый инстанс")

    if instance == "test":
        url = f"https://lt.pga.gazprombank.ru/api/v4/{instance_urls[instance]}/payment/{token}"
    else:
        url = f"https://www.pga.gazprombank.ru/api/v4/{instance_urls[instance]}/payment/{token}"
    
    try:
        response = requests.post(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Ошибка при запросе к API: {e}")
        raise

def get_bin_info(bin_number):
    """Получает информацию о BIN с помощью API apilayer.com/bincheck."""
    url = f"https://api.apilayer.com/bincheck/{bin_number}"
    headers = {"apikey": APILAYER_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Ошибка при запросе к API BIN: {e}")
        return None
    except json.JSONDecodeError:
        logging.error("Ошибка декодирования JSON ответа BIN")
        return None

@bot.message_handler(commands=["start"])
def cmd_start(message):
    chat_id = message.chat.id
    user_states.pop(chat_id, None)
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, selective=True)
    item1 = types.KeyboardButton("Запрос статуса операции")
    item2 = types.KeyboardButton("BIN Check")
    item3 = types.KeyboardButton("Валидатор подписи СБП")
    markup.add(item1, item2, item3)
    bot.send_message(chat_id, "Выберите действие:", reply_markup=markup)

@bot.message_handler(func=lambda message: message.text == "Запрос статуса операции")
def status_request(message):
    chat_id = message.chat.id
    user_states[chat_id] = {"step": "instance"}
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton("Тест", callback_data="instance_test"))
    markup.add(types.InlineKeyboardButton("1", callback_data="instance_1"))
    markup.add(types.InlineKeyboardButton("2", callback_data="instance_2"))
    markup.add(types.InlineKeyboardButton("3", callback_data="instance_3"))
    bot.send_message(chat_id, "Укажите инстанс:", reply_markup=markup)

@bot.message_handler(func=lambda message: message.text == "BIN Check")
def bin_check(message):
    chat_id = message.chat.id
    user_states[chat_id] = {"step": "bin_number"}
    bot.send_message(chat_id, "Введите BIN для проверки:")

@bot.message_handler(func=lambda message: message.text == "Валидатор подписи СБП")
def sbp_validator(message):
    chat_id = message.chat.id
    user_states[chat_id] = {"step": "sbp_action"}
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("Проверить формирование строки", callback_data="sbp_check_string"),
        types.InlineKeyboardButton("Подписать запрос", callback_data="sbp_sign_request"),
        types.InlineKeyboardButton("Сгенерировать ключи", callback_data="sbp_generate_keys"),
        types.InlineKeyboardButton("Проверить подпись", callback_data="sbp_verify_signature")
        # Убрали "Проверить ответ банка"
    )
    bot.send_message(chat_id, "Выберите действие валидатора СБП:", reply_markup=markup)

@bot.message_handler(commands=["cancel"])
def cmd_cancel(message):
    chat_id = message.chat.id
    user_states.pop(chat_id, None)
    bot.send_message(chat_id, "Операция отменена. Нажмите /start для новой попытки.")

@bot.callback_query_handler(func=lambda call: call.data.startswith("instance_"))
def on_instance_chosen(call):
    chat_id = call.message.chat.id
    instance = call.data.split("_")[1]
    state = user_states.get(chat_id, {})
    state["instance"] = instance
    state["step"] = "token"
    user_states[chat_id] = state
    
    if instance == "test":
        bot.send_message(chat_id, "🔬 <b>ТЕСТОВЫЙ РЕЖИМ</b>\nУкажите токен для проверки:", parse_mode="HTML")
    else:
        bot.send_message(chat_id, "Укажите токен:")

@bot.callback_query_handler(func=lambda call: call.data.startswith("sbp_"))
def on_sbp_action_chosen(call):
    chat_id = call.message.chat.id
    action = call.data
    
    if action == "sbp_generate_keys":
        validator = SBPValidator()
        try:
            private_key, public_key = validator.generate_key_pair()
            
            bot.send_message(chat_id, "🔑 <b>ПРИВАТНЫЙ КЛЮЧ:</b>\n(сохраните в безопасное место)\n\n" + 
                           f"<code>{private_key}</code>", parse_mode="HTML")
            
            bot.send_message(chat_id, "🔑 <b>ПУБЛИЧНЫЙ КЛЮЧ:</b>\n(отправьте по почте)\n\n" + 
                           f"<code>{public_key}</code>", parse_mode="HTML")
            
            bot.send_message(chat_id, "✅ Ключи успешно сгенерированы!")
            
        except Exception as e:
            bot.send_message(chat_id, f"❌ Ошибка генерации ключей: {e}")
        
        user_states.pop(chat_id, None)
        return
    
    state = user_states.get(chat_id, {})
    state["sbp_action"] = action
    state["step"] = "sbp_json"
    user_states[chat_id] = state
    
    if action == "sbp_check_string":
        bot.send_message(chat_id, "Введите JSON тело запроса:")
    elif action == "sbp_sign_request":
        bot.send_message(chat_id, "Введите JSON тело запроса для подписи:")
    elif action == "sbp_verify_signature":
        bot.send_message(chat_id, "Введите JSON тело запроса с полем 'sign' для проверки:")

@bot.message_handler(func=lambda message: True, content_types=['text'])
def handle_text(message):
    chat_id = message.chat.id
    text = message.text.strip()
    state = user_states.get(chat_id, {})

    if not state:
        bot.reply_to(message, "Нажмите /start, чтобы начать.")
        return

    if state.get("step") == "token":
        state["token"] = text
        try:
            payment_status = get_payment_status(state["instance"], state["token"])
            formatted_result = json.dumps(payment_status, indent=2, ensure_ascii=False)
            
            if state["instance"] == "test":
                bot.send_message(chat_id, f"🔬 <b>ТЕСТОВЫЙ РЕЗУЛЬТАТ:</b>\n```json\n{formatted_result}\n```", parse_mode="HTML")
            else:
                bot.send_message(chat_id, f"Результат запроса:\n```json\n{formatted_result}\n```", parse_mode="Markdown")
                
        except Exception as e:
            bot.send_message(chat_id, f"Произошла ошибка: {e}")
        finally:
            user_states.pop(chat_id, None)
            bot.send_message(chat_id, "Готово. Чтобы сделать новый запрос, нажмите /start.")

    elif state.get("step") == "bin_number":
        bin_number = text
        try:
            bin_info = get_bin_info(bin_number)
            if bin_info:
                formatted_result = json.dumps(bin_info, indent=2, ensure_ascii=False)
                bot.send_message(chat_id, f"Результат проверки BIN:\n```json\n{formatted_result}\n```", parse_mode="Markdown")
            else:
                bot.send_message(chat_id, "Не удалось получить информацию о BIN.")
        except Exception as e:
            bot.send_message(chat_id, f"Произошла ошибка: {e}")
        finally:
            user_states.pop(chat_id, None)
            bot.send_message(chat_id, "Готово. Чтобы сделать новый запрос, нажмите /start.")

    elif state.get("step") == "sbp_json":
        try:
            request_data = parse_json_flexible(text)
            state["sbp_json"] = request_data
            state["step"] = "sbp_method"
            user_states[chat_id] = state
            
            markup = types.InlineKeyboardMarkup()
            markup.add(
                types.InlineKeyboardButton("Порядок следования", callback_data="method_order"),
                types.InlineKeyboardButton("Алфавитный порядок", callback_data="method_alphabet")
            )
            bot.send_message(chat_id, "Выберите метод формирования строки:", reply_markup=markup)
            
        except Exception as e:
            bot.send_message(chat_id, f"❌ Ошибка парсинга JSON: {e}")
            user_states.pop(chat_id, None)

    else:
        bot.reply_to(message, "Неизвестная команда. Нажмите /start для начала работы.")

@bot.callback_query_handler(func=lambda call: call.data.startswith("method_"))
def on_method_chosen(call):
    chat_id = call.message.chat.id
    method = call.data.split("_")[1]
    state = user_states.get(chat_id, {})
    action = state.get("sbp_action")
    request_data = state.get("sbp_json", {})
    
    state["sbp_method"] = method
    user_states[chat_id] = state
    
    validator = SBPValidator()
    
    if action == "sbp_check_string":
        sign_string = validator.build_sign_string(request_data, method)
        
        response = f"📊 <b>РЕЗУЛЬТАТ ФОРМИРОВАНИЯ СТРОКИ:</b>\n\n"
        response += f"🔧 <b>Метод:</b> {'ПОРЯДОК СЛЕДОВАНИЯ' if method == 'order' else 'АЛФАВИТНЫЙ ПОРЯДОК'}\n"
        response += f"🔤 <b>Собираемая строка</b> ({len(sign_string)} символов):\n<code>{escape_html(sign_string)}</code>"
        
        if 'sign' in request_data:
            response += f"\n\n✍️ <b>Поле sign из запроса:</b>\n<code>{request_data['sign']}</code>"
        
        bot.send_message(chat_id, response, parse_mode="HTML")
        user_states.pop(chat_id, None)
        
    elif action == "sbp_sign_request":
        try:
            data_to_sign = request_data.copy()
            
            if 'sign' in data_to_sign:
                del data_to_sign['sign']
            
            signed_request = validator.sign_request(data_to_sign, method)
            sign_string = validator.build_sign_string(data_to_sign, method)
            
            response = f"✅ <b>ЗАПРОС УСПЕШНО ПОДПИСАН!</b>\n\n"
            response += f"🔧 <b>Метод:</b> {'ПОРЯДОК СЛЕДОВАНИЯ' if method == 'order' else 'АЛФАВИТНЫЙ ПОРЯДОК'}\n"
            response += f"🔤 <b>Строка для подписи</b> ({len(sign_string)} символов):\n<code>{escape_html(sign_string)}</code>\n\n"
            response += f"✍️ <b>Поле sign:</b>\n<code>{signed_request['sign']}</code>\n\n"
            response += f"📦 <b>Полный запрос с подписью:</b>\n<code>{escape_html(json.dumps(signed_request, indent=2, ensure_ascii=False))}</code>"
            
            bot.send_message(chat_id, response, parse_mode="HTML")
            
        except Exception as e:
            bot.send_message(chat_id, f"❌ Ошибка подписания: {e}\n\nУбедитесь что файл {PRIVATE_KEY_PATH} существует")
        
        user_states.pop(chat_id, None)
        
    elif action == "sbp_verify_signature":
        if 'sign' not in request_data:
            bot.send_message(chat_id, "❌ В запросе нет поля 'sign' для проверки")
            user_states.pop(chat_id, None)
            return
        
        try:
            signature = request_data['sign']
            
            is_valid = validator.verify_signature(request_data, signature, method)
            
            data_for_verification = request_data.copy()
            if 'sign' in data_for_verification:
                del data_for_verification['sign']
            sign_string = validator.build_sign_string(data_for_verification, method)
            
            response = f"🔍 <b>РЕЗУЛЬТАТ ПРОВЕРКИ ПОДПИСИ:</b>\n\n"
            if is_valid:
                response += "✅ <b>ПОДПИСЬ ВАЛИДНА!</b>\n"
            else:
                response += "❌ <b>ПОДПИСЬ НЕВАЛИДНА!</b>\n"
            
            response += f"\n🔧 <b>Метод:</b> {'ПОРЯДОК СЛЕДОВАНИЯ' if method == 'order' else 'АЛФАВИТНЫЙ ПОРЯДОК'}\n"
            response += f"🔤 <b>Проверяемая строка</b> ({len(sign_string)} символов):\n<code>{escape_html(sign_string)}</code>\n\n"
            response += f"✍️ <b>Подпись:</b>\n<code>{signature}</code>"
            
            bot.send_message(chat_id, response, parse_mode="HTML")
            
        except Exception as e:
            bot.send_message(chat_id, f"❌ Ошибка проверки подписи: {e}")
        
        user_states.pop(chat_id, None)

def ensure_dirs():
    os.makedirs(TMP_DIR, exist_ok=True)
    if not os.path.exists(TEMPLATES_DIR):
        os.makedirs(TEMPLATES_DIR)
    
    # Создаем директорию для ключей, если не существует
    key_dir = os.path.dirname(PRIVATE_KEY_PATH)
    if not os.path.exists(key_dir):
        os.makedirs(key_dir)

if __name__ == "__main__":
    ensure_dirs()
    logging.info("Postman bot started")
    bot.infinity_polling()
