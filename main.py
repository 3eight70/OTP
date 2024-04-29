from flask import Flask, request, jsonify
import hashlib
import hmac
import os
import time
import json
import requests
import psutil

app = Flask(__name__)


def generate_symmetric_key(length=32):
    return os.urandom(length)


def generate_salt(length=16):
    return os.urandom(length).hex()


def generate_totp(key, digits=6, interval=30):
    current_time = int(time.time() // interval)
    hmac_result = hmac.new(key, str(current_time).encode(), hashlib.sha256).digest() # Юзаем Hash-based Message Authentication Code (HMAC) и алгоритм хэширования SHA256
    offset = hmac_result[-1] & 0x0F # Здесь мы получаем последний байт хеша и применяем маску, чтобы получить младшие 4 бита. Это предназначено для выбора начальной позиции
    binary = ((hmac_result[offset] & 0x7F) << 24 | (hmac_result[offset + 1] & 0xFF) << 16 |
              (hmac_result[offset + 2] & 0xFF) << 8 | (hmac_result[offset + 3] & 0xFF)) # берем 4 байта из хэша начиная с offset, и объединяем их в одно целое число. Маска 0x7F удаляет старший бит для обеспечения положительного числа.
    otp = str(binary % (10 ** digits)).zfill(digits) # Преобразуем binary в строку, заполняет строку нулями слева
    return otp


def generate_key_from_api():
    try:
        print("Ключ сгенерен апишкой")

        url = "https://api.random.org/json-rpc/4/invoke"

        headers = {
            "Content-Type": "application/json"
        }

        jsonText = {
            "jsonrpc": "2.0",
            "method": "generateStrings",
            "params": {
                "apiKey": "ecc3739f-3a69-47c7-bd0c-40304d737f0a",
                "n": 1,
                "length": "32",
                "characters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            },
            "id": 1
        }

        response = requests.post(url, headers=headers, data=json.dumps(jsonText))

        if response.status_code == 200:
            data = response.json()
            key = hashlib.sha256(str(data["result"]["random"]["data"]).encode()).digest()
            return key
        else:
            raise Exception("Запрос вернул статус не 200")
    except Exception as e:
        print(f"Что-то пошло не так: {e}")
        return None


def check_entropy():
    entropy = psutil.virtual_memory().available
    return entropy >= 12800000000


@app.route("/generate_temp_password", methods=["POST"])
def generate_temp_password():
    key = None

    if not check_entropy():
        key = generate_key_from_api()
        if not key:
            return jsonify({"error": "Неполучается сгенерировать ключ"}), 500

    request_data = request.get_json()
    if "password" not in request_data:
        return jsonify({"error": "Отсутствует поле 'password' в запросе"}), 400

    password = request_data["password"]
    salt = generate_salt()
    hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()

    if not key:
        key = generate_symmetric_key()

    totp_code = generate_totp(key)

    return jsonify({
        "salt": salt,
        "hashed_password": hashed_password,
        "totp_code": totp_code
    })


if __name__ == "__main__":
    app.run(debug=True)
