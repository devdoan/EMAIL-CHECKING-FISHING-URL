# -*- coding: utf-8 -*-
import os
import json
import time
import shutil
import platform
import subprocess
import tempfile
import base64
import requests
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import threading

MAILBOX_HOLD = "attacker_holding"
SERVER_URL = "http://localhost:8000/receive"  # Địa chỉ Máy chủ thật

app = Flask(__name__)


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))


def a_human_attacker_intercepts(email_data):

    if not os.path.exists(MAILBOX_HOLD):
        os.makedirs(MAILBOX_HOLD)


    filename = f"intercepted_{int(time.time())}.json"
    hold_path = os.path.join(MAILBOX_HOLD, filename)

    try:
        # Lưu thư lại để mở Notepad
        with open(hold_path, "w") as f:
            json.dump(email_data, f, indent=2)

        print(f"🔥 [ATTACKER]: Đã CHẶN được thư: {filename}!")

        metadata = email_data.get('metadata', {})
        is_encrypted = metadata.get('encrypted', False)

        if is_encrypted:
            # --- KỊCH BẢN 1: THƯ ĐÃ MÃ HÓA ---
            print("--- Nội dung thư bị chặn (Ciphertext) ---")
            print(f"    {email_data['body']}")
            print("-----------------------------------------")


            tamper = input(
                ">>> [ATTACKER] Phát hiện thư MÃ HÓA. Bạn có muốn thử tấn công (giải mã, sửa) không? (y/n): ")
            if tamper.lower() == 'y':

                try:
                    password = input(">>> [ATTACKER] Nhập mật khẩu ăn cắp được để giải mã: ")
                    salt_b64 = email_data['metadata']['salt']
                    salt = base64.b64decode(salt_b64.encode('utf-8'))
                    key = derive_key(password, salt)
                    decryption_engine = Fernet(key)
                    plaintext_body = decryption_engine.decrypt(email_data['body'].encode('utf-8')).decode('utf-8')
                    print(f"...[ATTACKER]: Giải mã thành công! Nội dung gốc là: '{plaintext_body}'")

                    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".txt", encoding='utf-8') as tf:
                        tf.write(plaintext_body);
                        temp_filename = tf.name
                    print(">>> HÃY CHỈNH SỬA NỘI DUNG PLAINTEXT, LƯU LẠI VÀ ĐÓNG TRÌNH SOẠN THẢO <<<");
                    time.sleep(3)
                    if platform.system() == "Windows":
                        subprocess.run(["notepad", temp_filename], check=True)
                    elif platform.system() == "Darwin":
                        subprocess.run(["open", "-W", "-t", temp_filename], check=True)
                    else:
                        editor = os.environ.get('EDITOR', 'nano');
                        subprocess.run([editor, temp_filename], check=True)
                    with open(temp_filename, "r", encoding='utf-8') as tf:
                        malicious_plaintext = tf.read()
                    os.remove(temp_filename)

                    print(f"...[ATTACKER]: Nội dung mới (giả mạo) là: '{malicious_plaintext}'")
                    new_ciphertext = decryption_engine.encrypt(malicious_plaintext.encode('utf-8'))
                    email_data['body'] = new_ciphertext.decode('utf-8')
                    print("✅ [ATTACKER]: Đã MÃ HÓA LẠI thư bằng nội dung giả mạo.")
                except InvalidToken:
                    print("...[ATTACKER]: SAI MẬT KHẨU! Không thể giải mã. Sẽ chuyển tiếp thư gốc.")
                except Exception as e:
                    print(f"...[ATTACKER]: Lỗi giải mã/sửa: {e}. Sẽ chuyển tiếp thư gốc.")

            else:
                print("...[ATTACKER]: Bỏ qua. Sẽ chuyển tiếp thư mã hóa gốc.")

        else:
            # --- KỊCH BẢN 2: THƯ KHÔNG MÃ HÓA (PLAINTEXT) ---
            # (Phần này đã chính xác theo yêu cầu của bạn)
            print("--- Nội dung thư bị chặn (Plaintext) ---")
            print(f"    {email_data['body']}")
            print("---------------------------------------")
            tamper = input(">>> [ATTACKER] Bạn có muốn tấn công (sửa) nội dung plaintext này không? (y/n): ")
            if tamper.lower() == 'y':
                try:
                    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".txt", encoding='utf-8') as tf:
                        tf.write(email_data['body']);
                        temp_filename = tf.name
                    print(">>> HÃY CHỈNH SỬA NỘI DUNG PLAINTEXT, LƯU LẠI VÀ ĐÓNG TRÌNH SOẠN THẢO <<<");
                    time.sleep(3)
                    if platform.system() == "Windows":
                        subprocess.run(["notepad", temp_filename], check=True)
                    elif platform.system() == "Darwin":
                        subprocess.run(["open", "-W", "-t", temp_filename], check=True)
                    else:
                        editor = os.environ.get('EDITOR', 'nano');
                        subprocess.run([editor, temp_filename], check=True)
                    with open(temp_filename, "r", encoding='utf-8') as tf:
                        email_data['body'] = tf.read()
                    os.remove(temp_filename)
                    print("✅ [ATTACKER]: Đã sửa đổi nội dung plaintext.")
                except Exception as e:
                    print(f"❌ [ATTACKER]: Lỗi khi sửa: {e}")

        # Thả thư (Chuyển tiếp đến Máy chủ thật)
        print(f"✅ [ATTACKER]: Đã THẢ thư. Đang chuyển tiếp đến Máy chủ ({SERVER_URL})...")
        try:
            requests.post(SERVER_URL, json=email_data)
        except requests.ConnectionError:
            print(f"❌ [ATTACKER]: Lỗi kết nối! Bạn đã chạy 'server_app.py' chưa?")
        except Exception as e:
            print(f"❌ [ATTACKER]: Lỗi khi chuyển tiếp: {e}")

    except Exception as e:
        print(f"❌ [ATTACKER]: Lỗi nghiêm trọng: {e}")
    finally:

        # if os.path.exists(hold_path):
        #     os.remove(hold_path)
        pass


@app.route("/intercept", methods=["POST"])
def intercept_email():

    email_data = request.json

    # Phải chạy hàm tấn công trong một luồng (thread) riêng
    # để không làm Flask bị treo (vì Flask không thể chờ input())
    attacker_thread = threading.Thread(target=a_human_attacker_intercepts, args=(email_data,))
    attacker_thread.start()

    return jsonify({"status": "received"}), 200


if __name__ == "__main__":
    print("--- 😈 KẺ TẤN CÔNG (ATTACKER_APP) ĐÃ KHỞI ĐỘNG (Máy chủ HTTP) ---")
    print(f"--- Thư mục lưu trữ: {os.path.abspath(MAILBOX_HOLD)} ---")
    print("--- Đang lắng nghe trên http://localhost:5000 ---")
    app.run(port=5000, debug=False)  # Tắt debug để tránh chạy 2 luồng