# -*- coding: utf-8 -*-
import json
import hashlib
import os
import time
import shutil
import sqlite3
import threading  # <-- Thêm Threading để khóa file
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# --- CẤU HÌNH DATABASE ---
DATABASE_FILE = "mail_server.db"
DNS_FILE = "simulated_dns.json"
DOMAIN = "my-project.com"

# --- KHÓA ĐỂ GHI FILE (Chống xung đột) ---
dns_lock = threading.Lock()

# Tải "DNS"
try:
    with open(DNS_FILE, "r") as f:
        DNS_RECORDS = json.load(f)
    print("🌍 [SERVER]: Đã tải 'simulated_dns.json'.")
except FileNotFoundError:
    print("❌ LỖI: Không tìm thấy 'simulated_dns.json'.");
    exit()

app = Flask(__name__)


# --- HÀM TẠO KHÓA (GĐ 9.0 - Lấy từ Setup) ---
def generate_rsa_key_pair():
    """Tạo cặp khóa RSA mới (Private/Public) CHO NGƯỜI DÙNG MỚI."""
    print(f"...[SERVER-KEYS]: Đang tạo cặp khóa RSA 2048-bit mới...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # 1. Trích xuất Private Key (để gửi về Client)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # 2. Trích xuất Public Key (để lưu vào DNS)
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    print(f"✅ [SERVER-KEYS]: Đã tạo khóa thành công.")
    return priv_pem, pub_pem


# --- QUẢN LÝ DATABASE ---
def get_db():
    db = sqlite3.connect(DATABASE_FILE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS emails
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           timestamp
                           INTEGER
                           NOT
                           NULL,
                           sender
                           TEXT
                           NOT
                           NULL,
                           recipient
                           TEXT
                           NOT
                           NULL,
                           subject
                           TEXT
                           NOT
                           NULL,
                           body
                           TEXT
                           NOT
                           NULL,
                           metadata_json
                           TEXT
                           NOT
                           NULL,
                           headers_json
                           TEXT
                           NOT
                           NULL
                       );
                       ''')
        db.commit()
        print("✅ [SERVER-DB]: Đã khởi tạo cơ sở dữ liệu và bảng 'emails'.")


# (Các hàm xác thực: dns_lookup, verify_spf, verify_dkim, check_dmarc giữ nguyên)
def dns_lookup(record_name):
    print(f"🔍 [SERVER-DNS]: Đang tra cứu '{record_name}'...")
    # Luôn đọc lại file DNS để lấy dữ liệu mới nhất
    with dns_lock:
        with open(DNS_FILE, "r") as f:
            DNS_RECORDS = json.load(f)
    return DNS_RECORDS.get(record_name, {}).get("value")


def verify_spf(email_object):
    print("\n[SERVER-SPF]: Đang kiểm tra IP người gửi...");
    try:
        sending_ip = email_object["metadata"]["sending_ip"];
        domain = email_object["headers"]["From"].split("@")[1]
        spf_record_str = dns_lookup(domain)
        if not spf_record_str or not spf_record_str.startswith("v=spf1"): raise Exception("Không tìm thấy bản ghi SPF.")
        print(f"✅ [SERVER-SPF]: Đã tìm thấy bản ghi SPF: '{spf_record_str}'")
        authorized_ips = []
        for part in spf_record_str.split(' '):
            if part.startswith("ip4:"): authorized_ips.append(part.split(':')[1])
        if sending_ip in authorized_ips:
            print(f"🎉 [SERVER-SPF]: IP {sending_ip} được ủy quyền. (pass)!");
            return "pass"
        else:
            print(f"❌ [SERVER-SPF]: IP {sending_ip} KHÔNG được ủy quyền (fail).");
            return "fail"
    except Exception as e:
        print(f"❌ [SERVER-SPF]: Lỗi! {e}");
        return "fail"


def verify_dkim(email_object):
    print("\n[SERVER-DKIM]: Đang kiểm tra chữ ký nội dung...");
    try:
        headers = email_object["headers"];
        domain = headers["From"].split("@")[1]
        body_to_check = email_object['body']
        dkim_header = json.loads(headers["DKIM-Signature"])
        if dkim_header["d"] != domain: raise Exception("Domain chữ ký không khớp.")
        selector = dkim_header["s"];
        dkim_record_name = f"{selector}._domainkey.{domain}"
        public_key_pem = dns_lookup(dkim_record_name)
        if not public_key_pem: raise Exception("Không tìm thấy Khóa Công khai DKIM.")
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        body_hash = hashlib.sha256(body_to_check.encode('utf-8')).hexdigest()
        data_to_verify = f"Subject:{headers['Subject']}\nBody-Hash:{body_hash}".encode('utf-8')
        signature = bytes.fromhex(dkim_header["b"])
        public_key.verify(signature, data_to_verify, padding.PKCS1v15(), hashes.SHA256())
        print("🎉 [SERVER-DKIM]: Xác thực thành công (pass)!");
        return "pass"
    except InvalidSignature:
        print("❌ [SERVER-DKIM]: Lỗi! Chữ ký KHÔNG HỢP LỆ (fail).");
        return "fail"
    except Exception as e:
        print(f"❌ [SERVER-DKIM]: Lỗi! {e}");
        return "fail"


def check_dmarc(dkim_result, spf_result, domain):
    print("\n[SERVER-DMARC]: Đang kiểm tra chính sách cuối cùng...")
    dmarc_record_name = f"_dmarc.{domain}";
    dmarc_policy_str = dns_lookup(dmarc_record_name)
    final_action = "accept"
    if dmarc_policy_str and "p=reject" in dmarc_policy_str:
        print(f"✅ [SERVER-DMARC]: Tìm thấy chính sách: {dmarc_policy_str}")
        if dkim_result == "pass":
            final_action = "accept";
            print("✅ [SERVER-DMARC]: DKIM=pass. Email được CHẤP NHẬN.")
        else:
            final_action = "reject";
            print(f"❌ [SERVER-DMARC]: DKIM=fail. Email bị TỪ CHỐI (bất kể SPF).")
    else:
        print("⚠️ [SERVER-DMARC]: Không tìm thấy chính sách 'p=reject', email được CHẤP NHẬN.")
    return final_action


# --- API ENDPOINTS ---

@app.route("/receive", methods=["POST"])
def receive_email():
    """API nhận email (từ Attacker), xác thực và LƯU VÀO DB."""
    print("\n[SERVER]: Phát hiện email mới (từ Attacker)...")
    email_data = request.json
    domain = email_data["headers"]["From"].split("@")[1]
    spf_status = verify_spf(email_data)
    dkim_status = verify_dkim(email_data)
    final_action = check_dmarc(dkim_status, spf_status, domain)

    if final_action == "accept":
        print(f"✅ [SERVER]: Email được CHẤP NHẬN. Đang lưu vào database...")
        try:
            db = get_db()
            db.execute(
                "INSERT INTO emails (timestamp, sender, recipient, subject, body, metadata_json, headers_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (int(time.time()), email_data["headers"]["From"], email_data["headers"]["To"],
                 email_data["headers"]["Subject"],
                 email_data["body"], json.dumps(email_data["metadata"]), json.dumps(email_data["headers"]))
            )
            db.commit()
            return jsonify({"status": "accepted"}), 200
        except Exception as e:
            print(f"❌ [SERVER-DB]: Lỗi khi lưu vào database: {e}")
            return jsonify({"status": "db_error"}), 500
    else:
        print(f"❌ [SERVER]: Email bị TỪ CHỐI. Đang xóa...")
        return jsonify({"status": "rejected"}), 403


@app.route("/fetch_mailbox", methods=["GET"])
def fetch_mailbox():
    user_email = request.args.get('user_email')
    if not user_email: return jsonify({"error": "Cần cung cấp 'user_email'"}), 400
    print(f"\n[SERVER]: Client '{user_email}' đang yêu cầu hộp thư ĐẾN...")
    try:
        db = get_db()
        cursor = db.execute("SELECT * FROM emails WHERE recipient = ? ORDER BY timestamp DESC", (user_email,))
        emails = cursor.fetchall();
        email_list = [dict(row) for row in emails]
        print(f"✅ [SERVER]: Đã tìm thấy {len(email_list)} email cho {user_email}.")
        return jsonify({"status": "ok", "emails": email_list}), 200
    except Exception as e:
        print(f"❌ [SERVER-DB]: Lỗi khi lấy email: {e}");
        return jsonify({"status": "db_error"}), 500


@app.route("/fetch_sent_items", methods=["GET"])
def fetch_sent_items():
    user_email = request.args.get('user_email')
    if not user_email: return jsonify({"error": "Cần cung cấp 'user_email'"}), 400
    print(f"\n[SERVER]: Client '{user_email}' đang yêu cầu hộp thư ĐI...")
    try:
        db = get_db()
        cursor = db.execute("SELECT * FROM emails WHERE sender = ? ORDER BY timestamp DESC", (user_email,))
        emails = cursor.fetchall();
        email_list = [dict(row) for row in emails]
        print(f"✅ [SERVER]: Đã tìm thấy {len(email_list)} email đã gửi từ {user_email}.")
        return jsonify({"status": "ok", "emails": email_list}), 200
    except Exception as e:
        print(f"❌ [SERVER-DB]: Lỗi khi lấy thư đã gửi: {e}");
        return jsonify({"status": "db_error"}), 500


@app.route("/delete_email", methods=["POST"])
def delete_email():
    data = request.json
    email_id = data.get('email_id')
    if not email_id: return jsonify({"error": "Cần cung cấp 'email_id'"}), 400
    print(f"\n[SERVER]: Yêu cầu XÓA email có ID: {email_id}...")
    try:
        db = get_db()
        cursor = db.execute("DELETE FROM emails WHERE id = ?", (email_id,))
        db.commit()
        if cursor.rowcount > 0:
            print(f"✅ [SERVER]: Đã xóa thành công email ID: {email_id}.")
            return jsonify({"status": "deleted"}), 200
        else:
            print(f"⚠️ [SERVER]: Không tìm thấy email ID: {email_id} để xóa.")
            return jsonify({"error": "email not found"}), 404
    except Exception as e:
        print(f"❌ [SERVER-DB]: Lỗi khi xóa email: {e}");
        return jsonify({"status": "db_error"}), 500


@app.route("/get_public_key", methods=["GET"])
def get_public_key():
    email_address = request.args.get('email')
    if not email_address: return jsonify({"error": "Cần cung cấp 'email'"}), 400
    print(f"\n[SERVER-KEYS]: Yêu cầu Khóa Công khai cho: {email_address}...")
    try:
        # Đảm bảo đọc file mới nhất
        with dns_lock:
            with open(DNS_FILE, "r") as f:
                DNS_RECORDS = json.load(f)

        key_server_records = DNS_RECORDS.get("key_server", {})
        public_key_pem = key_server_records.get(email_address)

        if public_key_pem:
            print(f"✅ [SERVER-KEYS]: Đã tìm thấy khóa. Đang gửi...")
            return jsonify({"status": "ok", "email": email_address, "public_key": public_key_pem}), 200
        else:
            print(f"❌ [SERVER-KEYS]: Không tìm thấy khóa cho {email_address}.")
            return jsonify({"error": "User not found or has no public key"}), 404
    except Exception as e:
        print(f"❌ [SERVER-KEYS]: Lỗi khi tra cứu khóa: {e}");
        return jsonify({"status": "server_error"}), 500


# --- API MỚI (Giai đoạn 9.0) ---
@app.route("/register", methods=["POST"])
def register_user():
    """API để đăng ký người dùng mới."""
    data = request.json
    new_email = data.get('email')

    if not new_email or not new_email.endswith(f"@{DOMAIN}"):
        return jsonify({"error": "Email không hợp lệ hoặc không thuộc domain."}), 400

    print(f"\n[SERVER-REGISTER]: Yêu cầu đăng ký cho: {new_email}...")

    # Sử dụng Khóa (Lock) để ngăn 2 người cùng đăng ký 1 lúc
    with dns_lock:
        # 1. Đọc lại file DNS MỚI NHẤT
        with open(DNS_FILE, "r") as f:
            current_dns = json.load(f)

        key_server_records = current_dns.get("key_server", {})

        # 2. Kiểm tra xem user đã tồn tại chưa
        if new_email in key_server_records:
            print(f"❌ [SERVER-REGISTER]: Đăng ký thất bại. Email '{new_email}' đã tồn tại.")
            return jsonify({"error": "Email đã tồn tại."}), 409  # 409 Conflict

        try:
            # 3. Tạo cặp khóa mới
            private_key_pem, public_key_pem = generate_rsa_key_pair()

            # 4. Cập nhật bản ghi DNS
            current_dns["key_server"][new_email] = public_key_pem

            # 5. Ghi đè file DNS
            with open(DNS_FILE, "w") as f:
                json.dump(current_dns, f, indent=2)

            print(f"✅ [SERVER-REGISTER]: Đã đăng ký thành công {new_email}.")
            print(f"... Đã lưu Khóa Công khai vào {DNS_FILE}.")
            print(f"... Đang gửi Khóa Riêng tư về cho Client...")

            # 6. Gửi Khóa RIÊNG TƯ về cho Client
            return jsonify({
                "status": "registered",
                "email": new_email,
                "private_key": private_key_pem
            }), 200

        except Exception as e:
            print(f"❌ [SERVER-REGISTER]: Lỗi nghiêm trọng khi tạo khóa: {e}")
            return jsonify({"error": "Lỗi server khi tạo khóa."}), 500

if __name__ == "__main__":
    init_db()
    print("--- 📧 MÁY CHỦ (SERVER_APP V9.0 - ĐĂNG KÝ) ĐÃ KHỞI ĐỘNG ---")
    print("--- Đang lắng nghe trên http://localhost:8000 ---")
    app.run(port=8000, debug=False)