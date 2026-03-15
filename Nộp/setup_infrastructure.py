# -*- coding: utf-8 -*-
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# --- CẤU HÌNH ---
DOMAIN = "my-project.com"
SELECTOR = "selector1"
DMARC_POLICY = "v=DMARC1; p=reject"
AUTHORIZED_IP = "192.168.1.100"
SPF_POLICY = f"v=spf1 ip4:{AUTHORIZED_IP} -all"

# --- DANH SÁCH NGƯỜI DÙNG TĨNH  ---
USERS_TO_CREATE = ["an", "yen", "bob"]  # Thêm bob cho dễ thử nghiệm


# --- HÀM TẠO KHÓA MỚI ---
def generate_rsa_key_pair(username: str):
    """Tạo và lưu cặp khóa RSA (Private/Public) cho một người dùng."""
    print(f"...Đang tạo khóa cho '{username}'...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # 1. Lưu Private Key (dùng để Giải mã)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{username}_private_key.pem", "wb") as f:
        f.write(priv_pem)

    # 2. Trích xuất Public Key (dùng để Mã hóa)
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    print(f"✅ Đã tạo '{username}_private_key.pem'")
    return pub_pem


def setup():
    print("--- Bắt đầu Cài đặt Cơ sở hạ tầng (Giai đoạn 7.0 - RSA Hybrid) ---")

    # === PHẦN 1: TẠO KHÓA DKIM (CHO TÊN MIỀN) ===
    print("\n[PHẦN 1]: Đang tạo khóa DKIM (cho Tên miền)...")
    domain_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    domain_public_key = domain_private_key.public_key()

    domain_private_key_pem = domain_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Tên này (private_key.pem) là mặc định cho DKIM
    with open("private_key.pem", "wb") as f:
        f.write(domain_private_key_pem)
    print("✅ Đã lưu 'private_key.pem' (cho DKIM).")

    domain_public_key_pem_str = domain_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # === PHẦN 2: TẠO KHÓA E2E (CHO NGƯỜI DÙNG) ===
    print("\n[PHẦN 2]: Đang tạo khóa E2E (cho Người dùng)...")
    user_public_keys = {}
    for user in USERS_TO_CREATE:
        user_pub_key_str = generate_rsa_key_pair(user)
        user_public_keys[f"{user}@{DOMAIN}"] = user_pub_key_str

    # === PHẦN 3: TẠO DNS MÔ PHỎNG ===
    print("\n[PHẦN 3]: Đang tạo 'simulated_dns.json'...")
    dns_records = {
        # Bản ghi DKIM
        f"{SELECTOR}._domainkey.{DOMAIN}": {"type": "TXT", "value": domain_public_key_pem_str},
        # Bản ghi DMARC
        f"_dmarc.{DOMAIN}": {"type": "TXT", "value": DMARC_POLICY},
        # Bản ghi SPF
        f"{DOMAIN}": {"type": "TXT", "value": SPF_POLICY},

        # --- BẢN GHI MỚI (Mô phỏng Máy chủ Khóa Công khai) ---
        "key_server": user_public_keys
    }

    with open("simulated_dns.json", "w") as f:
        json.dump(dns_records, f, indent=2)
    print("✅ Đã tạo 'simulated_dns.json' (bao gồm cả Khóa Công khai của người dùng).")

    # === PHẦN 4: TẠO THƯ MỤC & DB ===
    if not os.path.exists("attacker_holding"):
        os.makedirs("attacker_holding")
    if os.path.exists("mail_server.db"):
        os.remove("mail_server.db")
        print("🚮 Đã xóa 'mail_server.db' cũ.")
    print("✅ Đã tạo thư mục 'attacker_holding'.")

    print(f"\n--- Cài đặt Giai đoạn 7.0 hoàn tất! ---")


if __name__ == "__main__":
    setup()