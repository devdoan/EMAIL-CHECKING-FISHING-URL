# -*- coding: utf-8 -*-
import json
import hashlib
import os
import time
import base64
import requests
import customtkinter
import datetime
import re
import joblib
import numpy as np
from urllib.parse import urlparse, quote_plus
from tldextract import extract
from urlextract import URLExtract

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- CẤU HÌNH ---
DOMAIN = "my-project.com"
SELECTOR = "selector1"
AUTHORIZED_IP = "192.168.1.100"
ATTACKER_URL = "http://localhost:5000/intercept"
SERVER_URL = "http://localhost:8000"
REFRESH_INTERVAL = 10000

# --- CẤU HÌNH GĐ 10 (ML) ---
MODEL_PATH = "phishing_model.joblib"
SCALER_PATH = "phishing_model_scaler.joblib"
FEATURE_NAMES_PATH = "phishing_model_features.json"
ML_THRESHOLD = 0.50  # Ngưỡng ML là 50%

# --- CẤU HÌNH GĐ 10.B (API) ---
VIRUSTOTAL_API_KEY = "b2ffa626e6cfee7ecad0ca0338b784c457d20877cf8315a7fbb991d7937e1dac"

# Danh sách từ khóa nghi ngờ (lấy từ file train)
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'secure', 'update', 'banking', 'signin',
    'password', 'ebay', 'paypal', 'webscr', 'cmd', 'bin'
]


# --- CÁC HÀM CRYPTO (Nằm ngoài Class) ---
def derive_key(password: str, salt: bytes) -> bytes:
    """(GĐ 6.0) Tạo khóa AES từ Mật khẩu Chung."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=100000, backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))


# --- ỨNG DỤNG MAIL (Class-based) ---

class MailApp(customtkinter.CTk):

    def __init__(self):
        super().__init__()
        self.title("Dự án Mail An Ninh (Phiên bản 14.1 - Final)")
        self.geometry("800x600")

        # --- Thuộc tính trạng thái (State) ---
        self.user_email = None
        self.email_to_unlock = None
        self.is_refreshing = False

        self.dkim_private_key = self.load_dkim_key()
        self.e2e_private_key = None

        if not self.dkim_private_key:
            self.title("LỖI KHỞI TẠO")
            error_label = customtkinter.CTkLabel(self, text="LỖI: Không tìm thấy 'private_key.pem' (Khóa DKIM).")
            error_label.pack(pady=50, padx=50);
            return

        # --- GĐ 10: TẢI BỘ NÃO ML ---
        self.ml_model, self.ml_scaler, self.ml_features = self.load_ml_engine()
        self.url_extractor = URLExtract()  # Bộ trích xuất URL
        if not self.ml_model:
            self.title("LỖI KHỞI TẠO")
            error_label = customtkinter.CTkLabel(self,
                                                 text="LỖI: Không tải được 'phishing_model.joblib'.\nHãy chạy 'train_phishing_model.py' trước.")
            error_label.pack(pady=50, padx=50);
            return

        if VIRUSTOTAL_API_KEY == "DÁN_API_KEY_CỦA_BẠN_VÀO_ĐÂY":
            print("⚠️ CẢNH BÁO: VIRUSTOTAL_API_KEY chưa được cấu hình. Lớp 2 sẽ bị vô hiệu hóa.")

        # --- Tạo các Khung (Frame) cho các "trang" ---
        self.login_frame = self.create_login_frame()
        self.register_frame = self.create_register_frame()
        self.main_app_frame = self.create_main_app_frame()
        self.read_frame = self.create_read_email_frame()
        self.password_frame = self.create_password_prompt_frame()
        self.compose_frame = self.create_compose_frame()

        # --- Khởi động ---
        self.show_frame(self.login_frame)

    def load_dkim_key(self):
        """Tải khóa DKIM của TÊN MIỀN (dùng để ký)."""
        try:
            with open("private_key.pem", "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            print("🔑 [CLIENT-GUI]: Đã tải Khóa Riêng tư (DKIM) của Tên miền.")
            return key
        except FileNotFoundError:
            print("❌ LỖI: Không tìm thấy 'private_key.pem'. Hãy chạy 'setup' trước.");
            return None
        except Exception as e:
            print(f"❌ LỖI khi tải khóa DKIM: {e}");
            return None

    def load_user_e2e_key(self, username: str):
        """Tải khóa E2E CÁ NHÂN của Người dùng (dùng để giải mã)."""
        key_filename = f"{username}_private_key.pem"
        try:
            with open(key_filename, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            print(f"🔑 [CLIENT-GUI]: Đã tải Khóa Riêng tư E2E ({key_filename}).")
            self.e2e_private_key = key
            return True
        except FileNotFoundError:
            print(f"❌ LỖI: Không tìm thấy khóa E2E cá nhân '{key_filename}'.")
            return False
        except Exception as e:
            print(f"❌ LỖI khi tải khóa E2E: {e}");
            return False

    def load_ml_engine(self):
        """Tải mô hình ML, Scaler và danh sách Đặc trưng."""
        try:
            print("[CLIENT-ML]: Đang tải 'Bộ não' Phân tích Nội dung (RandomForest)...")
            model = joblib.load(MODEL_PATH)
            scaler = joblib.load(SCALER_PATH)
            with open(FEATURE_NAMES_PATH, "r") as f:
                features = json.load(f)

            if len(features) != 12:
                print(f"❌ LỖI: Tệp features.json không hợp lệ! Cần 12 đặc trưng, tìm thấy {len(features)}")
                return None, None, None

            print("✅ [CLIENT-ML]: Tải 'Bộ não' ML (RandomForest) thành công.")
            return model, scaler, features

        except FileNotFoundError as e:
            print(f"❌ LỖI: Không tìm thấy tệp ML: {e}")
            return None, None, None
        except Exception as e:
            print(f"❌ LỖI khi tải mô hình ML: {e}")
            return None, None, None

    def show_frame(self, frame_to_show):
        """Ẩn tất cả các khung và hiển thị khung được chọn."""
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.main_app_frame.pack_forget()
        self.read_frame.pack_forget()
        self.password_frame.pack_forget()
        self.compose_frame.pack_forget()

        # --- NÂNG CẤP 14.0 ---
        # Ẩn kết quả quét thủ công cũ khi chuyển trang
        if hasattr(self, 'manual_scan_result_frame'):  # Kiểm tra xem nó đã được tạo chưa
            self.manual_scan_result_frame.pack_forget()
        # --- KẾT THÚC NÂNG CẤP ---

        frame_to_show.pack(fill="both", expand=True)

    # --- 1. TRANG ĐĂNG NHẬP (Login Page) ---
    def create_login_frame(self):
        frame = customtkinter.CTkFrame(self)
        label = customtkinter.CTkLabel(frame, text=f"Nhập email của bạn\n(ví dụ: an@{DOMAIN})", font=("", 16))
        label.pack(pady=20, padx=10, anchor="center")
        email_entry = customtkinter.CTkEntry(frame, placeholder_text=f"user@{DOMAIN}", width=300, font=("", 14))
        email_entry.pack(pady=12, padx=10)
        email_entry.focus()
        self.login_error_label = customtkinter.CTkLabel(frame, text="", text_color="red")
        self.login_error_label.pack(pady=5)
        login_button = customtkinter.CTkButton(frame, text="Đăng nhập",
                                               command=lambda: self.handle_login(email_entry.get()))
        login_button.pack(pady=12, padx=10)
        register_button = customtkinter.CTkButton(
            frame, text="Chưa có tài khoản? Đăng ký...",
            fg_color="transparent",
            command=lambda: self.show_frame(self.register_frame)
        )
        register_button.pack(pady=10)
        return frame

    def handle_login(self, email_attempt: str):
        email = email_attempt.strip()
        if "@" not in email or not email.endswith(f"@{DOMAIN}"):
            self.login_error_label.configure(text=f"Email không hợp lệ. Phải có dạng 'user@{DOMAIN}'.")
            return
        username = email.split('@')[0]
        if self.load_user_e2e_key(username):
            self.user_email = email
            self.title(f"Hộp thư của: {self.user_email} (Đã tải khóa E2E)")
            print(f"[GUI]: Đăng nhập thành công với {self.user_email}")
            self.show_frame(self.main_app_frame)
            self.after(100, self.auto_refresh_task)
        else:
            print(f"LỖI: Không tìm thấy khóa cho '{username}'")
            self.login_error_label.configure(
                text=f"Đăng nhập thất bại.\nKhông tìm thấy tệp khóa '{username}_private_key.pem'.\n(Bạn đã Đăng ký chưa?)")

    # --- 1.B TRANG ĐĂNG KÝ (Register Page - GĐ 9.0) ---
    def create_register_frame(self):
        frame = customtkinter.CTkFrame(self)
        label = customtkinter.CTkLabel(frame, text=f"Đăng ký Tài khoản Mới", font=("", 18))
        label.pack(pady=20, padx=10, anchor="center")
        info_label = customtkinter.CTkLabel(frame,
                                            text=f"Nhập email bạn muốn tạo (phải thuộc @{DOMAIN})\nServer sẽ tạo và gửi Khóa Riêng tư cho bạn.")
        info_label.pack(pady=10)
        email_entry = customtkinter.CTkEntry(frame, placeholder_text=f"user_moi@{DOMAIN}", width=300, font=("", 14))
        email_entry.pack(pady=12, padx=10)
        self.register_status_label = customtkinter.CTkLabel(frame, text="", text_color="red")
        self.register_status_label.pack(pady=5)
        register_button = customtkinter.CTkButton(frame, text="Đăng ký",
                                                  command=lambda: self.handle_register(email_entry.get()))
        register_button.pack(pady=12, padx=10)
        back_button = customtkinter.CTkButton(
            frame, text="< Quay lại Đăng nhập",
            fg_color="transparent",
            command=lambda: self.show_frame(self.login_frame)
        )
        back_button.pack(pady=10)
        return frame

    def handle_register(self, email_attempt: str):
        email = email_attempt.strip()
        username = email.split('@')[0]
        key_filename = f"{username}_private_key.pem"
        if "@" not in email or not email.endswith(f"@{DOMAIN}"):
            self.register_status_label.configure(text=f"Email không hợp lệ. Phải có dạng 'user@{DOMAIN}'.")
            return
        print(f"[GUI]: Đang yêu cầu đăng ký cho {email}...")
        self.register_status_label.configure(text="Đang xử lý, vui lòng chờ...", text_color="gray")
        try:
            response = requests.post(f"{SERVER_URL}/register", json={"email": email}, timeout=10)
            if response.status_code == 200:
                data = response.json()
                private_key_pem = data['private_key']
                print(f"✅ [GUI]: Đăng ký thành công. Đã nhận Khóa Riêng tư.")
                with open(key_filename, "w") as f:
                    f.write(private_key_pem)
                print(f"✅ [GUI]: Đã lưu Khóa Riêng tư vào tệp '{key_filename}'.")
                self.register_status_label.configure(text="Đăng ký thành công! Đang đăng nhập...", text_color="green")
                self.after(1000, lambda: self.handle_login(email))
            else:
                error_msg = response.json().get('error', 'Lỗi không xác định')
                print(f"❌ [GUI]: Đăng ký thất bại: {error_msg}")
                self.register_status_label.configure(text=f"Lỗi: {error_msg}", text_color="red")
        except requests.ConnectionError:
            self.register_status_label.configure(text="Lỗi kết nối. (server_app.py chưa chạy?)", text_color="red")
        except Exception as e:
            print(f"❌ [GUI]: Lỗi khi đăng ký: {e}")
            self.register_status_label.configure(text=f"Lỗi: {e}", text_color="red")

    # --- HÀM MỚI: VÒNG LẶP TỰ ĐỘNG ---
    def auto_refresh_task(self):
        print(f"[GUI]: Tự động làm mới (Auto-Refresh) sau {REFRESH_INTERVAL}ms...")
        if not self.is_refreshing: self.handle_smart_refresh()
        self.after(REFRESH_INTERVAL, self.auto_refresh_task)

    # --- 2. TRANG HỘP THƯ CHÍNH (Giao diện Tab) ---
    def create_main_app_frame(self):
        """(GĐ 14.0) Tạo giao diện chính với TabView VÀ Trình quét URL."""
        frame = customtkinter.CTkFrame(self)

        # 1. Khung Điều khiển (Soạn, Làm mới)
        control_frame = customtkinter.CTkFrame(frame)
        control_frame.pack(fill="x", padx=10, pady=10)
        compose_button = customtkinter.CTkButton(control_frame, text="Soạn thư mới", command=self.handle_new_compose)
        compose_button.pack(side="left", padx=5, pady=5)
        self.refresh_button = customtkinter.CTkButton(control_frame, text="Làm mới (Refresh)",
                                                      command=self.handle_smart_refresh)
        self.refresh_button.pack(side="right", padx=5, pady=5)

        # --- GĐ 14.0: KHUNG QUÉT THỦ CÔNG ---
        scanner_frame = customtkinter.CTkFrame(frame, fg_color="transparent")
        scanner_frame.pack(fill="x", padx=10, pady=(0, 5))

        customtkinter.CTkLabel(scanner_frame, text="Kiểm tra URL thủ công:", width=140, anchor="w").pack(side="left",
                                                                                                         padx=5)
        self.manual_url_entry = customtkinter.CTkEntry(scanner_frame, placeholder_text="Dán URL bất kỳ vào đây...")
        self.manual_url_entry.pack(side="left", fill="x", expand=True, padx=5)

        # --- SỬA LỖI ---
        scan_button = customtkinter.CTkButton(
            scanner_frame,
            text="Quét",
            width=80,
            command=self.handle_manual_url_scan  # GÁN HÀM
        )

        scan_button.pack(side="left", padx=(5, 5))

        # Khung kết quả (ẩn)
        self.manual_scan_result_frame = customtkinter.CTkFrame(frame, fg_color="#006400")  # Mặc định Xanh
        self.manual_scan_result_label = customtkinter.CTkLabel(self.manual_scan_result_frame, text="",
                                                               text_color="white", justify="left")
        self.manual_scan_result_label.pack(padx=10, pady=10, fill="x")
        # --- KẾT THÚC GĐ 14.0 ---

        # 3. Khung Tab (Hộp thư đến / Hộp thư đi)
        self.tab_view = customtkinter.CTkTabview(frame)
        self.tab_view.pack(fill="both", expand=True, padx=10, pady=10)
        tab_inbox = self.tab_view.add("Hộp thư đến")
        self.inbox_list_frame = customtkinter.CTkScrollableFrame(tab_inbox)
        self.inbox_list_frame.pack(fill="both", expand=True)
        tab_sent = self.tab_view.add("Hộp thư đi")
        self.sent_list_frame = customtkinter.CTkScrollableFrame(tab_sent)
        self.sent_list_frame.pack(fill="both", expand=True)

        return frame

    def handle_smart_refresh(self):
        if self.is_refreshing:
            print("[GUI]: Đã bỏ qua (skip) lần làm mới vì đang bận.")
            return
        self.is_refreshing = True
        self.refresh_button.configure(state="disabled", text="Đang tải...")
        selected_tab = self.tab_view.get()
        print(f"[GUI]: Làm mới tab: {selected_tab}")
        if selected_tab == "Hộp thư đến":
            self.handle_refresh_inbox()
        elif selected_tab == "Hộp thư đi":
            self.handle_refresh_sent()
        else:
            self.is_refreshing = False
            self.refresh_button.configure(state="normal", text="Làm mới (Refresh)")

    def handle_refresh_inbox(self):
        print(f"[GUI]: Đang làm mới HỘP THƯ ĐẾN...")
        for widget in self.inbox_list_frame.winfo_children(): widget.destroy()
        loading_label = customtkinter.CTkLabel(self.inbox_list_frame, text="Đang tải thư...")
        loading_label.pack(pady=10)
        try:
            response = requests.get(f"{SERVER_URL}/fetch_mailbox", params={"user_email": self.user_email}, timeout=5)
            loading_label.destroy()
            if response.status_code != 200: raise Exception(f"Server báo lỗi: {response.text}")
            received_emails = response.json().get('emails', [])
            if not received_emails:
                customtkinter.CTkLabel(self.inbox_list_frame, text="Hộp thư đến trống.").pack(pady=10);
                return
            print(f"[GUI]: Tìm thấy {len(received_emails)} email đến.")
            for email_row in received_emails:
                self.create_email_button(email_row, target_frame=self.inbox_list_frame)
        except Exception as e:
            loading_label.destroy()
            print(f"❌ [GUI]: Lỗi khi lấy Hộp thư đến: {e}")
            customtkinter.CTkLabel(self.inbox_list_frame, text=f"Lỗi khi tải thư:\n{e}").pack(pady=10)
        finally:
            self.is_refreshing = False
            self.refresh_button.configure(state="normal", text="Làm mới (Refresh)")

    def handle_refresh_sent(self):
        print(f"[GUI]: Đang làm mới HỘP THƯ ĐI...")
        for widget in self.sent_list_frame.winfo_children(): widget.destroy()
        loading_label = customtkinter.CTkLabel(self.sent_list_frame, text="Đang tải thư...")
        loading_label.pack(pady=10)
        try:
            response = requests.get(f"{SERVER_URL}/fetch_sent_items", params={"user_email": self.user_email}, timeout=5)
            loading_label.destroy()
            if response.status_code != 200: raise Exception(f"Server báo lỗi: {response.text}")
            sent_emails = response.json().get('emails', [])
            if not sent_emails:
                customtkinter.CTkLabel(self.sent_list_frame, text="Hộp thư đi trống.").pack(pady=10);
                return
            print(f"[GUI]: Tìm thấy {len(sent_emails)} email đã gửi.")
            for email_row in sent_emails:
                self.create_email_button(email_row, target_frame=self.sent_list_frame)
        except Exception as e:
            loading_label.destroy()
            print(f"❌ [GUI]: Lỗi khi lấy Hộp thư đi: {e}")
            customtkinter.CTkLabel(self.sent_list_frame, text=f"Lỗi khi tải thư:\n{e}").pack(pady=10)
        finally:
            self.is_refreshing = False
            self.refresh_button.configure(state="normal", text="Làm mới (Refresh)")

    def create_email_button(self, email_row, target_frame: customtkinter.CTkScrollableFrame):
        headers = json.loads(email_row['headers_json'])
        metadata = json.loads(email_row['metadata_json'])
        if metadata.get('encrypted_aes_key'):
            is_encrypted_flag = "🔒 (Khóa)"
        elif metadata.get('encrypted'):
            is_encrypted_flag = "🔒 (Mật khẩu)"
        else:
            is_encrypted_flag = "   "
        timestamp = email_row.get('timestamp', time.time())
        dt_object = datetime.datetime.fromtimestamp(timestamp)
        time_str = dt_object.strftime("%Y-%m-%d %H:%M")
        if target_frame == self.sent_list_frame:
            email_text = f"{is_encrypted_flag} Đến: {headers.get('To')}\n     Chủ đề: {headers.get('Subject')}\n     ({time_str})"
        else:
            email_text = f"{is_encrypted_flag} Từ: {headers.get('From')}\n     Chủ đề: {headers.get('Subject')}\n     ({time_str})"
        email_button = customtkinter.CTkButton(
            target_frame, text=email_text, anchor="w",
            command=lambda data=email_row: self.handle_read_email(data)
        )
        email_button.pack(fill="x", padx=5, pady=5)

    # --- 3. TRANG ĐỌC THƯ (Read Email Page) ---

    def create_read_email_frame(self):
        """Tạo các widget cho trang đọc email (CẢNH BÁO PHISHING)."""
        frame = customtkinter.CTkFrame(self)
        control_frame = customtkinter.CTkFrame(frame)
        control_frame.pack(fill="x", padx=10, pady=10)
        back_button = customtkinter.CTkButton(control_frame, text="< Quay lại Hộp thư",
                                              command=lambda: self.show_frame(self.main_app_frame))
        back_button.pack(side="left")
        self.delete_email_button = customtkinter.CTkButton(
            control_frame, text="Xóa thư này",
            fg_color="#DB3E39", hover_color="#B22222"
        )
        self.delete_email_button.pack(side="right")
        header_frame = customtkinter.CTkFrame(frame)
        header_frame.pack(fill="x", padx=10, pady=5)
        self.read_from_label = customtkinter.CTkLabel(header_frame, text="Từ: ...", anchor="w")
        self.read_from_label.pack(fill="x", padx=5)
        self.read_subject_label = customtkinter.CTkLabel(header_frame, text="Chủ đề: ...", anchor="w")
        self.read_subject_label.pack(fill="x", padx=5)
        self.read_warning_frame = customtkinter.CTkFrame(frame, fg_color="#8B0000")
        self.read_warning_label = customtkinter.CTkLabel(self.read_warning_frame, text="⚠️ CẢNH BÁO: ...",
                                                         text_color="white", font=("", 14, "bold"), justify="left")
        self.read_warning_label.pack(padx=10, pady=10, fill="x")
        self.read_body_textbox = customtkinter.CTkTextbox(frame, wrap="word")
        self.read_body_textbox.pack(fill="both", expand=True, padx=10, pady=10)
        return frame

    def handle_read_email(self, email_row):
        """(SỬA LỖI GĐ 10.1) Bộ điều hướng."""
        print(f"[GUI]: Xử lý yêu cầu đọc thư...")
        headers = json.loads(email_row['headers_json'])
        metadata = json.loads(email_row['metadata_json'])
        body_from_email = email_row['body']
        email_id = email_row.get('id')
        self.delete_email_button.configure(state="normal",
                                           command=lambda id=email_id: self.handle_delete_email(id))
        plaintext_body = ""

        if metadata.get('encrypted_aes_key'):
            print("...Email đã mã hóa (RSA). Đang tự động giải mã...")
            if not self.e2e_private_key:
                plaintext_body = "[LỖI: BẠN KHÔNG CÓ KHÓA RIÊNG TƯ ĐỂ MỞ THƯ NÀY]"
            else:
                try:
                    encrypted_aes_key = base64.b64decode(metadata['encrypted_aes_key'])
                    aes_key = self.e2e_private_key.decrypt(
                        encrypted_aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    fernet = Fernet(aes_key)
                    plaintext_body = fernet.decrypt(body_from_email.encode('utf-8')).decode('utf-8')
                    print("...[GUI]: Giải mã RSA-AES thành công.")
                except Exception as e:
                    print(f"❌ LỖI: Giải mã thất bại: {e}")
                    plaintext_body = f"[LỖI GIẢI MÃ: KHÓA RSA CỦA BẠN KHÔNG KHỚP]"

            self._display_and_scan_plaintext(headers, plaintext_body)

        elif metadata.get('encrypted'):
            print("...Email đã mã hóa (Mật khẩu). Yêu cầu mật khẩu.")
            self.email_to_unlock = email_row
            self.password_error_label.configure(text="")
            self.password_entry.delete(0, "end")
            self.show_frame(self.password_frame)
            self.password_entry.focus()
            return

        else:
            print("...Email không mã hóa. Hiển thị trực tiếp.")
            plaintext_body = body_from_email
            self._display_and_scan_plaintext(headers, plaintext_body)

    def handle_delete_email(self, email_id):
        """Gọi API server để xóa email."""
        print(f"[GUI]: Yêu cầu xóa email ID: {email_id}")
        try:
            response = requests.post(f"{SERVER_URL}/delete_email",
                                     json={"email_id": email_id},
                                     timeout=5)
            if response.status_code == 200:
                print("...[GUI]: Xóa thành công trên server.")
                self.show_frame(self.main_app_frame)
                self.after(100, self.handle_smart_refresh)
            else:
                print(f"Lỗi: Server báo lỗi: {response.text}")
        except Exception as e:
            print(f"❌ [GUI]: Lỗi khi gọi API Xóa: {e}")

    # --- 4. TRANG NHẬP MẬT KHẨU (Password Page) ---

    def create_password_prompt_frame(self):
        """(GĐ 6.0) Tạo các widget cho trang nhập mật khẩu."""
        frame = customtkinter.CTkFrame(self)
        control_frame = customtkinter.CTkFrame(frame)
        control_frame.pack(fill="x", padx=10, pady=10)
        back_button = customtkinter.CTkButton(control_frame, text="< Quay lại Hộp thư",
                                              command=lambda: self.show_frame(self.main_app_frame))
        back_button.pack(side="left")
        label = customtkinter.CTkLabel(frame,
                                       text="Email này được mã hóa bằng Mật khẩu Chung.\nVui lòng nhập mật khẩu để giải mã:",
                                       font=("", 16))
        label.pack(pady=30, padx=10, anchor="center")
        self.password_entry = customtkinter.CTkEntry(frame, placeholder_text="Nhập mật khẩu...", width=300)
        self.password_entry.pack(pady=12, padx=10)
        self.password_error_label = customtkinter.CTkLabel(frame, text="", text_color="red")
        self.password_error_label.pack(pady=5)
        decrypt_button = customtkinter.CTkButton(frame, text="Giải mã",
                                                 command=self.handle_decrypt_email)
        decrypt_button.pack(pady=12, padx=10)
        return frame

    def handle_decrypt_email(self):
        """(GĐ 6.0) Thử giải mã email bằng mật khẩu đã nhập."""
        password = self.password_entry.get()
        if not self.email_to_unlock:
            self.show_frame(self.main_app_frame);
            return
        if not password:
            self.password_error_label.configure(text="Vui lòng nhập mật khẩu.");
            return

        print("[GUI]: Đang thử giải mã (Mật khẩu Chung)...")
        try:
            email_row = self.email_to_unlock
            headers = json.loads(email_row['headers_json'])
            metadata = json.loads(email_row['metadata_json'])
            body_from_email = email_row['body']
            salt_b64 = metadata.get('salt')
            if not salt_b64: raise Exception("Lỗi định dạng thư: Không tìm thấy 'salt'.")
            salt = base64.b64decode(salt_b64.encode('utf-8'))
            key = derive_key(password, salt)
            plaintext_body = Fernet(key).decrypt(body_from_email.encode('utf-8')).decode('utf-8')
            print("...[GUI]: Giải mã (Mật khẩu Chung) thành công.")

            self._display_and_scan_plaintext(headers, plaintext_body)

        except InvalidToken:
            print("...[GUI]: ❌ LỖI GIẢI MÃ! MẬT KHẨU SAI.")
            self.password_error_label.configure(text="Mật khẩu sai. Vui lòng thử lại.")
        except Exception as e:
            print(f"...[GUI]: ❌ LỖI GIẢI MÃ! ({e})")
            self.password_error_label.configure(text=f"Lỗi hệ thống: {e}")

    # --- 5. TRANG SOẠN THƯ  ---
    def create_compose_frame(self):
        """(GĐ 8.0) Tạo các widget cho trang soạn thư."""
        frame = customtkinter.CTkFrame(self)
        control_frame = customtkinter.CTkFrame(frame)
        control_frame.pack(fill="x", padx=10, pady=10)
        cancel_button = customtkinter.CTkButton(
            control_frame, text="Hủy",
            command=lambda: self.show_frame(self.main_app_frame),
            fg_color="gray"
        )
        cancel_button.pack(side="left")
        send_button = customtkinter.CTkButton(
            control_frame, text="Gửi thư",
            command=self.handle_send_email
        )
        send_button.pack(side="right")
        header_frame = customtkinter.CTkFrame(frame)
        header_frame.pack(fill="x", padx=10, pady=5)
        customtkinter.CTkLabel(header_frame, text="Đến (To):", width=60).pack(side="left", padx=5)
        self.compose_to_entry = customtkinter.CTkEntry(header_frame)
        self.compose_to_entry.pack(fill="x", expand=True, padx=5)
        subject_frame = customtkinter.CTkFrame(frame)
        subject_frame.pack(fill="x", padx=10, pady=5)
        customtkinter.CTkLabel(subject_frame, text="Chủ đề:", width=60).pack(side="left", padx=5)
        self.compose_subject_entry = customtkinter.CTkEntry(subject_frame)
        self.compose_subject_entry.pack(fill="x", expand=True, padx=5)

        self.encrypt_frame = customtkinter.CTkFrame(frame, fg_color="transparent")
        self.encrypt_frame.pack(fill="x", padx=10, pady=5)
        customtkinter.CTkLabel(self.encrypt_frame, text="Mã hóa:", width=60).pack(side="left", padx=5)
        self.compose_encrypt_choice = customtkinter.CTkSegmentedButton(
            self.encrypt_frame,
            values=["Không Mã hóa", "Mật khẩu Chung", "Khóa Public (RSA)"],
            command=self.toggle_encrypt_options
        )

        self.compose_encrypt_choice.set("Không Mã hóa")
        self.compose_encrypt_choice.pack(fill="x", expand=True, padx=5)
        self.compose_password_frame = customtkinter.CTkFrame(frame, fg_color="transparent")
        customtkinter.CTkLabel(self.compose_password_frame, text="Mật khẩu:", width=60).pack(side="left", padx=5)
        self.compose_password_entry = customtkinter.CTkEntry(self.compose_password_frame,
                                                             placeholder_text="Nhập mật khẩu chung...")
        self.compose_password_entry.pack(fill="x", expand=True, padx=5)
        self.compose_body_textbox = customtkinter.CTkTextbox(frame, wrap="word")
        self.compose_body_textbox.pack(fill="both", expand=True, padx=10, pady=10)
        self.compose_status_label = customtkinter.CTkLabel(frame, text="", text_color="green")
        self.compose_status_label.pack(padx=10, pady=5)
        return frame

    def handle_new_compose(self):
        """Hàm này dọn dẹp và chuyển sang trang Soạn thư."""
        print("[GUI]: Mở trang Soạn thư.")
        self.compose_to_entry.delete(0, "end")
        self.compose_subject_entry.delete(0, "end")
        self.compose_body_textbox.delete("0.0", "end")
        self.compose_password_entry.delete(0, "end")
        self.compose_encrypt_choice.set("Không Mã hóa")
        self.compose_status_label.configure(text="")
        self.toggle_encrypt_options("Không Mã hóa")
        self.show_frame(self.compose_frame)
        self.compose_to_entry.focus()

    def toggle_encrypt_options(self, choice: str):
        """(SỬA LỖI) Hàm này ẨN/HIỆN ô nhập mật khẩu E2E."""
        if choice == "Mật khẩu Chung":
            self.compose_password_frame.pack(fill="x", padx=10, pady=5, after=self.encrypt_frame)
            self.compose_password_entry.focus()
        else:
            self.compose_password_frame.pack_forget()

    def create_and_sign_email(self, from_email, to_email, subject, body_to_sign, metadata):
        """Tạo đối tượng email và ký DKIM (Đã chuyển vào Class)."""
        print(f"\n📨 [CLIENT-GUI]: Đang soạn email từ {from_email}...")
        body_hash = hashlib.sha256(body_to_sign.encode('utf-8')).hexdigest()
        data_to_sign = f"Subject:{subject}\nBody-Hash:{body_hash}".encode('utf-8')
        if not self.dkim_private_key:
            print("❌ [CLIENT-GUI]: Lỗi nghiêm trọng! Không tìm thấy Khóa DKIM để ký.");
            return None
        signature = self.dkim_private_key.sign(data_to_sign, padding.PKCS1v15(), hashes.SHA256())
        dkim_header = {"v": "1", "d": DOMAIN, "s": SELECTOR, "h": "Subject:Body-Hash", "b": signature.hex()}
        email_object = {
            "metadata": metadata,
            "headers": {"From": from_email, "To": to_email, "Subject": subject,
                        "DKIM-Signature": json.dumps(dkim_header)},
            "body": body_to_sign
        }
        print(f"✅ [CLIENT-GUI]: Email đã được ký DKIM.");
        return email_object

    def handle_send_email(self):
        """Logic chính để GỬI email (VIẾT LẠI - GDD 8.0)."""
        print("[GUI]: Bắt đầu quá trình gửi thư...")
        self.compose_status_label.configure(text="Đang gửi...", text_color="gray")
        to_email = self.compose_to_entry.get().strip()
        subject = self.compose_subject_entry.get().strip()
        body = self.compose_body_textbox.get("0.0", "end").strip()
        encrypt_choice = self.compose_encrypt_choice.get()
        if not to_email or not subject:
            self.compose_status_label.configure(text="Lỗi: 'Đến' và 'Chủ đề' không được trống.", text_color="red");
            return
        dialog_ip = customtkinter.CTkInputDialog(
            text=f"Mô phỏng SPF:\nNhập IP GỬI TỪ (để trống = {AUTHORIZED_IP})",
            title="Mô phỏng SPF"
        )
        input_dialog_window = dialog_ip.get_input()
        if input_dialog_window is None:
            print("...[GUI]: Người dùng đã hủy gửi (ở bước SPF).")
            self.compose_status_label.configure(text="Đã hủy gửi.", text_color="gray")
            return
        sending_ip = input_dialog_window.strip()
        if not sending_ip: sending_ip = AUTHORIZED_IP
        print(f"...[GUI]: Gửi từ IP: {sending_ip}")
        metadata = {"sending_ip": sending_ip}
        body_to_send = body
        try:
            if encrypt_choice == "Mật khẩu Chung":
                print("...[GUI]: Yêu cầu Mã hóa (Mật khẩu Chung)...")
                password = self.compose_password_entry.get()
                if not password:
                    raise Exception("Bạn đã chọn 'Mật khẩu Chung' nhưng chưa nhập mật khẩu.")
                salt = os.urandom(16)
                key = derive_key(password, salt)
                body_to_send = Fernet(key).encrypt(body.encode('utf-8')).decode('utf-8')
                metadata['encrypted'] = True
                metadata['salt'] = base64.b64encode(salt).decode('utf-8')
                print("...[GUI]: Nội dung đã được MÃ HÓA (Mật khẩu Chung).")
            elif encrypt_choice == "Khóa Public (RSA)":
                print("...[GUI]: Yêu cầu Mã hóa (Khóa Public)...")
                print(f"...Đang lấy Khóa Công khai của {to_email}...")
                response = requests.get(f"{SERVER_URL}/get_public_key", params={"email": to_email}, timeout=5)
                if response.status_code != 200:
                    raise Exception(
                        f"Không tìm thấy Khóa Public của Người nhận (Lỗi Server: {response.json().get('error')})")
                recipient_public_key_pem = response.json()['public_key']
                recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode('utf-8'))
                aes_key = Fernet.generate_key()
                fernet = Fernet(aes_key)
                body_to_send = fernet.encrypt(body.encode('utf-8')).decode('utf-8')
                encrypted_aes_key = recipient_public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                metadata['encrypted_aes_key'] = base64.b64encode(encrypted_aes_key).decode('utf-8')
                print("...[GUI]: Đã mã hóa thành công (RSA-AES Hybrid).")
            else:
                print("...[GUI]: Gửi dưới dạng văn bản thuần (plaintext).")
        except Exception as e:
            print(f"❌ Lỗi khi mã hóa: {e}")
            self.compose_status_label.configure(text=f"Lỗi Mã hóa: {e}", text_color="red")
            return
        email_to_send = self.create_and_sign_email(
            from_email=self.user_email,
            to_email=to_email,
            subject=subject,
            body_to_sign=body_to_send,
            metadata=metadata
        )
        if not email_to_send:
            self.compose_status_label.configure(text="Lỗi khi ký thư.", text_color="red");
            return
        try:
            response = requests.post(ATTACKER_URL, json=email_to_send, timeout=5)
            if response.status_code == 200:
                print(f"✅ [CLIENT-GUI]: Đã gửi email thành công (đến Attacker).")
                self.compose_status_label.configure(text="Đã gửi thành công!", text_color="green")
                self.after(2000, lambda: self.show_frame(self.main_app_frame))
            else:
                raise Exception(f"Máy chủ (Attacker) báo lỗi: {response.text}")
        except requests.ConnectionError:
            self.compose_status_label.configure(text="Lỗi kết nối! (attacker_app.py chưa chạy?)", text_color="red")
        except Exception as e:
            self.compose_status_label.configure(text=f"Lỗi khi gửi: {e}", text_color="red")

    # --- GĐ 10: CÁC HÀM CỦA BỘ NÃO ML ---

    # --- HÀM NÂNG CẤP (GĐ 13.1) ---
    def _display_and_scan_plaintext(self, headers, plaintext_body):
        """Hàm trợ giúp: Quét nội dung (CẢ ML VÀ API), Cập nhật UI."""

        warning_text = ""
        is_malicious_ml = False
        is_malicious_api = False
        probability_ml = 0.0

        ml_message = "ML: (chưa quét)"
        api_message = "API: (chưa quét)"
        frame_color = "#006400"  # Xanh lá (Mặc định)

        # 1. Quét nội dung (chỉ chạy nếu có "bộ não" ML)
        if self.ml_model:
            print("[GUI-ML]: Nội dung đã giải mã. Bắt đầu quét phishing...")

            # --- LỚP 1: LUÔN CHẠY ML ---
            is_malicious_ml, probability_ml = self.scan_body_for_links_ml(plaintext_body)
            ml_message = f"Mô hình ML (Lớp 1): {probability_ml * 100:.0f}% Độc hại"

            # --- LỚP 2: LUÔN CHẠY API ---
            api_mal, api_sus, api_total = self.scan_body_for_links_api(plaintext_body)

            # --- LOGIC (v13.2) ---
            if VIRUSTOTAL_API_KEY == "DÁN_API_KEY_CỦA_BẠN_VÀO_ĐÂY":
                api_message = "API VirusTotal (Lớp 2): Chưa cấu hình API Key."
            elif api_total > 0:  # Chỉ hiển thị kết quả nếu VT thực sự quét
                api_message = f"VirusTotal (Lớp 2): {api_mal} / {api_total} nhà cung cấp báo độc hại."
            else:  # (api_total == 0)
                api_message = "API VirusTotal (Lớp 2): An toàn (0 báo cáo)."


            # --- 2. TỔNG HỢP KẾT QUẢ ---
            is_malicious_api = (api_mal > 0) or (api_sus > 2)

            if is_malicious_ml and is_malicious_api:
                warning_text = f"🚨 CẢNH BÁO NGHIÊM TRỌNG (Cả hai Lớp)\n{ml_message}\n{api_message}"
                frame_color = "#8B0000"  # Đỏ sậm
            elif is_malicious_ml:
                warning_text = f"⚠️ CẢNH BÁO (Lớp 1: ML)\n{ml_message}\n{api_message}"
                frame_color = "#E06C00"  # Cam
            elif is_malicious_api:
                warning_text = f"⚠️ CẢNH BÁO (Lớp 2: API)\n{ml_message}\n{api_message}"
                frame_color = "#E06C00"  # Cam
            else:
                # Cả hai an toàn
                warning_text = f"✅ AN TOÀN (Đã quét 2 lớp)\n{ml_message}\n{api_message}"
                frame_color = "#006400"  # Xanh lá sậm

            print(f"[GUI-Scan]: {warning_text.replace('\n', ' | ')}")
            self.read_warning_label.configure(text=warning_text)
            self.read_warning_frame.configure(fg_color=frame_color)  # Đặt màu
            self.read_warning_frame.pack(fill="x", padx=10, pady=(5, 0), after=self.read_from_label.master)

        else:
            self.read_warning_frame.pack_forget()

        # 3. Cập nhật và Hiển thị UI
        self.read_from_label.configure(text=f"Từ: {headers.get('From')}")
        self.read_subject_label.configure(text=f"Chủ đề: {headers.get('Subject')}")
        self.read_body_textbox.configure(state="normal")
        self.read_body_textbox.delete("0.0", "end")
        self.read_body_textbox.insert("0.0", plaintext_body)
        self.read_body_textbox.configure(state="disabled")

        self.show_frame(self.read_frame)

    def scan_body_for_links_ml(self, body_text: str):
        """LỚP 1: Quét văn bản, trích xuất link, và dự đoán bằng ML."""
        try:
            urls = self.url_extractor.find_urls(body_text)
            if not urls:
                return False, 0.0  # Không có link, an toàn

            print(f"...[GUI-ML Lớp 1]: Tìm thấy {len(urls)} link: {urls}")
            highest_risk_prob = 0.0

            for url in urls:
                features = self.extract_features(url)
                if not features: continue
                features_scaled = self.ml_scaler.transform([features])
                probability_doc_hai = self.ml_model.predict_proba(features_scaled)[0][1]

                print(f"......Link (ML): '{url}' | Xác suất độc hại: {probability_doc_hai * 100:.2f}%")

                if probability_doc_hai > highest_risk_prob:
                    highest_risk_prob = probability_doc_hai

            if highest_risk_prob > ML_THRESHOLD:
                return True, highest_risk_prob  # (Độc hại, Xác suất)
            else:
                return False, highest_risk_prob  # (An toàn, Xác suất)

        except Exception as e:
            print(f"❌ [GUI-ML]: Lỗi khi quét Lớp 1 (ML): {e}")
            return False, 0.0

            # --- NÂNG CẤP (GĐ 13.1) ---

    def check_url_with_virustotal(self, url_to_check: str):
        """LỚP 2: Kiểm tra một URL với API VirusTotal.
        Trả về: (malicious_count, suspicious_count, total_vendors_count)
        """

        # Kiểm tra API key
        if VIRUSTOTAL_API_KEY == "DÁN_API_KEY_CỦA_BẠN_VÀO_ĐÂY":
            print("...[GUI-API Lớp 2]: Bỏ qua. API Key chưa được cấu hình.")
            return 0, 0, 0  # (0 Độc hại, 0 Đáng ngờ, 0 Tổng)


        print(f"...[GUI-API Lớp 2]: Đang gửi URL '{url_to_check}' đến VirusTotal...")

        url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        try:
            response = requests.get(api_url, headers=headers, timeout=10)

            if response.status_code == 404:
                print("...[GUI-API Lớp 2]: VirusTotal chưa biết đến URL này. (An toàn)")
                return 0, 0, 0
            if response.status_code != 200:
                print(f"❌ Lỗi: VirusTotal API báo lỗi {response.status_code}: {response.text}")
                return 0, 0, 0  # An toàn nếu API lỗi

            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            harmless_count = stats.get("harmless", 0)
            undetected_count = stats.get("undetected", 0)

            total_vendors = malicious_count + suspicious_count + harmless_count + undetected_count

            print(
                f"✅ [GUI-API Lớp 2]: Kết quả: {malicious_count} Độc hại, {suspicious_count} Đáng ngờ / {total_vendors} Tổng.")
            return malicious_count, suspicious_count, total_vendors

        except Exception as e:
            print(f"❌ [GUI-API]: Lỗi khi gọi VirusTotal: {e}")
            return 0, 0, 0  # An toàn nếu API lỗi

    # --- NÂNG CẤP (GĐ 13.1) ---
    def scan_body_for_links_api(self, body_text: str):
        """LỚP 2: Quét văn bản, trích xuất link, và GỌI API.
        Trả về: (highest_malicious, highest_suspicious, highest_total)
        """
        highest_malicious = 0
        highest_suspicious = 0
        highest_total = 0

        try:
            urls = self.url_extractor.find_urls(body_text)
            if not urls:
                return 0, 0, 0  # Không có link, an toàn

            print(f"...[GUI-API Lớp 2]: Tìm thấy {len(urls)} link để quét API...")

            for url in urls:
                mal_count, sus_count, total_count = self.check_url_with_virustotal(url)

                # Lưu lại kết quả của link nguy hiểm nhất (dựa trên mal_count)
                if mal_count > highest_malicious:
                    highest_malicious = mal_count
                    highest_suspicious = sus_count
                    highest_total = total_count

            return highest_malicious, highest_suspicious, highest_total

        except Exception as e:
            print(f"❌ [GUI-API]: Lỗi khi quét Lớp 2 (API): {e}")
            return 0, 0, 0  # An toàn nếu có lỗi

    # --- (GĐ 14.0) ---
    def handle_manual_url_scan(self):
        """Quét một URL thủ công và hiển thị kết quả."""
        url = self.manual_url_entry.get().strip()
        if not url:
            self.manual_scan_result_label.configure(text="Vui lòng nhập một URL để quét.")
            self.manual_scan_result_frame.configure(fg_color="#E06C00")  # Cam
            self.manual_scan_result_frame.pack(fill="x", padx=10, pady=(5, 5))
            return

        print(f"[GUI-Quét]: Bắt đầu quét thủ công URL: {url}")

        # --- LỚP 1: LUÔN CHẠY ML ---
        is_malicious_ml, probability_ml = self.scan_body_for_links_ml(url)
        ml_message = f"Mô hình ML (Lớp 1): {probability_ml * 100:.0f}% Độc hại"

        # --- LỚP 2: LUÔN CHẠY API ---
        api_mal, api_sus, api_total = self.scan_body_for_links_api(url)

        if VIRUSTOTAL_API_KEY == "DÁN_API_KEY_CỦA_BẠN_VÀO_ĐÂY":
            api_message = "API VirusTotal (Lớp 2): Chưa cấu hình API Key."
        elif api_total > 0:
            api_message = f"VirusTotal (Lớp 2): {api_mal} / {api_total} nhà cung cấp báo độc hại."
        else:
            api_message = "API VirusTotal (Lớp 2): An toàn (0 báo cáo)."

        # --- TỔNG HỢP KẾT QUẢ ---
        is_malicious_api = (api_mal > 0) or (api_sus > 2)

        if is_malicious_ml and is_malicious_api:
            warning_text = f"🚨 CẢNH BÁO NGHIÊM TRỌNG (Cả hai Lớp)\n{ml_message}\n{api_message}"
            frame_color = "#8B0000"  # Đỏ sậm
        elif is_malicious_ml:
            warning_text = f"⚠️ CẢNH BÁO (Lớp 1: ML)\n{ml_message}\n{api_message}"
            frame_color = "#E06C00"  # Cam
        elif is_malicious_api:
            warning_text = f"⚠️ CẢNH BÁO (Lớp 2: API)\n{ml_message}\n{api_message}"
            frame_color = "#E06C00"  # Cam
        else:
            warning_text = f"✅ AN TOÀN (Đã quét 2 lớp)\n{ml_message}\n{api_message}"
            frame_color = "#006400"  # Xanh lá sậm

        print(f"[GUI-Quét]: {warning_text.replace('\n', ' | ')}")
        self.manual_scan_result_label.configure(text=warning_text)
        self.manual_scan_result_frame.configure(fg_color=frame_color)
        # Hiển thị kết quả quét
        self.manual_scan_result_frame.pack(fill="x", padx=10, pady=(5, 5), after=self.tab_view)

    def extract_features(self, url: str):
        """(GĐ 10) Sao chép từ file train: Biến URL thành vector."""
        features = []
        try:
            parsed_url = urlparse(url)
            domain_parts = extract(url)
            domain, subdomain, suffix = domain_parts.domain, domain_parts.subdomain, domain_parts.suffix

            features.append(len(url))  # 1
            features.append(1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0)  # 2
            features.append(url.count('@'))  # 3
            features.append(url.count('/'))  # 4
            features.append(url.count('-'))  # 5
            features.append(url.count('.'))  # 6
            features.append(1 if parsed_url.scheme == 'https' else 0)  # 7
            features.append(len(domain))  # 8
            features.append(len(subdomain))  # 9
            features.append(subdomain.count('.'))  # 10
            keyword_count = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in url.lower())
            features.append(keyword_count)  # 11
            features.append(1 if suffix in ['com', 'org', 'net', 'gov', 'edu'] else 0)  # 12

            if len(features) != 12: return None
            return features
        except Exception as e:
            print(f"...[ML-Feature]: Lỗi trích xuất '{url}': {e}")
            return None


# --- ĐIỂM KHỞI ĐẦU ---
if __name__ == "__main__":
    customtkinter.set_appearance_mode("System")
    customtkinter.set_default_color_theme("blue")

    app = MailApp()
    # Chỉ chạy nếu cả 2 (DKIM và ML) đều được tải thành công
    if app.dkim_private_key and app.ml_model:
        app.mainloop()