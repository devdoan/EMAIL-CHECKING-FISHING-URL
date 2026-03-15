# Cài đặt thư viện cần thiết trước khi chạy:
# pip install cryptography requests

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import base64
import requests
import json
import time
import re
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import padding as sym_padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os

class HybridEncryptionTab:
    def __init__(self, parent):
        self.parent = parent
        self.frame = tk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Khóa RSA và AES
        self.private_key = None
        self.public_key = None
        self.aes_key = None
        self.aes_iv = None
        
        self.setup_ui()
        
    def setup_ui(self):
        tk.Label(self.frame, text="Nội dung Email:").pack(anchor="w")
        self.email_text = scrolledtext.ScrolledText(self.frame, width=60, height=8)
        self.email_text.pack(pady=5, fill=tk.BOTH, expand=True)
        
        btn_frame = tk.Frame(self.frame)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Tạo Khóa RSA", command=self.generate_rsa_keys).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Mã hóa AES + RSA", command=self.encrypt_hybrid).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Copy Base64 cho các Tab sau", command=self.copy_to_next).pack(side=tk.LEFT, padx=5)
        
        tk.Label(self.frame, text="Nội dung Email sau mã hóa AES (Base64):").pack(anchor="w", pady=(10,0))
        self.encrypted_email_text = scrolledtext.ScrolledText(self.frame, width=60, height=6)
        self.encrypted_email_text.pack(pady=5, fill=tk.BOTH, expand=True)
        
        tk.Label(self.frame, text="Session Key AES sau mã hóa RSA (Base64):").pack(anchor="w", pady=(10,0))
        self.encrypted_aes_key_text = scrolledtext.ScrolledText(self.frame, width=60, height=4)
        self.encrypted_aes_key_text.pack(pady=5, fill=tk.BOTH, expand=True)
        
        self.decrypted_text = tk.Text(self.frame, width=60, height=4)
        self.decrypted_text.pack(pady=5, fill=tk.BOTH, expand=True)
        tk.Button(self.frame, text="Giải mã để kiểm tra", command=self.decrypt_hybrid).pack(pady=5)
    
    def generate_rsa_keys(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.public_key = self.private_key.public_key()
        messagebox.showinfo("Thành công", "Đã tạo cặp khóa RSA!")
    
    def generate_aes_key_and_iv(self):
        self.aes_key = os.urandom(32)
        self.aes_iv = os.urandom(16)
    
    def encrypt_aes(self, plaintext):
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.aes_iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext
    
    def encrypt_hybrid(self):
        email_content = self.email_text.get("1.0", tk.END).strip()
        if not email_content:
            messagebox.showerror("Lỗi", "Vui lòng nhập nội dung email!")
            return
        if not self.private_key:
            messagebox.showerror("Lỗi", "Vui lòng tạo khóa RSA trước!")
            return
        self.generate_aes_key_and_iv()
        encrypted_email = self.encrypt_aes(email_content)
        encrypted_email_b64 = base64.b64encode(encrypted_email).decode('utf-8')
        self.encrypted_email_text.delete("1.0", tk.END)
        self.encrypted_email_text.insert("1.0", encrypted_email_b64)
        aes_key_serialized = self.aes_key + self.aes_iv
        encrypted_aes_key = self.public_key.encrypt(aes_key_serialized, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
        self.encrypted_aes_key_text.delete("1.0", tk.END)
        self.encrypted_aes_key_text.insert("1.0", encrypted_aes_key_b64)
        messagebox.showinfo("Thành công", "Đã mã hóa hybrid AES + RSA!")
    
    def decrypt_hybrid(self):
        encrypted_email_b64 = self.encrypted_email_text.get("1.0", tk.END).strip()
        encrypted_aes_key_b64 = self.encrypted_aes_key_text.get("1.0", tk.END).strip()
        if not encrypted_email_b64 or not encrypted_aes_key_b64:
            messagebox.showerror("Lỗi", "Vui lòng mã hóa trước!")
            return
        try:
            encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
            aes_key_iv = self.private_key.decrypt(encrypted_aes_key, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            aes_key = aes_key_iv[:32]
            aes_iv = aes_key_iv[32:]
            encrypted_email = base64.b64decode(encrypted_email_b64)
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(encrypted_email) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            decrypted_email = plaintext.decode('utf-8')
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert("1.0", decrypted_email)
            messagebox.showinfo("Thành công", "Đã giải mã thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi giải mã: {str(e)}")
    
    def copy_to_next(self):
        encrypted_email_b64 = self.encrypted_email_text.get("1.0", tk.END).strip()
        encrypted_aes_key_b64 = self.encrypted_aes_key_text.get("1.0", tk.END).strip()
        decrypted_content = self.decrypted_text.get("1.0", tk.END).strip()
        if not encrypted_email_b64 or not encrypted_aes_key_b64:
            messagebox.showerror("Lỗi", "Vui lòng mã hóa trước!")
            return
        self.parent.encrypted_email_b64 = encrypted_email_b64
        self.parent.encrypted_aes_key_b64 = encrypted_aes_key_b64
        self.parent.decrypted_content = decrypted_content if decrypted_content else "Nội dung mẫu: Check this URL: http://example.com"
        messagebox.showinfo("Thành công", "Đã copy dữ liệu sang các tab sau!")

class DKIMDMARCTab:
    def __init__(self, parent):
        self.parent = parent
        self.frame = tk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.dkim_private_key = None
        self.dkim_public_key = None
        self.dmarc_policy = "reject"
        self.spf_fail_mode = tk.BooleanVar(value=False)
        
        self.setup_ui()
        
    def setup_ui(self):
        chk_frame = tk.Frame(self.frame)
        chk_frame.pack(pady=5)
        tk.Checkbutton(chk_frame, text="Test Fail Case (SPF Fail)", variable=self.spf_fail_mode).pack(side=tk.LEFT)
        
        btn_frame = tk.Frame(self.frame)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Tạo Khóa DKIM (Ed25519)", command=self.generate_dkim_keys).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Load từ Tab Mã hóa & Kiểm tra", command=self.verify_dkim_dmarc).pack(side=tk.LEFT, padx=5)
        
        tk.Label(self.frame, text="Ciphertext AES (từ Tab Mã hóa):").pack(anchor="w")
        self.ciphertext_display = tk.Text(self.frame, width=60, height=4, state=tk.DISABLED)
        self.ciphertext_display.pack(pady=5, fill=tk.BOTH, expand=True)
        
        tk.Label(self.frame, text="Encrypted Session Key:").pack(anchor="w")
        self.session_key_display = tk.Text(self.frame, width=60, height=3, state=tk.DISABLED)
        self.session_key_display.pack(pady=5, fill=tk.BOTH, expand=True)
        
        tk.Label(self.frame, text="Kết quả Verify DKIM:").pack(anchor="w", pady=(10,0))
        self.dkim_result_text = scrolledtext.ScrolledText(self.frame, width=60, height=3)
        self.dkim_result_text.pack(pady=5, fill=tk.BOTH, expand=True)
        
        tk.Label(self.frame, text="Kết quả DMARC Policy:").pack(anchor="w", pady=(10,0))
        self.dmarc_result_text = scrolledtext.ScrolledText(self.frame, width=60, height=3)
        self.dmarc_result_text.pack(pady=5, fill=tk.BOTH, expand=True)
        
        tk.Label(self.frame, text="Quyết định Gửi Email:").pack(anchor="w", pady=(10,0))
        self.decision_text = tk.Text(self.frame, width=60, height=2)
        self.decision_text.pack(pady=5, fill=tk.BOTH, expand=True)
    
    def generate_dkim_keys(self):
        self.dkim_private_key = ed25519.Ed25519PrivateKey.generate()
        self.dkim_public_key = self.dkim_private_key.public_key()
        messagebox.showinfo("Thành công", "Đã tạo khóa DKIM!")
    
    def create_fake_dkim_signature(self, message_hash):
        if not self.dkim_private_key:
            raise ValueError("Chưa tạo khóa DKIM!")
        signature = self.dkim_private_key.sign(message_hash)
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_dkim_dmarc(self):
        if not hasattr(self.parent, 'encrypted_email_b64') or not self.parent.encrypted_email_b64:
            messagebox.showerror("Lỗi", "Vui lòng mã hóa ở tab trước và copy!")
            return
        if not self.dkim_private_key:
            messagebox.showerror("Lỗi", "Vui lòng tạo khóa DKIM trước!")
            return
        
        ciphertext_b64 = self.parent.encrypted_email_b64
        session_key_b64 = self.parent.encrypted_aes_key_b64
        
        self.ciphertext_display.config(state=tk.NORMAL)
        self.ciphertext_display.delete("1.0", tk.END)
        self.ciphertext_display.insert("1.0", ciphertext_b64)
        self.ciphertext_display.config(state=tk.DISABLED)
        
        self.session_key_display.config(state=tk.NORMAL)
        self.session_key_display.delete("1.0", tk.END)
        self.session_key_display.insert("1.0", session_key_b64)
        self.session_key_display.config(state=tk.DISABLED)
        
        try:
            email_body = f"From: sender@example.com\nTo: receiver@example.com\nSubject: Secure Email\n\n{ciphertext_b64}\n{session_key_b64}"
            message_hash = hashes.Hash(hashes.SHA256())
            message_hash.update(email_body.encode())
            digest = message_hash.finalize()
            
            fake_signature_b64 = self.create_fake_dkim_signature(digest)
            signature_bytes = base64.b64decode(fake_signature_b64)
            self.dkim_public_key.verify(signature_bytes, digest)
            dkim_status = "PASS - Chữ ký DKIM hợp lệ (domain alignment OK)"
            
            spf_pass = not self.spf_fail_mode.get()
            if dkim_status.startswith("PASS") and spf_pass:
                dmarc_status = f"PASS - DMARC policy '{self.dmarc_policy}' cho phép"
                decision = "AN TOÀN - Gửi email cho người nhận"
                color = "green"
            else:
                dmarc_status = "FAIL - DMARC policy yêu cầu reject"
                decision = "KHÔNG AN TOÀN - Reject email"
                color = "red"
            
            self.dkim_result_text.delete("1.0", tk.END)
            self.dkim_result_text.insert("1.0", dkim_status)
            
            self.dmarc_result_text.delete("1.0", tk.END)
            self.dmarc_result_text.insert("1.0", dmarc_status)
            
            self.decision_text.delete("1.0", tk.END)
            self.decision_text.insert("1.0", decision)
            self.decision_text.config(fg=color)
            
            messagebox.showinfo("Thành công", f"Quy trình hoàn tất! Quyết định: {decision}")
            
        except InvalidSignature:
            self.dkim_result_text.delete("1.0", tk.END)
            self.dkim_result_text.insert("1.0", "FAIL - Chữ ký DKIM không hợp lệ")
            self.dmarc_result_text.delete("1.0", tk.END)
            self.dmarc_result_text.insert("1.0", "FAIL - DMARC reject do DKIM fail")
            self.decision_text.delete("1.0", tk.END)
            self.decision_text.insert("1.0", "KHÔNG AN TOÀN - Reject email")
            self.decision_text.config(fg="red")
            messagebox.showerror("Lỗi", "DKIM verify thất bại!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi hệ thống: {str(e)}")

class VirusTotalTab:
    def __init__(self, parent):
        self.parent = parent
        self.frame = tk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.vt_api_key = "YOUR_API_KEY_HERE"  # Thay bằng API key thật
        self.decrypted_email = ""
        
        self.setup_ui()
        
    def setup_ui(self):
        tk.Label(self.frame, text="Nội dung Email sau Giải mã (từ Tab Mã hóa):").pack(anchor="w")
        self.decrypted_display = tk.Text(self.frame, width=60, height=6, state=tk.DISABLED)
        self.decrypted_display.pack(pady=5, fill=tk.BOTH, expand=True)
        
        tk.Label(self.frame, text="URL cần quét (trích xuất từ email hoặc nhập thủ công):").pack(anchor="w")
        self.url_entry = tk.Entry(self.frame, width=60)
        self.url_entry.pack(pady=5)
        tk.Button(self.frame, text="Trích xuất URL tự động", command=self.extract_url).pack(pady=5)
        
        tk.Button(self.frame, text="Quét VirusTotal", command=self.scan_url).pack(pady=10)
        
        tk.Label(self.frame, text="Kết quả Quét VirusTotal:").pack(anchor="w", pady=(10,0))
        self.vt_result_text = scrolledtext.ScrolledText(self.frame, width=60, height=6)
        self.vt_result_text.pack(pady=5, fill=tk.BOTH, expand=True)
        
        tk.Label(self.frame, text="Quyết định An toàn:").pack(anchor="w", pady=(10,0))
        self.safety_decision = tk.Text(self.frame, width=60, height=2)
        self.safety_decision.pack(pady=5, fill=tk.BOTH, expand=True)
    
    def extract_url(self):
        if hasattr(self.parent, 'decrypted_content') and self.parent.decrypted_content:
            self.decrypted_email = self.parent.decrypted_content
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', self.decrypted_email)
            if urls:
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, urls[0])
                messagebox.showinfo("Thành công", f"Đã trích xuất URL: {urls[0]}")
            else:
                messagebox.showinfo("Thông báo", "Không tìm thấy URL trong nội dung.")
        else:
            messagebox.showerror("Lỗi", "Vui lòng giải mã ở tab trước!")
    
    def scan_url(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Lỗi", "Vui lòng nhập URL!")
            return
        
        if self.decrypted_email:
            self.decrypted_display.config(state=tk.NORMAL)
            self.decrypted_display.delete("1.0", tk.END)
            self.decrypted_display.insert("1.0", self.decrypted_email)
            self.decrypted_display.config(state=tk.DISABLED)
        
        try:
            if self.vt_api_key == "YOUR_API_KEY_HERE":
                # Fallback mô phỏng (random clean/malicious để demo)
                import random
                positives = random.randint(0, 5)  # 0 = clean, >0 = malicious
                total = 90
                result = f"Mô phỏng: Detection {positives}/{total} engines (Malicious nếu >0)"
                is_safe = positives == 0
            else:
                # Gọi API VirusTotal v2 (đơn giản hơn v3 cho demo)
                params = {'apikey': self.vt_api_key, 'url': url}
                response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
                if response.status_code == 200:
                    scan_id = response.json().get('scan_id')
                    time.sleep(15)  # Đợi scan
                    report_response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params={'apikey': self.vt_api_key, 'resource': url})
                    report = report_response.json()
                    positives = report.get('positives', 0)
                    total = report.get('total', 0)
                    result = f"Detection: {positives}/{total} engines (Malicious nếu >0)"
                    is_safe = positives == 0
                else:
                    raise Exception("API error")
            
            self.vt_result_text.delete("1.0", tk.END)
            self.vt_result_text.insert("1.0", result)
            
            decision = "AN TOÀN - Email sạch, gửi nội dung gốc" if is_safe else "NGUY HIỂM - URL độc hại, chặn email"
            color = "green" if is_safe else "red"
            self.safety_decision.delete("1.0", tk.END)
            self.safety_decision.insert("1.0", decision)
            self.safety_decision.config(fg=color)
            
            messagebox.showinfo("Thành công", f"Quét hoàn tất! {decision}")
            
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi quét: {str(e)}")
            self.vt_result_text.delete("1.0", tk.END)
            self.vt_result_text.insert("1.0", f"Lỗi: {str(e)}")

class IntegratedApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Hệ thống Bảo mật Email Toàn diện")
        self.root.geometry("900x800")
        
        # Biến chia sẻ
        self.encrypted_email_b64 = ""
        self.encrypted_aes_key_b64 = ""
        self.decrypted_content = ""
        
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.encryption_tab = HybridEncryptionTab(notebook)
        notebook.add(self.encryption_tab.frame, text="Mã hóa AES + RSA")
        
        self.dkim_tab = DKIMDMARCTab(notebook)
        notebook.add(self.dkim_tab.frame, text="DKIM + DMARC")
        
        self.vt_tab = VirusTotalTab(notebook)
        notebook.add(self.vt_tab.frame, text="VirusTotal Scan")
        
        self.root.mainloop()

if __name__ == "__main__":
    app = IntegratedApp()