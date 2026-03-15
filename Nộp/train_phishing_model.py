# -*- coding: utf-8 -*-
import pandas as pd
import numpy as np
import re
import joblib
from urllib.parse import urlparse
from tldextract import extract
import time
from tqdm import tqdm
import json

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler # <-- Để chuẩn hóa dữ liệu
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression # <-- Model 1
from sklearn.svm import LinearSVC                 # <-- Model 2 (Nhanh hơn SVC)
import xgboost as xgb                             # <-- Model 3
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, f1_score, roc_curve, roc_auc_score # <-- THÊM: Import ROC metrics
import seaborn as sns
import matplotlib.pyplot as plt

# --- CẤU HÌNH ---

DATASET_PATH = "malicious_phish.csv"
MODEL_PATH = "phishing_model.joblib"
FEATURE_NAMES_PATH = "phishing_model_features.json"
SCALER_PATH = "phishing_model_scaler.joblib"

# --- BƯỚC 2: TRÍCH XUẤT ĐẶC TRƯNG  ---

# Danh sách từ khóa nghi ngờ
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'secure', 'update', 'banking', 'signin',
    'password', 'ebay', 'paypal', 'webscr', 'cmd', 'bin'
]

# Danh sách các đặc trưng (12)
FEATURE_NAMES = [
    'url_length', 'has_ip', 'count_at', 'count_slash', 'count_hyphen',
    'count_dot', 'has_https', 'domain_length', 'subdomain_length',
    'subdomain_dot_count', 'suspicious_keyword_count', 'is_common_suffix'
]

def extract_features(url):

    features = []

    try:
        parsed_url = urlparse(url)
        domain_parts = extract(url)
        domain = domain_parts.domain
        subdomain = domain_parts.subdomain
        suffix = domain_parts.suffix

        features.append(len(url)) # 1
        features.append(1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0) # 2
        features.append(url.count('@')) # 3
        features.append(url.count('/')) # 4
        features.append(url.count('-')) # 5
        features.append(url.count('.')) # 6
        features.append(1 if parsed_url.scheme == 'https' else 0) # 7
        features.append(len(domain)) # 8
        features.append(len(subdomain)) # 9
        features.append(subdomain.count('.')) # 10

        keyword_count = 0
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url.lower():
                keyword_count += 1
        features.append(keyword_count) # 11

        features.append(1 if suffix in ['com', 'org', 'net', 'gov', 'edu'] else 0) # 12

        # Đảm bảo luôn trả về đúng 12 đặc trưng
        if len(features) != 12: return [0] * 12

        return features

    except Exception as e:
        print(f"Lỗi khi xử lý URL: {url} - {e}")
        return [0] * 12 # 12 là tổng số đặc trưng

# --- BƯỚC 3: HUẤN LUYỆN VÀ ĐÁNH GIÁ MÔ HÌNH ---

def main():
    print("--- BẮT ĐẦU GIAI ĐOẠN 10.0 (PHẦN A, v2): SO SÁNH CÁC MÔ HÌNH ---")


    print(f"\n[1/7] Đang tải dữ liệu từ '{DATASET_PATH}'...")
    try:
        df = pd.read_csv(DATASET_PATH)
    except FileNotFoundError:
        print(f"❌ LỖI: Không tìm thấy tệp '{DATASET_PATH}'."); return

    print(f"Đã tải {len(df)} hàng dữ liệu.")

    print("Column names in the dataframe:", df.columns.tolist())

    df['label'] = df['type'].map({'benign': 0, 'phishing': 1, 'malware': 1, 'defacement': 1})
    df = df.dropna(subset=['url', 'label']) # Corrected column name to 'url'
    df['label'] = df['label'].astype(int)
    print("Ánh xạ nhãn hoàn tất.")


    print("\n[2/7] Bắt đầu trích xuất đặc trưng (Feature Engineering)...")
    tqdm.pandas(desc="Đang xử lý URL")
    df['features'] = df['url'].progress_apply(extract_features) # Corrected column name to 'url'
    print("Trích xuất đặc trưng hoàn tất.")


    print("\n[3/7] Đang chia dữ liệu (80% Train, 20% Test)...")
    X = np.array(list(df['features']))
    y = df['label'].values

    # Lưu lại tên các đặc trưng
    with open(FEATURE_NAMES_PATH, "w") as f:
        json.dump(FEATURE_NAMES, f)
    print(f"Đã lưu tên đặc trưng vào '{FEATURE_NAMES_PATH}'")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f" - Kích thước tập Train: {X_train.shape[0]}")
    print(f" - Kích thước tập Test: {X_test.shape[0]}")

    # --- CHUẨN HÓA DỮ LIỆU ---
    print("\n[4/7] Đang chuẩn hóa dữ liệu (StandardScaler)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Lưu lại scaler
    joblib.dump(scaler, SCALER_PATH)
    print(f"✅ Đã lưu scaler vào tệp: '{SCALER_PATH}'")


    print("\n[5/7] Bắt đầu huấn luyện và so sánh các mô hình...")

    # Định nghĩa các mô hình
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, n_jobs=-1, random_state=42),
        "Linear SVM (LinearSVC)": LinearSVC(dual=False, max_iter=2000, random_state=42), # dual=False nhanh hơn
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, max_depth=20),
        "XGBoost": xgb.XGBClassifier(n_estimators=100, random_state=42, n_jobs=-1, use_label_encoder=False, eval_metric='logloss')
    }

    results = []
    best_model_name = ""
    best_model_object = None
    best_f1 = -1.0

    for name, model in models.items():
        print(f"\n--- Đang huấn luyện: {name} ---")
        start_time = time.time()

        # QUAN TRỌNG: Dùng data đã scale cho LR và SVM
        if name in ["Logistic Regression", "Linear SVM (LinearSVC)"]:
            model.fit(X_train_scaled, y_train)
            y_pred = model.predict(X_test_scaled)
            # Cần predict_proba cho ROC curve, nhưng LinearSVC không có predict_proba
            # Logistic Regression có predict_proba
            if hasattr(model, "predict_proba"):
                 y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
            else:
                 # Đối với LinearSVC, dùng decision_function và chuyển đổi sang xác suất
                 # (Tuy nhiên, việc này có thể không chính xác hoàn toàn như predict_proba)
                 # Bỏ qua ROC cho LinearSVC nếu không có predict_proba rõ ràng
                 y_pred_proba = None # Sẽ xử lý sau để không vẽ ROC nếu None
        else: # Tree models không cần scale
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1]


        end_time = time.time()

        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred) # F1-score là chỉ số tốt nhất để so sánh

        # --- Tính và hiển thị ROC AUC ---
        roc_auc = None
        if y_pred_proba is not None:
             try:
                 roc_auc = roc_auc_score(y_test, y_pred_proba)
                 print(f"ROC AUC: {roc_auc:.4f}")
             except Exception as e:
                 print(f"Lỗi tính ROC AUC cho {name}: {e}")
                 roc_auc = None



        print(f"Hoàn tất sau {end_time - start_time:.2f} giây.")
        print(f"Accuracy: {accuracy * 100:.2f}%")
        print(f"F1-Score: {f1:.4f}")


        results.append({"Tên Mô hình": name, "Accuracy": accuracy, "F1-Score": f1, "Thời gian (s)": end_time - start_time, "ROC AUC": roc_auc}) # <-- THÊM: Thêm ROC AUC vào kết quả

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model_object = model

        # --- In báo cáo phân loại chi tiết (precision, recall, support) ---
        print("\n--- BÁO CÁO KẾT QUẢ CHI TIẾT (Test Set) ---")
        print(classification_report(y_test, y_pred, target_names=['An toàn (Benign)', 'Độc hại (Malicious)']))



        # --- Vẽ Ma trận Nhầm lẫn cho từng mô hình ---
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(6, 4))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                    xticklabels=['Dự đoán An toàn', 'Dự đoán Độc hại'],
                    yticklabels=['Thực tế An toàn', 'Thực tế Độc hại'])
        plt.title(f'Ma trận Nhầm lẫn - {name}')
        plt.ylabel('Thực tế')
        plt.xlabel('Dự đoán')
        plt.show()


        # --- Vẽ biểu đồ ROC cho từng mô hình (nếu có predict_proba) ---
        if y_pred_proba is not None:
             try:
                 fpr, tpr, thresholds = roc_curve(y_test, y_pred_proba)
                 plt.figure(figsize=(6, 4))
                 plt.plot(fpr, tpr, label=f'{name} (AUC = {roc_auc:.4f})')
                 plt.plot([0, 1], [0, 1], 'k--') # Đường chéo ngẫu nhiên
                 plt.xlim([0.0, 1.0])
                 plt.ylim([0.0, 1.05])
                 plt.xlabel('False Positive Rate (FPR)')
                 plt.ylabel('True Positive Rate (TPR)')
                 plt.title(f'Đường cong ROC - {name}')
                 plt.legend(loc="lower right")
                 plt.show()
             except Exception as e:
                  print(f"Lỗi vẽ ROC curve cho {name}: {e}")





    print(f"\n[6/7] Huấn luyện hoàn tất. Đang lưu mô hình TỐT NHẤT...")

    # In bảng kết quả
    results_df = pd.DataFrame(results).sort_values(by='F1-Score', ascending=False)
    print("\n--- BẢNG SO SÁNH KẾT QUẢ (Sắp xếp theo F1-Score) ---")
    print(results_df.to_string(index=False, float_format="%.4f"))

    # Lưu mô hình tốt nhất
    joblib.dump(best_model_object, MODEL_PATH)
    print(f"\n✅ ĐÃ LƯU MÔ HÌNH TỐT NHẤT ({best_model_name}) VÀO TỆP: '{MODEL_PATH}'")

    # === ĐÁNH GIÁ CHI TIẾT MÔ HÌNH TỐT NHẤT ===
    print(f"\n[7/7] Đánh giá chi tiết mô hình '{best_model_name}'...")

    # Cần dự đoán lại
    if best_model_name in ["Logistic Regression", "Linear SVM (LinearSVC)"]:
        X_test_best = X_test_scaled
    else:
        X_test_best = X_test

    y_pred_best = best_model_object.predict(X_test_best)

    # --- Báo cáo chi tiết ROC AUC và Confusion Matrix cho mô hình tốt nhất ---
    print("\n--- ĐÁNH GIÁ CHI TIẾT MÔ HÌNH TỐT NHẤT ---")
    # Chỉ tính predict_proba nếu mô hình có
    if hasattr(best_model_object, "predict_proba"):
         y_pred_proba_best = best_model_object.predict_proba(X_test_best)[:, 1]
         try:
             roc_auc_best = roc_auc_score(y_test, y_pred_proba_best)
             print(f"ROC AUC (Mô hình Tốt nhất - {best_model_name}): {roc_auc_best:.4f}")
         except Exception as e:
              print(f"Lỗi tính ROC AUC cho mô hình tốt nhất ({best_model_name}): {e}")
    else:
         print(f"Mô hình tốt nhất ({best_model_name}) không hỗ trợ predict_proba cho ROC AUC.")



    print("\n--- BÁO CÁO KẾT QUẢ (Test Set) ---")
    print(classification_report(y_test, y_pred_best, target_names=['An toàn (Benign)', 'Độc hại (Malicious)']))

    cm = confusion_matrix(y_test, y_pred_best)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Dự đoán An toàn', 'Dự đoán Độc hại'],
                yticklabels=['Thực tế An toàn', 'Thực tế Độc hại'])
    plt.title(f'Ma trận Nhầm lẫn (Confusion Matrix) - {best_model_name}')
    plt.ylabel('Thực tế')
    plt.xlabel('Dự đoán')
    plt.show()

    # Vẽ biểu đồ ROC cho mô hình tốt nhất (nếu có predict_proba)
    if hasattr(best_model_object, "predict_proba"):
         try:
             fpr_best, tpr_best, thresholds_best = roc_curve(y_test, y_pred_proba_best)
             plt.figure(figsize=(8, 6))
             plt.plot(fpr_best, tpr_best, label=f'{best_model_name} (AUC = {roc_auc_best:.4f})')
             plt.plot([0, 1], [0, 1], 'k--') # Đường chéo ngẫu nhiên
             plt.xlim([0.0, 1.0])
             plt.ylim([0.0, 1.05])
             plt.xlabel('False Positive Rate (FPR)')
             plt.ylabel('True Positive Rate (TPR)')
             plt.title(f'Đường cong ROC - {best_model_name}')
             plt.legend(loc="lower right")
             plt.show()
         except Exception as e:
              print(f"Lỗi vẽ ROC curve cho mô hình tốt nhất ({best_model_name}): {e}")



if __name__ == "__main__":
    main()