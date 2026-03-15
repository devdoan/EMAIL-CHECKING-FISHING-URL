# -*- coding: utf-8 -*-
import pandas as pd
import numpy as np
import time
import json
import tensorflow as tf
from transformers import DistilBertTokenizer, TFDistilBertModel
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
from tqdm import tqdm

# --- CẤU HÌNH ---
DATASET_PATH = "malicious_phish.csv"
MODEL_SAVE_PATH = "bert_phishing_model.keras"
TOKENIZER_SAVE_PATH = "bert_tokenizer"

# Cấu hình BERT
BERT_MODEL_NAME = 'distilbert-base-uncased'
MAX_LENGTH = 128 # Độ dài tối đa của một URL (sau khi token hóa)

# --- BƯỚC 1 ---

def load_data():

    print(f"\n[1/5] Đang tải dữ liệu từ '{DATASET_PATH}'...")
    try:
        df = pd.read_csv(DATASET_PATH)
    except FileNotFoundError:
        print(f"❌ LỖI: Không tìm thấy tệp '{DATASET_PATH}'."); return None, None

    print(f"Đã tải {len(df)} hàng dữ liệu.")
    df['label'] = df['type'].map({'benign': 0, 'phishing': 1, 'malware': 1, 'defacement': 1})
    df = df.dropna(subset=['url', 'label'])
    df['label'] = df['label'].astype(int)
    print("Ánh xạ nhãn hoàn tất.")

    return df['url'].values, df['label'].values

# --- TOKEN HÓA (Tokenization) ---

def tokenize_data(urls, tokenizer):
    """Biến danh sách các chuỗi URL thành các vector số (tokens)."""
    print(f"\n[2/5] Bắt đầu Token hóa {len(urls)} URL (sử dụng {BERT_MODEL_NAME})...")
    print(f"(Việc này có thể mất vài phút...)")

    # Chuẩn bị 2 mảng numpy rỗng
    input_ids = np.zeros((len(urls), MAX_LENGTH), dtype='int32')
    attention_masks = np.zeros((len(urls), MAX_LENGTH), dtype='int32')

    for i, url in enumerate(tqdm(urls, desc="Đang Token hóa")):
        try:
            encoded = tokenizer.encode_plus(
                url,
                add_special_tokens=True,
                max_length=MAX_LENGTH,
                padding='max_length',
                truncation=True,
                return_attention_mask=True,
                return_tensors='np'
            )
            input_ids[i] = encoded['input_ids'][0]
            attention_masks[i] = encoded['attention_mask'][0]
        except Exception as e:
            print(f"Lỗi khi token hóa URL: {url} - {e}")
            input_ids[i] = np.zeros((MAX_LENGTH,), dtype='int32') # Vector rỗng nếu lỗi
            attention_masks[i] = np.zeros((MAX_LENGTH,), dtype='int32')

    print("Token hóa hoàn tất.")
    return input_ids, attention_masks

# --- XÂY DỰNG MÔ HÌNH (Fine-tuning) ---

def build_model():

    print("\n[3/5] Đang xây dựng mô hình (Tải DistilBERT)...")

    # Tải mô hình BERT gốc

    bert_model = TFDistilBertModel.from_pretrained(BERT_MODEL_NAME, from_pt=True)

    bert_model.trainable = False # <-- Đóng băng (Freeze) các lớp BERT


    # Định nghĩa các lớp Input
    input_ids_layer = tf.keras.layers.Input(shape=(MAX_LENGTH,), name='input_ids', dtype='int32')
    attention_mask_layer = tf.keras.layers.Input(shape=(MAX_LENGTH,), name='attention_mask', dtype='int32')

    # Kết nối BERT
    bert_output = bert_model(input_ids_layer, attention_mask=attention_mask_layer)[0]

    # Thêm "đầu" (head) phân loại
    cls_token = bert_output[:, 0, :] # Lấy vector [CLS] (đại diện cho cả câu)

    x = tf.keras.layers.Dense(128, activation='relu')(cls_token)
    x = tf.keras.layers.Dropout(0.2)(x)
    output_layer = tf.keras.layers.Dense(1, activation='sigmoid')(x) # 1 neuron (0 hoặc 1)

    # Tạo mô hình
    model = tf.keras.Model(inputs=[input_ids_layer, attention_mask_layer], outputs=output_layer)

    # iên dịch (Compile) mô hình
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-4),
        loss='binary_crossentropy',
        metrics=['accuracy']
    )

    print("Xây dựng mô hình hoàn tất.")
    model.summary() # In cấu trúc mô hình
    return model

# ---  HUẤN LUYỆN VÀ ĐÁNH GIÁ ---

def main():
    print("--- BẮT ĐẦU GIAI ĐOẠN 11.0: HUẤN LUYỆN MÔ HÌNH BERT ---")

    # Tải dữ liệu
    urls, labels = load_data()
    if urls is None: return

    # Token hóa
    tokenizer = DistilBertTokenizer.from_pretrained(BERT_MODEL_NAME)
    input_ids, attention_masks = tokenize_data(urls, tokenizer)

    # Chia dữ liệu
    print("\n[3/5] Đang chia dữ liệu (80% Train, 20% Test)...")
    X_train_ids, X_test_ids, y_train, y_test = train_test_split(input_ids, labels, test_size=0.2, random_state=42, stratify=labels)
    X_train_masks, X_test_masks, _, _ = train_test_split(attention_masks, labels, test_size=0.2, random_state=42, stratify=labels)

    # Đóng gói dữ liệu test
    X_test = {'input_ids': X_test_ids, 'attention_mask': X_test_masks}

    # Xây dựng mô hình
    model = build_model()

    # Huấn luyện
    print("\n[4/5] Bắt đầu huấn luyện mô hình (Fine-tuning)...")
    print("(Việc này sẽ mất RẤT LÂU nếu không có GPU)")
    start_time = time.time()

    history = model.fit(
        x={'input_ids': X_train_ids, 'attention_mask': X_train_masks},
        y=y_train,
        validation_data=(X_test, y_test),
        epochs=3, #đủ cho fine-tuning
        batch_size=64
    )

    end_time = time.time()
    print(f"✅ Huấn luyện hoàn tất sau {end_time - start_time:.2f} giây.")

    # 6. Đánh giá
    print("\n[5/5] Đang đánh giá và lưu mô hình...")
    y_pred_probs = model.predict(X_test)
    y_pred = (y_pred_probs > 0.5).astype(int)

    print("\n--- BÁO CÁO KẾT QUẢ (Test Set) ---")
    print(classification_report(y_test, y_pred, target_names=['An toàn (Benign)', 'Độc hại (Malicious)']))

    accuracy = accuracy_score(y_test, y_pred)
    print(f"Độ chính xác (Accuracy): {accuracy * 100:.2f}%")

    # 7. Lưu trữ
    print(f"\n✅ ĐÃ LƯU MÔ HÌNH VÀO TỆP: '{MODEL_SAVE_PATH}'")
    model.save(MODEL_SAVE_PATH)

    print(f"✅ ĐÃ LƯU TOKENIZER VÀO THƯ MỤC: '{TOKENIZER_SAVE_PATH}'")
    tokenizer.save_pretrained(TOKENIZER_SAVE_PATH)

    # Ma trận Nhầm lẫn
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Dự đoán An toàn', 'Dự đoán Độc hại'],
                yticklabels=['Thực tế An toàn', 'Thực tế Độc hại'])
    plt.title(f'Ma trận Nhầm lẫn (Confusion Matrix) - {BERT_MODEL_NAME}')
    plt.ylabel('Thực tế')
    plt.xlabel('Dự đoán')
    plt.show()

if __name__ == "__main__":
    main()