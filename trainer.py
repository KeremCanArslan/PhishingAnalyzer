import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os
import numpy as np

DATASET_FILE = "Phishing_Email.csv"

print(f"--- FİNAL EĞİTİM MODÜLÜ BAŞLATILIYOR ---")
print(f"Hedef Dosya: {DATASET_FILE}")

if not os.path.exists(DATASET_FILE):
    print(f"HATA: '{DATASET_FILE}' bulunamadı!")
    print("Lütfen dosya adının doğru olduğundan emin olun.")
    exit()

try:
    # 1. VERİYİ OKU
    try:
        df = pd.read_csv(DATASET_FILE, encoding='utf-8')
    except UnicodeDecodeError:
        print("UTF-8 okunamadı, Latin-1 deneniyor...")
        df = pd.read_csv(DATASET_FILE, encoding='latin-1')
    except pd.errors.ParserError:
        print("CSV format hatası! Python motoru ile deneniyor...")
        df = pd.read_csv(DATASET_FILE, encoding='utf-8', engine='python', on_bad_lines='skip')

    print(f"Toplam Satır Sayısı: {len(df)}")
    print("Sütunlar:", df.columns.tolist())

    # 2. SÜTUNLARI BELİRLEME
    msg_col = 'Email Text'
    label_col = 'Email Type'

    if msg_col not in df.columns:
        for col in df.columns:
            if col.lower() in ['text', 'message', 'body', 'content', 'email text']: msg_col = col
    
    if label_col not in df.columns:
        for col in df.columns:
            if col.lower() in ['type', 'label', 'class', 'email type']: label_col = col

    print(f"Mesaj Sütunu: '{msg_col}' | Etiket Sütunu: '{label_col}'")

    # 3. VERİ TEMİZLİĞİ
    df = df.dropna(subset=[msg_col, label_col])
    
    # 4. ETİKETLERİ DÖNÜŞTÜR (Safe Email -> 0, Phishing Email -> 1)
    
    def clean_label(val):
        s = str(val).lower().strip()
        if 'phishing' in s or 'spam' in s:
            return 1 # SPAM / PHISHING
        return 0 # SAFE / HAM

    df['Target'] = df[label_col].apply(clean_label)
    
    print("\nVeri Dağılımı:")
    print(df['Target'].value_counts().rename({0: 'Güvenli (Safe)', 1: 'Saldırı (Phishing)'}))

    # 5. EĞİTİM (TF-IDF)
    print("\nMetinler vektörleştiriliyor (Bu işlem biraz sürebilir)...")
    

    vectorizer = TfidfVectorizer(stop_words='english', max_features=30000)
    X = vectorizer.fit_transform(df[msg_col].astype(str))
    y = df['Target']

    # Eğitim ve Test seti (%80 eğitim, %20 test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Model eğitiliyor...")
    model = MultinomialNB(alpha=0.1) # Alpha 0.1 daha keskin öğrenme sağlar
    model.fit(X_train, y_train)

    # 6. TEST VE SONUÇ
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    
    print("-" * 40)
    print(f"MODEL DOĞRULUĞU: %{acc*100:.2f}")
    print("-" * 40)

    # 7. KAYDET
    with open("vectorizer.pkl", "wb") as f: pickle.dump(vectorizer, f)
    with open("spam_model.pkl", "wb") as f: pickle.dump(model, f)

    
    # 8. TEST
    print("ÖRNEK TEST")
    ornekler = [
        "Urgent: Your account has been suspended. Click here to verify.", # Phishing
        "Hey, are we still meeting for lunch tomorrow?", # Safe
        "Hesabınız askıya alındı, giriş yapın." 
    ]
    
    vec_ornek = vectorizer.transform(ornekler)
    probs = model.predict_proba(vec_ornek)[:, 1] * 100
    
    for text, prob in zip(ornekler, probs):
        durum = "SALDIRI (PHISHING)" if prob > 50 else "GÜVENLİ"
        print(f"Mesaj: '{text}' -> %{prob:.2f} {durum}")

except Exception as e:
    print(f"\nBeklenmedik bir hata oluştu: {e}")