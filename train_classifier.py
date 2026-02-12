# train_classifier.py
"""
Train a classifier that uses sentence-transformers embeddings + LightGBM (preferred)
or RandomForest (fallback). Saves:
 - /models/embedder_name.txt   (the sentence-transformers model name used)
 - /models/classifier.joblib    (trained classifier)
 - /models/label_encoder.joblib (optional label encoder)
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
from tqdm import tqdm

# Preferred libraries (you must install these locally)
# pip install sentence-transformers lightgbm scikit-learn joblib tqdm

try:
    from sentence_transformers import SentenceTransformer
    EMBED_AVAILABLE = True
except Exception as e:
    EMBED_AVAILABLE = False
    print("sentence-transformers not available. Please pip install sentence-transformers to use embeddings.")

try:
    import lightgbm as lgb
    LGB_AVAILABLE = True
except Exception:
    LGB_AVAILABLE = False
    print("lightgbm not available. Will fallback to RandomForestClassifier.")

from sklearn.ensemble import RandomForestClassifier

DATA_PATH = "data/synthetic_honeypot_logs_1000.csv"
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

EMBEDDER_NAME = "all-MiniLM-L6-v2"  # small and fast; change if you want

def load_data(path=DATA_PATH):
    df = pd.read_csv(path)
    # ensure text field
    df['log'] = df['log'].astype(str)
    df['label'] = df['label'].astype(str)
    return df

def compute_embeddings(texts, embedder):
    # returns numpy array (n_samples, emb_dim)
    return embedder.encode(texts, show_progress_bar=True, convert_to_numpy=True)

def main():
    df = load_data()
    X = df['log'].tolist()
    y = df['label'].tolist()

    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    joblib.dump(le, os.path.join(MODEL_DIR, "label_encoder.joblib"))
    print("Saved label encoder.")

    X_train, X_test, y_train, y_test = train_test_split(X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)

    # embeddings
    if EMBED_AVAILABLE:
        embedder = SentenceTransformer(EMBEDDER_NAME)
        print("Computing embeddings (this may take a while)...")
        X_train_emb = compute_embeddings(X_train, embedder)
        X_test_emb = compute_embeddings(X_test, embedder)
        # save which embedder we used
        with open(os.path.join(MODEL_DIR, "embedder_name.txt"), "w") as f:
            f.write(EMBEDDER_NAME)
    else:
        # fallback: simple TF-IDF (not ideal but works if embeddings unavailable)
        from sklearn.feature_extraction.text import TfidfVectorizer
        tfidf = TfidfVectorizer(ngram_range=(1,3), max_features=20000)
        X_train_emb = tfidf.fit_transform(X_train)
        X_test_emb = tfidf.transform(X_test)
        joblib.dump(tfidf, os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib"))
        print("Saved TF-IDF vectorizer as fallback.")

    # classifier
    if LGB_AVAILABLE:
        clf = lgb.LGBMClassifier(n_estimators=500, n_jobs=-1, random_state=42)
        clf.fit(X_train_emb, y_train)
    else:
        clf = RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=42)
        clf.fit(X_train_emb, y_train)

    # evaluate
    preds = clf.predict(X_test_emb)
    acc = accuracy_score(y_test, preds)
    print(f"Test accuracy: {acc:.4f}")
    print("Classification report:")
    print(classification_report(y_test, preds, target_names=le.classes_))

    joblib.dump(clf, os.path.join(MODEL_DIR, "classifier.joblib"))
    print(f"Saved classifier to {os.path.join(MODEL_DIR,'classifier.joblib')}")

if __name__ == "__main__":
    main()
