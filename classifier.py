# classifier.py
import re
import joblib
import os
from suggestions import get_suggestion

MODEL_DIR = "models"
CLASSIFIER_PATH = os.path.join(MODEL_DIR, "classifier.joblib")
LABEL_ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.joblib")
TFIDF_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib")
EMBEDDER_NAME_PATH = os.path.join(MODEL_DIR, "embedder_name.txt")

# Rule-based patterns (fast fallback or to increase precision)
RULES = [
    (re.compile(r"(wget|curl).*(http|https).*\.sh|\.php|/payload", re.I), "malware_download"),
    (re.compile(r"nc\s+.*(-e|--exec)|bash\s+-i\s+>&\s+/dev/tcp", re.I), "reverse_shell"),
    (re.compile(r"(cat|less|more)\s+/(etc/passwd|etc/shadow)", re.I), "credential_harvest"),
    (re.compile(r"ssh\s+.*", re.I), "brute_force"),
    (re.compile(r"find\s+.*-name", re.I), "enumeration"),
    (re.compile(r"chmod\s+\+x", re.I), "persistence_or_filesystem"),
    (re.compile(r"(uname|lsb_release|hostname|ifconfig|ip addr|dpkg -l)", re.I), "reconnaissance"),
]

def rule_based(log_text):
    for pat, label in RULES:
        if pat.search(log_text):
            return label
    return None

# lazy loads
_CLASSIFIER = None
_LABEL_ENCODER = None
_TFIDF = None
_EMBEDDER = None
_EMBEDDER_NAME = None

def load_models():
    global _CLASSIFIER, _LABEL_ENCODER, _TFIDF, _EMBEDDER, _EMBEDDER_NAME
    if _CLASSIFIER is None:
        if os.path.exists(CLASSIFIER_PATH):
            _CLASSIFIER = joblib.load(CLASSIFIER_PATH)
        else:
            _CLASSIFIER = None
    if _LABEL_ENCODER is None and os.path.exists(LABEL_ENCODER_PATH):
        _LABEL_ENCODER = joblib.load(LABEL_ENCODER_PATH)
    if _TFIDF is None and os.path.exists(TFIDF_PATH):
        _TFIDF = joblib.load(TFIDF_PATH)
    if _EMBEDDER is None and os.path.exists(EMBEDDER_NAME_PATH):
        with open(EMBEDDER_NAME_PATH, "r") as f:
            _EMBEDDER_NAME = f.read().strip()
        try:
            from sentence_transformers import SentenceTransformer
            _EMBEDDER = SentenceTransformer(_EMBEDDER_NAME)
        except Exception as e:
            _EMBEDDER = None

def predict_with_ml(log_text):
    load_models()
    # try rule-based first
    if _CLASSIFIER is None:
        return None
    # embeddings or tfidf
    try:
        if _EMBEDDER is not None:
            emb = _EMBEDDER.encode([log_text], convert_to_numpy=True)
            probs = _CLASSIFIER.predict_proba(emb)[0]
            idx = int(probs.argmax())
            label = _LABEL_ENCODER.inverse_transform([idx])[0] if _LABEL_ENCODER is not None else str(idx)
            confidence = float(probs.max())
            return label, confidence
        elif _TFIDF is not None:
            vec = _TFIDF.transform([log_text])
            probs = _CLASSIFIER.predict_proba(vec)[0]
            idx = int(probs.argmax())
            label = _LABEL_ENCODER.inverse_transform([idx])[0] if _LABEL_ENCODER is not None else str(idx)
            confidence = float(probs.max())
            return label, confidence
        else:
            return None
    except Exception as e:
        print("ML predict error:", e)
        return None

def classify_log(log_text):
    # rule-based first
    rb = rule_based(log_text)
    if rb:
        suggestion = get_suggestion(rb)
        return {"label": rb, "confidence": 1.0, "suggestion": suggestion, "source": "rule"}

    ml_res = predict_with_ml(log_text)
    if ml_res:
        label, conf = ml_res
        suggestion = get_suggestion(label)
        return {"label": label, "confidence": conf, "suggestion": suggestion, "source": "ml"}

    # fallback
    suggestion = get_suggestion("unknown")
    return {"label": "unknown", "confidence": 0.0, "suggestion": suggestion, "source": "fallback"}
