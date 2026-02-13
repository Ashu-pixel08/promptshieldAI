"""
Load model.pkl and vectorizer.pkl once at startup; expose predict_prompt(prompt).
"""
import os
import pickle


def _artifact_path(filename):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, filename)


def load_model():
    """Load model.pkl once. Call at module load; reuse the returned object."""
    path = _artifact_path("model.pkl")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Model file not found. Run ml_train.py first. Expected: {path}")
    with open(path, "rb") as f:
        return pickle.load(f)


def load_vectorizer():
    """Load vectorizer.pkl once. Call at module load; reuse the returned object."""
    path = _artifact_path("vectorizer.pkl")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Vectorizer file not found. Run ml_train.py first. Expected: {path}")
    with open(path, "rb") as f:
        return pickle.load(f)


# Load once when this module is imported (server start). Do NOT reload per request.
try:
    model = load_model()
    vectorizer = load_vectorizer()
except FileNotFoundError:
    model = None
    vectorizer = None


def _preprocess(prompt: str) -> str:
    """Lowercase and strip whitespace (match ml_train preprocessing)."""
    return (prompt or "").lower().strip()


# Safe default when model/vectorizer missing or prediction fails (fallback to keyword-only detection).
_SAFE_DEFAULT = {"ml_prediction": "SAFE", "ml_confidence": 0.0}


def predict_prompt(prompt: str) -> dict:
    """
    Preprocess prompt, transform with vectorizer, predict with model.
    Reuses global model and vectorizer; does not reload.
    If model.pkl or vectorizer.pkl not found (or any error): returns safe default, does not crash.
    Returns {"ml_prediction": "SAFE"|"MALICIOUS", "ml_confidence": float in [0, 1]}.
    """
    if model is None or vectorizer is None:
        return _SAFE_DEFAULT.copy()
    try:
        text = _preprocess(prompt)
        X = vectorizer.transform([text])
        pred = model.predict(X)[0]
        proba = model.predict_proba(X)[0]
        # pred: 0 = SAFE, 1 = MALICIOUS (same as ml_train)
        label = "SAFE" if pred == 0 else "MALICIOUS"
        confidence = float(proba[pred])
        return {
            "ml_prediction": label,
            "ml_confidence": round(confidence, 4),
        }
    except Exception:
        return _SAFE_DEFAULT.copy()
