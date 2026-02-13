"""
Train a binary classifier (SAFE=0, MALICIOUS=1) from train.jsonl using
TfidfVectorizer and LogisticRegression. Saves model.pkl and vectorizer.pkl.
"""
import json
import os
import pickle

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


def extract_human_prompt(text: str) -> str:
    """Extract only the Human prompt part after 'Human: '."""
    if not text or "Human:" not in text:
        return ""
    # Get text after first "Human: "
    after_human = text.split("Human:", 1)[-1].strip()
    # Take only up to "Assistant:" if present (rest is model reply)
    if "Assistant:" in after_human:
        after_human = after_human.split("Assistant:")[0]
    return after_human.strip()


def preprocess(text: str) -> str:
    """Lowercase and strip whitespace."""
    return (text or "").lower().strip()


def main():
    # Project directory = parent of backend (where train.jsonl lives)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    train_path = os.path.join(project_dir, "train.jsonl")

    if not os.path.isfile(train_path):
        raise FileNotFoundError(f"Training file not found: {train_path}")

    texts = []
    labels = []

    with open(train_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            chosen = entry.get("chosen", "")
            rejected = entry.get("rejected", "")

            human_chosen = extract_human_prompt(chosen)
            human_rejected = extract_human_prompt(rejected)

            human_chosen = preprocess(human_chosen)
            human_rejected = preprocess(human_rejected)

            if human_chosen:
                texts.append(human_chosen)
                labels.append(0)  # SAFE
            if human_rejected:
                texts.append(human_rejected)
                labels.append(1)  # MALICIOUS

    if not texts:
        raise ValueError("No valid (chosen/rejected) Human prompts found in train.jsonl")

    # Features and model
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(texts)
    y = labels

    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X, y)

    # Training accuracy
    train_acc = model.score(X, y)
    print(f"Training accuracy: {train_acc:.4f}")

    # Save next to this script (in backend/)
    model_path = os.path.join(script_dir, "model.pkl")
    vec_path = os.path.join(script_dir, "vectorizer.pkl")

    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    with open(vec_path, "wb") as f:
        pickle.dump(vectorizer, f)

    print(f"Saved model to {model_path}")
    print(f"Saved vectorizer to {vec_path}")


if __name__ == "__main__":
    main()
