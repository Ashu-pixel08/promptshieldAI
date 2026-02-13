"""
Prompt threat detection: keyword-based scoring + ML model.
Final threat score is between 0 and 10 (for Threat Meter UI).
"""

import json
import re
import sys

from ml_model import predict_prompt

# -------------------------
# Keyword detection config
# -------------------------

RISKY_ACTIONS = [
    "kill", "hack", "bypass", "override", "reveal", "disable",
    "steal", "access", "make", "create", "build", "produce", "manufacture"
]

SENSITIVE_TARGETS = [
    "human", "person", "people", "user", "system", "database",
    "password", "account", "server", "backend", "drug", "cocaine",
    "bomb", "weapon", "explosive"
]

SAFE_TARGETS = [
    "virus", "bug", "malware", "error", "issue", "file"
]

MAX_DISTANCE = 3


# -------------------------
# Utility functions
# -------------------------

def _levenshtein(a, b):
    m, n = len(a), len(b)
    dp = [[0]*(n+1) for _ in range(m+1)]

    for i in range(m+1):
        dp[i][0] = i
    for j in range(n+1):
        dp[0][j] = j

    for i in range(1, m+1):
        for j in range(1, n+1):
            cost = 0 if a[i-1] == b[j-1] else 1
            dp[i][j] = min(
                dp[i-1][j] + 1,
                dp[i][j-1] + 1,
                dp[i-1][j-1] + cost
            )

    return dp[m][n]


def _closest_match(token, candidates, max_dist):
    best = None
    best_dist = float("inf")

    for c in candidates:
        d = _levenshtein(token, c)
        if d <= max_dist and d < best_dist:
            best = c
            best_dist = d

    return best


# -------------------------
# Keyword scoring (0–5)
# -------------------------

def _keyword_score(prompt):

    lower = prompt.lower()

    normalized = re.sub(r"[^\w\s]", " ", lower)
    normalized = re.sub(r"\s+", " ", normalized).strip()

    if not normalized:
        return 0, [], []

    tokens = normalized.split()

    has_intent_phrase = (
        "how to" in normalized
        or "ways to" in normalized
        or "method to" in normalized
    )

    action_indices = []
    sensitive_indices = []
    safe_indices = []

    for idx, token in enumerate(tokens):

        action = token if token in RISKY_ACTIONS else _closest_match(token, RISKY_ACTIONS, 1)
        if action:
            action_indices.append({"word": action, "idx": idx})

        sens = token if token in SENSITIVE_TARGETS else _closest_match(token, SENSITIVE_TARGETS, 1)
        if sens:
            sensitive_indices.append({"word": sens, "idx": idx})

        safe = token if token in SAFE_TARGETS else _closest_match(token, SAFE_TARGETS, 1)
        if safe:
            safe_indices.append({"word": safe, "idx": idx})

    score = 0

    # Strong malicious pattern
    for a in action_indices:
        for t in sensitive_indices:
            if abs(a["idx"] - t["idx"]) <= MAX_DISTANCE:
                score += 3

    # Weak malicious pattern
    for a in action_indices:
        for t in safe_indices:
            if abs(a["idx"] - t["idx"]) <= MAX_DISTANCE:
                score += 1

    if has_intent_phrase:
        score += 1

    score = min(score, 5)

    detected_actions = list({a["word"] for a in action_indices})
    detected_targets = list({t["word"] for t in sensitive_indices})

    return score, detected_actions, detected_targets


# -------------------------
# Main detection function
# -------------------------

def analyze_prompt(prompt):

    prompt = (prompt or "").strip()

    keyword_score, detected_actions, detected_targets = _keyword_score(prompt)

    # keyword contributes up to 5
    score = keyword_score

    ml_prediction = "SAFE"
    ml_confidence = 0.0

    try:

        ml_result = predict_prompt(prompt)

        ml_prediction = ml_result["ml_prediction"]
        ml_confidence = ml_result["ml_confidence"]

        if ml_prediction == "MALICIOUS":

            # ML contributes up to 5
            ml_boost = ml_confidence * 5

            score += ml_boost

            # force strong malicious detection
            if ml_confidence >= 0.5:
                score = max(score, 7)

    except Exception:
        pass

    score = min(10, round(score, 1))

    # Threat levels for 10 scale
    if score <= 2:
        threat_level = "SAFE"
    elif score <= 6:
        threat_level = "MEDIUM"
    else:
        threat_level = "HIGH"

    if score >= 8:
        confidence = "high"
    elif score >= 4:
        confidence = "medium"
    else:
        confidence = "low"

    explanation = "Analysis based on keyword patterns and machine learning detection."

    return {
        "threatScore": score,
        "threatLevel": threat_level,
        "detectedActions": detected_actions,
        "detectedTargets": detected_targets,
        "mlPrediction": ml_prediction,
        "mlConfidence": ml_confidence,
        "confidence": confidence,
        "explanation": explanation,
        "scale": "0–10",
        "detectionMethod": "Keyword + Machine Learning"
    }


# -------------------------
# CLI testing
# -------------------------

def main():

    if len(sys.argv) > 1:
        prompt = sys.argv[1]
    else:
        prompt = sys.stdin.read()

    result = analyze_prompt(prompt)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()


