"""Called by Node to get ML prediction JSON. Reads prompt from stdin, prints JSON to stdout."""
import json
import sys

try:
    from ml_model import predict_prompt
    prompt = sys.stdin.read()
    result = predict_prompt(prompt)
    print(json.dumps(result))
except Exception:
    print(json.dumps({"ml_prediction": "SAFE", "ml_confidence": 0}))
