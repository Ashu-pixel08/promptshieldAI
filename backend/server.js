require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { getAllRecords, insertRecord } = require("./db");

const app = express();

// Basic middleware
app.use(
  cors({
    origin: "*",
  })
);
app.use(express.json());

const PORT = process.env.PORT || 5000;

// --- Context-aware prompt analysis engine ---
function analyzePromptContext(prompt) {
  const original = typeof prompt === "string" ? prompt : "";
  const lower = original.toLowerCase();

  // 1) Normalize: remove punctuation, collapse spaces.
  const normalized = lower
    .replace(/[^\w\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  if (!normalized) {
    return {
      threatScore: 0,
      threatLevel: "SAFE",
      detectedActions: [],
      detectedTargets: [],
      explanation:
        "No meaningful text was provided, so no risky patterns could be detected.",
      confidence: "low",
    };
  }

  const tokens = normalized.split(" ").filter(Boolean);

  // 2) Intent phrases (simple detection over normalized string).
  const hasIntentPhrase =
    normalized.includes("how to") ||
    normalized.includes("ways to") ||
    normalized.includes("method to");

  // 3) Actions and targets (with simple synonym expansion).
  const riskyActions = [
    "kill",
    "hack",
    "bypass",
    "override",
    "reveal",
    "disable",
    "steal",
    "access",
  ];

  const sensitiveTargets = [
    // Core
    "human",
    "person",
    "people",
    "user",
    "users",
    "system",
    "database",
    "password",
    "account",
    "server",
    "ai",
    // Synonyms / related
    "individual",
    "someone",
    "anyone",
    "backend",
  ];

  const safeTargets = [
    // Core
    "virus",
    "bug",
    "malware",
    "error",
    "issue",
    "file",
    // Synonyms / related
    "trojan",
    "worm",
    "glitch",
  ];

  // Simple edit‑distance matcher to handle small typos like "kil" → "kill".
  function levenshtein(a, b) {
    const m = a.length;
    const n = b.length;
    const dp = Array.from({ length: m + 1 }, () =>
      new Array(n + 1).fill(0)
    );

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1, // deletion
          dp[i][j - 1] + 1, // insertion
          dp[i - 1][j - 1] + cost // substitution
        );
      }
    }
    return dp[m][n];
  }

  function closestMatch(token, candidates, maxDistance) {
    let best = null;
    let bestDist = Infinity;
    for (const cand of candidates) {
      const d = levenshtein(token, cand);
      if (d <= maxDistance && d < bestDist) {
        best = cand;
        bestDist = d;
      }
    }
    return best;
  }

  const detectedActionsSet = new Set();
  const detectedTargetsSet = new Set();

  const actionIndices = [];
  const sensitiveIndices = [];
  const safeIndices = [];

  tokens.forEach((token, idx) => {
    // Map token to closest risky action (if any) so that small
    // spelling mistakes like "kil" still count as "kill".
    let action = null;
    if (riskyActions.includes(token)) {
      action = token;
    } else {
      action = closestMatch(token, riskyActions, 1);
    }
    if (action) {
      detectedActionsSet.add(action);
      actionIndices.push({ word: action, idx });
    }

    // Do the same for sensitive and safe targets.
    let sensitive = null;
    if (sensitiveTargets.includes(token)) {
      sensitive = token;
    } else {
      sensitive = closestMatch(token, sensitiveTargets, 1);
    }
    if (sensitive) {
      detectedTargetsSet.add(sensitive);
      sensitiveIndices.push({ word: sensitive, idx });
    }

    let safe = null;
    if (safeTargets.includes(token)) {
      safe = token;
    } else {
      safe = closestMatch(token, safeTargets, 1);
    }
    if (safe) {
      detectedTargetsSet.add(safe);
      safeIndices.push({ word: safe, idx });
    }
  });

  // 2-word phrase chunks (for explanation purposes and a bit of extra context).
  const phrasePairs = [];
  for (let i = 0; i < tokens.length - 1; i++) {
    phrasePairs.push(`${tokens[i]} ${tokens[i + 1]}`);
  }

  let score = 0;
  const explanationParts = [];

  const usedActionIdx = new Set();
  const usedTargetIdx = new Set();

  // Helper to record combinations in the explanation.
  function recordCombo(action, target, severity) {
    if (severity === "high") {
      explanationParts.push(
        `Detected a risky action "${action}" targeting sensitive term "${target}", which indicates potentially harmful intent.`
      );
    } else if (severity === "safe") {
      explanationParts.push(
        `Action "${action}" appears to target "${target}", which is typically safe in a cybersecurity or debugging context.`
      );
    }
  }

  // 4) Context scoring: action + sensitive target (HIGH) / action + safe target (SAFE).
  const MAX_DISTANCE = 3; // tokens window for "same context"

  // High‑risk combos: dangerous action + sensitive target.
  actionIndices.forEach((a) => {
    sensitiveIndices.forEach((t) => {
      if (
        Math.abs(a.idx - t.idx) <= MAX_DISTANCE &&
        !usedActionIdx.has(a.idx) &&
        !usedTargetIdx.has(t.idx)
      ) {
        usedActionIdx.add(a.idx);
        usedTargetIdx.add(t.idx);
        score += 5;
        recordCombo(a.word, t.word, "high");
      }
    });
  });

  // Safe‑leaning combos: dangerous action + safe target.
  actionIndices.forEach((a) => {
    safeIndices.forEach((t) => {
      if (
        Math.abs(a.idx - t.idx) <= MAX_DISTANCE &&
        !usedActionIdx.has(a.idx) &&
        !usedTargetIdx.has(t.idx)
      ) {
        usedActionIdx.add(a.idx);
        usedTargetIdx.add(t.idx);
        // 0 or +1 – we choose +1 to keep mild signal while staying "SAFE".
        score += 1;
        recordCombo(a.word, t.word, "safe");
      }
    });
  });

  // Remaining actions without explicit targets: medium risk.
  actionIndices.forEach((a) => {
    if (!usedActionIdx.has(a.idx)) {
      usedActionIdx.add(a.idx);
      score += 2;
      explanationParts.push(
        `Detected risky action "${a.word}" without an explicit target; context may still be harmful depending on how it is used.`
      );
    }
  });

  // Intent phrases + any risky combination -> extra risk.
  if (hasIntentPhrase && score > 0) {
    score += 2;
    explanationParts.push(
      'Prompt uses instructional phrasing (e.g., "how to", "ways to", or "method to"), which strengthens the indication of harmful intent around detected actions/targets.'
    );
  }

  // Cap score at 10.
  if (score > 10) score = 10;

  // 5) Threat classification.
  let threatLevel = "SAFE";
  if (score === 0) {
    threatLevel = "SAFE";
  } else if (score <= 4) {
    threatLevel = "MEDIUM";
  } else {
    threatLevel = "HIGH";
  }

  // Simple confidence heuristic.
  let confidence = "medium";
  if (score >= 7) {
    confidence = "high";
  } else if (score <= 2) {
    confidence = "low";
  }

  const detectedActions = Array.from(detectedActionsSet);
  const detectedTargets = Array.from(detectedTargetsSet);

  if (explanationParts.length === 0) {
    explanationParts.push(
      "No risky action/target patterns were detected. The prompt appears safe based on current heuristics."
    );
  }

  const explanation = explanationParts.join(" ");

  return {
    threatScore: score,
    threatLevel,
    detectedActions,
    detectedTargets,
    explanation,
    confidence,
  };
}

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    message: "PromptShield backend is running.",
  });
});

// List all records for cards
app.get("/api/records", async (req, res) => {
  try {
    const rows = await getAllRecords();
    res.json(rows);
  } catch (err) {
    console.error("Error fetching records:", err);
    res.status(500).json({ error: "Failed to fetch records." });
  }
});

// Create a new record:
// - receives user input from frontend
// - forwards to upstream ANALYZE_URL
// - stores input + analysis in SQLite
// - returns the created record
app.post("/api/records", async (req, res) => {
  const { prompt } = req.body || {};

  if (!prompt || typeof prompt !== "string" || !prompt.trim()) {
    return res
      .status(400)
      .json({ error: "Missing or invalid 'prompt' field in request body." });
  }

  let analysisText = "";

  try {
    const analysisResult = analyzePromptContext(prompt);
    analysisText = JSON.stringify(analysisResult, null, 2);
  } catch (err) {
    console.error("Error running local analysis engine:", err);
    analysisText =
      "Error running local analysis engine. Saved prompt without structured analysis.";
  }

  try {
    const record = await insertRecord(prompt.trim(), analysisText);
    res.status(201).json(record);
  } catch (err) {
    console.error("Error inserting record into database:", err);
    res.status(500).json({ error: "Failed to save record to database." });
  }
});

// Standalone analysis endpoint for direct use.
app.post("/analyze", (req, res) => {
  const { prompt } = req.body || {};

  if (!prompt || typeof prompt !== "string" || !prompt.trim()) {
    return res
      .status(400)
      .json({ error: "Missing or invalid 'prompt' field in request body." });
  }

  try {
    const result = analyzePromptContext(prompt);
    return res.json(result);
  } catch (err) {
    console.error("Error in /analyze endpoint:", err);
    return res.status(500).json({
      error: "Internal error while analyzing prompt.",
    });
  }
});

app.listen(PORT, () => {
  console.log(`PromptShield backend listening on http://localhost:${PORT}`);
});

