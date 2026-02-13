const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const { spawnSync } = require("child_process");

// Path to database
const DB_PATH = path.join(__dirname, "promptshield.db");

// Path to detector.py
const DETECTOR_PATH = path.join(__dirname, "detector.py");

// Connect database
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("Failed to connect to SQLite database:", err);
  } else {
    console.log("Connected to SQLite database at", DB_PATH);
  }
});

// Create table if not exists
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_input TEXT NOT NULL,
      analysis TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    (err) => {
      if (err) {
        console.error("Error creating records table:", err);
      } else {
        console.log("Ensured records table exists.");
      }
    }
  );
});


// ============================
// CALL PYTHON DETECTOR
// ============================

function analyzePromptWithPython(prompt) {

  try {

    const result = spawnSync("python", [DETECTOR_PATH, prompt], {
      encoding: "utf-8"
    });

    if (result.error) {
      console.error("Python execution error:", result.error);
      return null;
    }

    if (!result.stdout) {
      console.error("Python returned empty result");
      return null;
    }

    const analysis = JSON.parse(result.stdout);

    return analysis;

  } catch (err) {

    console.error("Detector error:", err);
    return null;

  }

}


// ============================
// GET ALL RECORDS
// ============================

function getAllRecords() {

  return new Promise((resolve, reject) => {

    db.all(
      "SELECT id, user_input, analysis, created_at FROM records ORDER BY created_at DESC",
      (err, rows) => {

        if (err) {
          return reject(err);
        }

        resolve(rows || []);

      }
    );

  });

}


// ============================
// INSERT RECORD WITH AI ANALYSIS
// ============================

function insertRecord(userInput) {

  return new Promise((resolve, reject) => {

    // Call Python detector
    const analysisResult = analyzePromptWithPython(userInput);

    if (!analysisResult) {
      return reject(new Error("Failed to analyze prompt"));
    }

    const analysisJSON = JSON.stringify(analysisResult);

    const sql =
      "INSERT INTO records (user_input, analysis) VALUES (?, ?)";

    db.run(sql, [userInput, analysisJSON], function (err) {

      if (err) {
        return reject(err);
      }

      const insertedId = this.lastID;

      db.get(
        "SELECT id, user_input, analysis, created_at FROM records WHERE id = ?",
        [insertedId],
        (getErr, row) => {

          if (getErr) {
            return reject(getErr);
          }

          resolve(row);

        }
      );

    });

  });

}


module.exports = {
  db,
  getAllRecords,
  insertRecord,
};


