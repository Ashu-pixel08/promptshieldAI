const path = require("path");
const sqlite3 = require("sqlite3").verbose();

// Path to the SQLite database file (created if it does not exist)
const DB_PATH = path.join(__dirname, "promptshield.db");

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("Failed to connect to SQLite database:", err);
  } else {
    console.log("Connected to SQLite database at", DB_PATH);
  }
});

// Ensure the main table exists
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

function insertRecord(userInput, analysis) {
  return new Promise((resolve, reject) => {
    const sql =
      "INSERT INTO records (user_input, analysis) VALUES (?, ?)";
    db.run(sql, [userInput, analysis], function (err) {
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

