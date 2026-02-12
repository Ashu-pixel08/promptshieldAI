PromptShield Full-Stack Agent
=============================

This project connects your PromptShield-style frontend to a backend agent API and a local database. It is structured as:

- `backend`: Node.js + Express + SQLite API server
- `frontend`: React + Vite single-page app

## Getting Started

### 1. Install dependencies

From the project root, run:

```bash
cd backend
npm install

cd ../frontend
npm install
```

### 2. Configure backend

In `backend`, create a `.env` file (optional) to point at your existing Replit backend:

```bash
ANALYZE_URL=https://cyborg-backend--kashyapvk1708.replit.app/analyze
PORT=5000
```

If `.env` is not provided, the backend will default to the above `ANALYZE_URL` and port `5000`.

### 3. Run backend

```bash
cd backend
npm start
```

This will:

- create a local SQLite database file (`promptshield.db`) if it does not exist
- expose REST endpoints under `http://localhost:5000/api`

### 4. Run frontend (dev mode)

```bash
cd frontend
npm run dev
```

By default the frontend talks to `http://localhost:5000/api`. You can change this in `frontend/src/config.js` if needed.

### 5. Main flows

- User submits text in the frontend form.
- Frontend POSTs to `/api/records` on the backend.
- Backend forwards the text to your Replit `/analyze` endpoint, receives the analysis, stores both input and analysis in SQLite, and returns the saved record.
- Frontend shows all stored records as cards.

### API Summary

- `GET /api/records` — list all stored records (for cards)
- `POST /api/records` — create a new record by sending user input; backend calls `ANALYZE_URL`, stores the result, and returns the created row

