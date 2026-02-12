import { API_BASE_URL } from "./config";

export async function fetchRecords() {
  const res = await fetch(`${API_BASE_URL}/records`);
  if (!res.ok) {
    throw new Error(`Failed to fetch records: ${res.status}`);
  }
  return res.json();
}

export async function createRecord(prompt) {
  const res = await fetch(`${API_BASE_URL}/records`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ prompt }),
  });

  if (!res.ok) {
    const errorBody = await res.json().catch(() => ({}));
    const msg = errorBody.error || `Failed to create record: ${res.status}`;
    throw new Error(msg);
  }

  return res.json();
}

