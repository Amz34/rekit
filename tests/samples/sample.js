// Test fixture for `rekit js` — an intentionally noisy bundle.
// Mixes a real API surface with values that look like secrets so the
// interesting-value filter, the redaction path and the obfuscation signals
// all get exercised. None of these are live credentials.
const API_BASE = "https://api.example.com/v1";
const CDN = "https://cdn.example.com/assets/";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";          // AWS's public documentation sample key
const BEARER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.c2ln";
const WEBHOOK = "https://hooks.example.com/services/T000/B000";
const DB_URL = "postgres://user:pass@db.internal.example.com:5432/app";

const _0x4f2a = ["log", "warn", "error"];
function bootstrap(_0xa1, _0xb2) {
  return _0xa1[_0xb2 % _0xa1.length];
}

async function fetchReport(id) {
  const r = await fetch(API_BASE + "/reports/" + id, {
    headers: { Authorization: "Bearer " + BEARER },
  });
  return r.json();
}

eval(atob("Y29uc29sZS5sb2coJ29iZnVzY2F0ZWQnKQ=="));

export { API_BASE, CDN, AWS_KEY, WEBHOOK, DB_URL, fetchReport, bootstrap };
