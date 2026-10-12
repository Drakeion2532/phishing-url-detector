// Calls the PhishGuard API and caches verdicts for 10 minutes.
const API = "http://127.0.0.1:8003/check";
const cache = new Map();
chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg.type !== "check") return;
  const hit = cache.get(msg.url);
  if (hit && Date.now() - hit.t < 600000) { reply(hit.v); return; }
  fetch(API, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({url: msg.url})})
    .then(r => r.json()).then(v => { cache.set(msg.url, {t: Date.now(), v}); reply(v); })
    .catch(() => reply(null));
  return true; // async reply
});
