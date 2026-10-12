// Before a link is followed, ask PhishGuard. Phishing -> block + explain; suspicious -> confirm.
document.addEventListener("click", (ev) => {
  const a = ev.target.closest && ev.target.closest("a[href]");
  if (!a || !/^https?:/.test(a.href) || a.dataset.pgChecked) return;
  if (new URL(a.href).hostname === location.hostname) return;   // same-site links are fine
  ev.preventDefault();
  chrome.runtime.sendMessage({type: "check", url: a.href}, (v) => {
    const go = () => { a.dataset.pgChecked = "1"; a.click(); };
    if (!v || v.verdict === "safe") return go();
    const why = (v.reasons || []).slice(0, 4).map(r => "• " + r).join("\n");
    const msg = `PhishGuard: this link looks ${v.verdict.toUpperCase()} (${Math.round(v.score * 100)}% risk)\n\n${a.href}\n\n${why}\n\nOpen it anyway?`;
    if (v.verdict === "suspicious" ? confirm(msg) : confirm(msg + "\n\n(Not recommended)")) go();
  });
}, true);
