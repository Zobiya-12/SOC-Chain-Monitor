// SOC Chain Monitor landing page.
// No innerHTML anywhere: the page only toggles classes and sets textContent (strict CSP page).
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var enc = new TextEncoder();

  // The four events shown in the pipeline animation. Index 2 is the one the attacker rewrites.
  var LOGS = [
    { timestamp: "2026-10-14T09:02:00Z", event_type: "ConsoleLogin", actor: "alice", detail: "success" },
    { timestamp: "2026-10-14T02:42:10Z", event_type: "ConsoleLogin", actor: "admin", detail: "success from 203.0.113.50" },
    { timestamp: "2026-10-14T02:46:00Z", event_type: "StopLogging", actor: "admin", detail: "CloudTrail logging disabled" },
    { timestamp: "2026-10-14T03:10:00Z", event_type: "ConsoleLogin", actor: "root", detail: "success" }
  ];
  var VICTIM = 2;
  var FORGED_DETAIL = "routine maintenance";

  var STAGES = [
    { title: "Ingest", dur: 3600, text: "Security events arrive from AWS CloudTrail and are queued for the next batch." },
    { title: "Detect", dur: 4200, text: "The detection rules check every event. Three of these four are suspicious and raise alerts." },
    { title: "Seal", dur: 4400, text: "Each log is hashed into a leaf. Pairs of hashes are combined upward until one Merkle root is left." },
    { title: "Anchor", dur: 4000, text: "The root is written to the smart contract as block #0042. Nobody can change it after this." },
    { title: "Attack", dur: 4400, text: "An attacker with database access rewrites the StopLogging event to hide what they did." },
    { title: "Verify", dur: 6000, text: "The root recomputed from the stored logs no longer matches the root on the chain. Verdict: TAMPERED, plus a CRITICAL alert." }
  ];

  // ---- hashing: same scheme as the backend (0x00 leaf prefix, 0x01 node prefix) ----
  var hasSubtle = !!(window.crypto && window.crypto.subtle);
  function canonical(entry) {
    var out = {};
    Object.keys(entry).sort().forEach(function (k) { out[k] = entry[k]; });
    return JSON.stringify(out);
  }
  function toHex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }
  function fromHex(hex) {
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  // Display-only fallback for insecure contexts where crypto.subtle is unavailable.
  function fallbackHash(bytes) {
    var out = "";
    for (var r = 0; r < 8; r++) {
      var h = (0x811c9dc5 ^ Math.imul(r + 1, 0x9e3779b1)) >>> 0;
      for (var i = 0; i < bytes.length; i++) { h ^= bytes[i]; h = Math.imul(h, 0x01000193); }
      out += ("0000000" + (h >>> 0).toString(16)).slice(-8);
    }
    return Promise.resolve(out);
  }
  function sha(bytes) { return hasSubtle ? crypto.subtle.digest("SHA-256", bytes).then(toHex) : fallbackHash(bytes); }
  function concat(prefix, a, b) {
    var out = new Uint8Array(1 + a.length + (b ? b.length : 0));
    out[0] = prefix; out.set(a, 1); if (b) out.set(b, 1 + a.length);
    return out;
  }
  function leafHash(entry) { return sha(concat(0, enc.encode(canonical(entry)))); }
  function nodeHash(l, r) { return sha(concat(1, fromHex(l), fromHex(r))); }
  function tree(entries) {
    return Promise.all(entries.map(leafHash)).then(function (leaves) {
      return Promise.all([nodeHash(leaves[0], leaves[1]), nodeHash(leaves[2], leaves[3])]).then(function (nodes) {
        return nodeHash(nodes[0], nodes[1]).then(function (root) { return { leaves: leaves, nodes: nodes, root: root }; });
      });
    });
  }
  function shortLeaf(h) { return "0x" + h.slice(0, 6); }
  function shortRoot(h) { return "0x" + h.slice(0, 8) + "…" + h.slice(-4); }

  // ------------------------------------------------------- simulation state
  var sim, stageEl, steps, toggleBtn;
  var hashes = null;
  var stage = -1, playing = false, timer = null, startedAt = 0, remaining = 0;

  function setText(id, text) { var n = $(id); if (n) n.textContent = text; }

  function paintHashes() {
    if (!hashes) return;
    var t = stage >= 4 ? hashes.forged : hashes.orig;
    for (var i = 0; i < 4; i++) {
      setText("tn-l" + i + "-h", shortLeaf(t.leaves[i]));
      setText("log-hash-" + i, "leaf " + shortLeaf(t.leaves[i]));
    }
    setText("tn-n0-h", shortLeaf(t.nodes[0]));
    setText("tn-n1-h", shortLeaf(t.nodes[1]));
    setText("tn-root-h", shortRoot(t.root));
    setText("cb-root", shortRoot(hashes.orig.root));
    setText("cmp-chain", stage >= 3 ? shortRoot(hashes.orig.root) : "not anchored");
    setText("cmp-now", stage >= 5 ? shortRoot(hashes.forged.root) : stage >= 2 ? shortRoot(t.root) : "–");
  }

  function go(n, replay) {
    stage = n;
    var cls = ["sim-stage"];
    for (var k = 0; k <= n; k++) cls.push("at-" + k);
    cls.push("now-" + n);
    if (replay) { stageEl.className = "sim-stage"; void stageEl.offsetWidth; }
    stageEl.className = cls.join(" ");

    steps.forEach(function (b) { b.classList.remove("active"); });
    void stageEl.offsetWidth; // restart the progress-bar animation
    steps.forEach(function (b, i) {
      b.style.setProperty("--dur", STAGES[i].dur + "ms");
      b.classList.toggle("done", i < n);
      b.classList.toggle("active", i === n);
      if (i === n) b.setAttribute("aria-current", "step"); else b.removeAttribute("aria-current");
    });

    setText("cap-num", "0" + (n + 1));
    setText("cap-title", STAGES[n].title);
    setText("cap-text", STAGES[n].text);
    var body = $("cap-body");
    body.classList.remove("cap-body"); void body.offsetWidth; body.classList.add("cap-body");

    paintHashes();
    remaining = STAGES[n].dur;
    schedule();
  }

  function schedule() {
    clearTimeout(timer);
    if (!playing) return;
    startedAt = Date.now();
    timer = setTimeout(function () {
      if (stage < STAGES.length - 1) go(stage + 1); else go(0, true);
    }, remaining);
  }

  function setPlaying(p) {
    if (p === playing) return;
    playing = p;
    sim.classList.toggle("paused", !p);
    toggleBtn.textContent = p ? "Pause" : "Play";
    toggleBtn.setAttribute("aria-label", p ? "Pause animation" : "Play animation");
    if (p) schedule();
    else { clearTimeout(timer); remaining = Math.max(400, remaining - (Date.now() - startedAt)); }
  }

  function startSim() {
    sim = $("sim");
    stageEl = $("sim-stage");
    toggleBtn = $("sim-toggle");
    steps = Array.prototype.slice.call(document.querySelectorAll("#sim-steps button"));
    if (!sim || !stageEl) return;

    var forgedLogs = LOGS.map(function (l) { return Object.assign({}, l); });
    forgedLogs[VICTIM].detail = FORGED_DETAIL;
    Promise.all([tree(LOGS), tree(forgedLogs)]).then(function (r) {
      hashes = { orig: r[0], forged: r[1] };
      paintHashes();
    });

    steps.forEach(function (b, i) { b.addEventListener("click", function () { go(i, i === 0); }); });
    toggleBtn.addEventListener("click", function () { setPlaying(!playing); });
    $("sim-restart").addEventListener("click", function () { go(0, true); });

    var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    sim.classList.add("paused");
    var begin = function () { setPlaying(!reduced); go(0, true); };

    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (entries) {
        if (entries.some(function (e) { return e.isIntersecting; })) { io.disconnect(); begin(); }
      }, { threshold: 0.25 });
      io.observe(stageEl);
    } else {
      begin();
    }
    document.addEventListener("visibilitychange", function () {
      if (document.hidden && playing) setPlaying(false);
    });
  }

  // ---------------------------------------------------- live backend status
  function loadStatus() {
    var node = $("live-status");
    if (!node) return;
    fetch("/health").then(function (r) { return r.json(); }).then(function (h) {
      var c = h.chain || {};
      node.className = "live " + (c.connected ? "up" : "down");
      node.textContent = c.connected
        ? "Backend online · " + (c.mode === "simulated" ? "simulated ledger (demo, not a real blockchain)" : "chain " + c.chain_id + " (" + c.mode + ")") + " · " + h.stats.batches + " batch(es) · " + h.stats.alerts + " alert(s)"
        : "Backend online, blockchain offline: " + (c.reason || "unknown") + ". Verification will answer UNVERIFIABLE.";
    }).catch(function () {
      node.className = "live down";
      node.textContent = "Backend not reachable";
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    startSim();
    loadStatus();
  });
})();
