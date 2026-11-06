// SOC Chain Monitor console: live visuals.
// Reads the tables that dashboard.js renders (no extra API calls) and drives
// the KPI counters, the animated ledger strip and the sync clock.
// No innerHTML: everything is built with createElement + textContent.
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var seenBlocks = {};

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }

  function countUp(node, target) {
    if (!node) return;
    var from = parseInt(node.getAttribute("data-value") || "0", 10);
    node.setAttribute("data-value", String(target));
    if (from === target) { node.textContent = String(target); return; }
    var card = node.closest(".kpi");
    if (card) { card.classList.remove("bump"); void card.offsetWidth; card.classList.add("bump"); }
    if (reduced) { node.textContent = String(target); return; }
    var start = performance.now(), dur = 700;
    (function frame(now) {
      var t = Math.min(1, (now - start) / dur);
      var eased = 1 - Math.pow(1 - t, 3);
      node.textContent = String(Math.round(from + (target - from) * eased));
      if (t < 1) requestAnimationFrame(frame);
    })(start);
  }

  function tick() {
    var d = new Date();
    var pad = function (x) { return ("0" + x).slice(-2); };
    var c = $("fx-clock");
    if (c) c.textContent = pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function synced() {
    var s = $("fx-sync");
    if (s) { s.classList.remove("flash"); void s.offsetWidth; s.classList.add("flash"); }
  }

  // ---- alerts summary chips look like "CRITICAL: 3"
  function readAlerts() {
    var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    document.querySelectorAll("#alert-summary .chip").forEach(function (c) {
      var m = /^(\w+):\s*(\d+)/.exec(c.textContent || "");
      if (m && m[1] in counts) {
        counts[m[1]] = parseInt(m[2], 10);
        c.setAttribute("data-sev", m[1]);
      }
    });
    var total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW;
    countUp($("kpi-alerts"), total);
    countUp($("kpi-critical"), counts.CRITICAL);
    var crit = $("kpi-critical");
    if (crit) crit.closest(".kpi").classList.toggle("hot", counts.CRITICAL > 0);
    synced();
  }

  // ---- batches table rows: [#, Logs, Alerts, Merkle root, On-chain, button]
  function readBatches() {
    var rows = [];
    document.querySelectorAll("#batches tr").forEach(function (tr) {
      var td = tr.querySelectorAll("td");
      if (td.length < 5) return;
      rows.push({
        id: parseInt(td[0].textContent, 10),
        logs: parseInt(td[1].textContent, 10) || 0,
        alerts: parseInt(td[2].textContent, 10) || 0,
        root: td[3].textContent,
        anchored: /^block/i.test(td[4].textContent || ""),
        selected: tr.classList.contains("selected"),
        open: td[5] ? td[5].querySelector("button") : null
      });
    });
    countUp($("kpi-batches"), rows.length);
    countUp($("kpi-anchored"), rows.filter(function (r) { return r.anchored; }).length);
    renderChain(rows);
    synced();
  }

  function renderChain(rows) {
    var strip = $("chain-strip");
    if (!strip) return;
    clear(strip);
    if (!rows.length) {
      strip.appendChild(el("li", "cb-empty", "No blocks yet. Use “Load sample attack” to seal the first batch."));
      return;
    }
    rows.sort(function (a, b) { return a.id - b.id; });
    rows.slice(-12).forEach(function (r) {
      var key = r.id + ":" + r.anchored;
      var cls = "cb" + (r.anchored ? " anchored" : " pending") + (r.alerts ? " alerting" : "") + (r.selected ? " selected" : "");
      if (!seenBlocks[key]) cls += " fresh";
      seenBlocks[key] = true;
      var li = el("li", cls);
      var btn = el("button", "cb-btn");
      btn.type = "button";
      btn.setAttribute("aria-label", "Open batch " + r.id);
      var head = el("span", "cb-head");
      head.appendChild(el("b", "", "#" + String(r.id).padStart(4, "0")));
      head.appendChild(el("span", "cb-state", r.anchored ? "on-chain" : "local"));
      btn.appendChild(head);
      btn.appendChild(el("span", "cb-root", r.root));
      var meta = el("span", "cb-meta");
      meta.appendChild(el("span", "", r.logs + " logs"));
      meta.appendChild(el("span", r.alerts ? "cb-alerts" : "", r.alerts + " alerts"));
      btn.appendChild(meta);
      if (r.open) btn.addEventListener("click", function () { r.open.click(); });
      li.appendChild(btn);
      strip.appendChild(li);
    });
    strip.scrollLeft = strip.scrollWidth;
  }

  function readPending() {
    var m = /(\d+)/.exec(($("pending") || {}).textContent || "");
    countUp($("kpi-pending"), m ? parseInt(m[1], 10) : 0);
  }

  function watch(id, fn) {
    var node = $(id);
    if (!node) return;
    new MutationObserver(fn).observe(node, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ["class"] });
  }

  document.addEventListener("DOMContentLoaded", function () {
    watch("alert-summary", readAlerts);
    watch("batches", readBatches);
    watch("pending", readPending);
    renderChain([]);
    tick();
    setInterval(tick, 1000);
  });
})();
