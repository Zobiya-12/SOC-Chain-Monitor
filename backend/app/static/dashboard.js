// SOC Chain Monitor dashboard.
// SECURITY: log text is attacker-controlled, so this file never uses innerHTML.
// Everything is built with createElement + textContent.
(function () {
  "use strict";

  var state = { batchId: null, selectedLog: null, demo: false };
  var $ = function (id) { return document.getElementById(id); };

  function el(tag, props, children) {
    var node = document.createElement(tag);
    Object.keys(props || {}).forEach(function (k) {
      if (k === "text") node.textContent = props[k];
      else if (k === "class") node.className = props[k];
      else if (k === "onclick") node.addEventListener("click", props[k]);
      else node.setAttribute(k, props[k]);
    });
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function short(h) { return h ? h.slice(0, 10) + "…" + h.slice(-6) : "–"; }

  var toastTimer = null;
  function toast(message, isError) {
    var t = $("toast");
    t.textContent = message;
    t.className = isError ? "error" : "";
    t.style.display = "block";
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.style.display = "none"; }, 6000);
  }

  function api(path, options) {
    options = options || {};
    var headers = { "Content-Type": "application/json" };
    var key = $("apikey").value;
    if (key) headers["X-API-Key"] = key;
    return fetch(path, { method: options.method || "GET", headers: headers,
                         body: options.body ? JSON.stringify(options.body) : undefined })
      .then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (data) {
          if (!res.ok) {
            var d = data.detail;
            throw new Error(typeof d === "string" ? d : (d ? JSON.stringify(d) : "HTTP " + res.status));
          }
          return data;
        });
      });
  }
  function guard(promise) { return promise.catch(function (e) { toast(e.message, true); throw e; }); }

  // ------------------------------------------------------------ status
  function loadStatus() {
    return api("/health").then(function (h) {
      state.demo = !!h.demo_mode;
      var chips = $("status");
      clear(chips);
      var c = h.chain || {};
      chips.appendChild(el("span", { class: "chip " + (c.connected ? "good" : "bad"),
        text: c.connected ? (c.mode === "simulated" ? "SIMULATED ledger (demo, not a real blockchain)"
                                                   : "blockchain: connected (" + c.mode + ", chain " + c.chain_id + ")")
                          : "blockchain: OFFLINE – " + (c.reason || "unknown") }));
      chips.appendChild(el("span", { class: "chip " + (h.auth_enabled ? "good" : ""),
        text: h.auth_enabled ? "API key: required" : "API key: off" }));
      chips.appendChild(el("span", { class: "chip", text: h.demo_mode ? "demo mode: ON" : "demo mode: off" }));
      $("pending").textContent = h.stats.pending_logs + " log(s) waiting to be sealed.";
      $("demo-panel").hidden = !state.demo || state.batchId === null;
    });
  }

  // ------------------------------------------------------------ alerts
  function loadAlerts() {
    var sev = $("severity-filter").value;
    return Promise.all([api("/alerts" + (sev ? "?severity=" + encodeURIComponent(sev) : "")),
                        api("/alerts/summary")]).then(function (r) {
      var sum = $("alert-summary");
      clear(sum);
      ["CRITICAL", "HIGH", "MEDIUM", "LOW"].forEach(function (s) {
        sum.appendChild(el("span", { class: "chip", text: s + ": " + ((r[1].by_severity || {})[s] || 0) }));
      });
      var table = $("alerts");
      clear(table);
      table.appendChild(el("tr", {}, ["Severity", "Rule", "Message", "Batch", "Log #"].map(function (h) {
        return el("th", { text: h });
      })));
      if (!r[0].alerts.length) {
        table.appendChild(el("tr", {}, [el("td", { text: "No alerts.", colspan: "5" })]));
      }
      r[0].alerts.forEach(function (a) {
        table.appendChild(el("tr", {}, [
          el("td", {}, [el("span", { class: "sev " + a.severity, text: a.severity })]),
          el("td", { text: a.rule }), el("td", { text: a.message }),
          el("td", { text: a.batch_id == null ? "–" : String(a.batch_id) }),
          el("td", { text: a.log_index == null ? "–" : String(a.log_index) })
        ]));
      });
    });
  }

  // ----------------------------------------------------------- batches
  function loadBatches() {
    return api("/logs/batches").then(function (batches) {
      var table = $("batches");
      clear(table);
      table.appendChild(el("tr", {}, ["#", "Logs", "Alerts", "Merkle root", "On-chain", ""].map(function (h) {
        return el("th", { text: h });
      })));
      if (!batches.length) table.appendChild(el("tr", {}, [el("td", { text: "No batches yet.", colspan: "6" })]));
      batches.forEach(function (b) {
        var onchain = b.anchored
          ? (b.explorer_url ? el("a", { href: b.explorer_url, target: "_blank", rel: "noopener noreferrer",
                                        text: "block " + b.block_number })
                            : el("span", { text: "block " + b.block_number }))
          : el("span", { text: "no", title: b.anchor_error || "" });
        var row = el("tr", { class: b.batch_id === state.batchId ? "selected" : "" }, [
          el("td", { text: String(b.batch_id) }), el("td", { text: String(b.log_count) }),
          el("td", { text: String(b.alerts_raised) }),
          el("td", { class: "mono", text: short(b.merkle_root) }),
          el("td", {}, [onchain]),
          el("td", {}, [el("button", { class: "secondary", text: "Open",
                                        onclick: function () { openBatch(b.batch_id); } })])
        ]);
        table.appendChild(row);
      });
    });
  }

  function openBatch(id) {
    state.batchId = id;
    state.selectedLog = null;
    return guard(api("/logs/batch/" + id)).then(function (b) {
      $("detail").hidden = false;
      $("detail-title").textContent = "Batch " + id + " – " + b.log_count + " logs";
      $("integrity").hidden = true;
      $("btn-anchor").hidden = b.anchored;
      $("demo-panel").hidden = !state.demo;
      var table = $("logs");
      clear(table);
      table.appendChild(el("tr", {}, ["#", "Time", "Event", "Actor", "Detail", ""].map(function (h) {
        return el("th", { text: h });
      })));
      b.logs.forEach(function (log, i) {
        var row = el("tr", { id: "log-" + i }, [
          el("td", { text: String(i) }), el("td", { text: String(log.timestamp) }),
          el("td", { text: log.event_type }), el("td", { text: log.actor }),
          el("td", { text: log.detail == null ? "" : String(log.detail) }),
          el("td", {}, [el("button", { class: "secondary", text: "Verify",
                                        onclick: function () { selectLog(i); verifyLog(i, log); } })])
        ]);
        table.appendChild(row);
      });
      document.dispatchEvent(new CustomEvent("soc:batch", { detail: { id: id, logs: b.logs } }));
      return loadBatches();
    });
  }

  function selectLog(i) {
    state.selectedLog = i;
    var rows = document.querySelectorAll("#logs tr");
    rows.forEach(function (r) { r.classList.remove("selected"); });
    var row = $("log-" + i);
    if (row) row.classList.add("selected");
  }

  function showCard(verdict, lines) {
    var card = $("integrity");
    clear(card);
    card.hidden = false;
    card.className = "card " + verdict;
    card.appendChild(el("div", { class: "verdict", text: verdict }));
    lines.forEach(function (l) { card.appendChild(el("div", { class: l.mono ? "mono" : "", text: l.text })); });
  }

  function verifyIntegrity() {
    if (state.batchId === null) return;
    guard(api("/logs/batch/" + state.batchId + "/integrity")).then(function (r) {
      document.dispatchEvent(new CustomEvent("soc:integrity", { detail: r }));
      showCard(r.verdict, [
        { text: r.explanation },
        { text: "recomputed from stored logs: " + short(r.root_recomputed_from_current_logs), mono: true },
        { text: "stored locally:              " + short(r.root_sealed_locally), mono: true },
        { text: "on-chain:                    " + short(r.root_on_chain), mono: true }
      ]);
      return Promise.all([loadAlerts(), loadBatches()]);
    });
  }

  function verifyLog(i, log) {
    guard(api("/logs/verify", { method: "POST", body: { batch_id: state.batchId, log_index: i, log_entry: log } }))
      .then(function (r) {
        showCard(r.status.toUpperCase(), [{ text: r.message }]);
      });
  }

  // ------------------------------------------------------------- actions
  function ingest(entry) {
    return api("/logs/ingest", { method: "POST", body: entry });
  }
  function refreshAll() { return Promise.all([loadStatus(), loadAlerts(), loadBatches()]).catch(function (e) { toast(e.message, true); }); }

  function sampleScenario() {
    var d = new Date().toISOString().slice(0, 10);
    function at(t) { return d + "T" + t; }
    var logs = [
      [at("09:02:00"), "ConsoleLogin", "alice", "success"],
      [at("09:15:00"), "AssumeRole", "alice", "role DevOps"],
      [at("02:41:00"), "FailedLogin", "admin", "bad password"],
      [at("02:41:20"), "FailedLogin", "admin", "bad password"],
      [at("02:41:40"), "FailedLogin", "admin", "bad password"],
      [at("02:42:10"), "ConsoleLogin", "admin", "success from 203.0.113.50"],
      [at("02:44:00"), "AttachRolePolicy", "admin", "AdministratorAccess attached"],
      [at("02:46:00"), "StopLogging", "admin", "CloudTrail logging disabled"],
      [at("03:10:00"), "ConsoleLogin", "root", "success"]
    ];
    var chain = Promise.resolve();
    logs.forEach(function (l) {
      chain = chain.then(function () {
        return ingest({ timestamp: l[0], source: "aws-cloudtrail", event_type: l[1], actor: l[2], detail: l[3] });
      });
    });
    guard(chain.then(function () { return api("/logs/seal-batch", { method: "POST" }); })).then(function (b) {
      toast("Sealed batch " + b.batch_id + " – " + b.alerts_raised + " alert(s) raised.");
      return refreshAll().then(function () { return openBatch(b.batch_id); });
    });
  }

  function tamper(rewrite) {
    if (state.batchId === null) return;
    var idx = state.selectedLog === null ? 0 : state.selectedLog;
    var text = $("demo-text").value || "nothing happened";
    guard(api("/demo/tamper/" + state.batchId + "/" + idx + "?new_detail=" + encodeURIComponent(text) +
              "&rewrite_local_root=" + (rewrite ? "true" : "false"), { method: "POST" }))
      .then(function () {
        toast("Log " + idx + " tampered" + (rewrite ? " and local root rewritten" : "") + ". Checking the chain...");
        document.dispatchEvent(new CustomEvent("soc:tamper", { detail: { batch_id: state.batchId, index: idx, rewrite: rewrite } }));
        return openBatch(state.batchId).then(verifyIntegrity);
      });
  }

  function wire() {
    $("btn-refresh").addEventListener("click", refreshAll);
    $("btn-sample").addEventListener("click", sampleScenario);
    $("btn-integrity").addEventListener("click", verifyIntegrity);
    $("btn-detect").addEventListener("click", function () {
      if (state.batchId === null) return;
      guard(api("/logs/batch/" + state.batchId + "/detect", { method: "POST" })).then(function (r) {
        toast(r.alerts_found + " alert(s) found."); return Promise.all([loadAlerts(), loadBatches()]);
      });
    });
    $("btn-anchor").addEventListener("click", function () {
      if (state.batchId === null) return;
      guard(api("/logs/batch/" + state.batchId + "/anchor", { method: "POST" })).then(function () {
        toast("Anchored on-chain."); return openBatch(state.batchId);
      });
    });
    $("btn-tamper").addEventListener("click", function () { tamper(false); });
    $("btn-tamper-smart").addEventListener("click", function () { tamper(true); });
    $("severity-filter").addEventListener("change", loadAlerts);
    $("btn-ingest").addEventListener("click", function () {
      guard(ingest({ source: $("in-source").value, event_type: $("in-event").value,
                     actor: $("in-actor").value, detail: $("in-detail").value })).then(loadStatus);
    });
    $("btn-seal").addEventListener("click", function () {
      guard(api("/logs/seal-batch", { method: "POST" })).then(function (b) {
        toast("Sealed batch " + b.batch_id + " – " + b.alerts_raised + " alert(s) raised.");
        return refreshAll().then(function () { return openBatch(b.batch_id); });
      });
    });
    var saved = sessionStorage.getItem("soc_api_key");
    if (saved) $("apikey").value = saved;
    $("apikey").addEventListener("change", function () { sessionStorage.setItem("soc_api_key", $("apikey").value); });
    refreshAll();
    setInterval(loadStatus, 15000);
  }

  document.addEventListener("DOMContentLoaded", wire);
})();
