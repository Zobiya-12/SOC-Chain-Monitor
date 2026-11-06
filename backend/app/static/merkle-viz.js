// SOC Chain Monitor console: Merkle tree view of the open batch.
// Listens for events fired by dashboard.js (soc:batch, soc:integrity, soc:tamper).
// Hashing matches the backend exactly: leaf = sha256(0x00 + canonical JSON),
// node = sha256(0x01 + left + right), an unpaired node is promoted unchanged.
// No innerHTML: SVG is built with createElementNS + textContent.
(function () {
  "use strict";

  var NS = "http://www.w3.org/2000/svg";
  var BOX_W = 92, BOX_H = 40, GAP_X = 16, GAP_Y = 52, PAD = 20, MAX_FULL = 16;
  var enc = new TextEncoder();
  var $ = function (id) { return document.getElementById(id); };
  var batches = {};   // id -> {baseline, cur, tamperIndex, verdict, chainRoot}
  var openId = null;

  // ------------------------------------------------------------- hashing
  function sortKeys(v) {
    if (Array.isArray(v)) return v.map(sortKeys);
    if (v && typeof v === "object") {
      var out = {};
      Object.keys(v).sort().forEach(function (k) { out[k] = sortKeys(v[k]); });
      return out;
    }
    return v;
  }
  function canonical(entry) {
    // Python's json.dumps escapes non-ASCII; JSON.stringify does not, so match it.
    return JSON.stringify(sortKeys(entry)).replace(/[\u0080-\uffff]/g, function (c) {
      return "\\u" + ("0000" + c.charCodeAt(0).toString(16)).slice(-4);
    });
  }
  function hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }
  function unhex(h) {
    var o = new Uint8Array(h.length / 2);
    for (var i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16);
    return o;
  }
  function sha(prefix, a, b) {
    var out = new Uint8Array(1 + a.length + (b ? b.length : 0));
    out[0] = prefix; out.set(a, 1); if (b) out.set(b, 1 + a.length);
    return crypto.subtle.digest("SHA-256", out).then(hex);
  }
  function buildTree(logs) {
    return Promise.all(logs.map(function (l) { return sha(0, enc.encode(canonical(l))); })).then(function (leaves) {
      var levels = [leaves];
      function up(level) {
        if (level.length === 1) return Promise.resolve();
        var jobs = [];
        for (var i = 0; i < level.length; i += 2) {
          jobs.push(i + 1 < level.length ? sha(1, unhex(level[i]), unhex(level[i + 1])) : Promise.resolve(level[i]));
        }
        return Promise.all(jobs).then(function (next) { levels.push(next); return up(next); });
      }
      return up(leaves).then(function () { return { leaves: leaves, levels: levels, root: levels[levels.length - 1][0] }; });
    });
  }

  // ------------------------------------------------------------ svg helpers
  function svg(tag, attrs, text) {
    var n = document.createElementNS(NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function short(h) { return h ? "0x" + h.slice(0, 6) : "–"; }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }

  function drawNode(parent, cx, cy, label, hash, cls, w) {
    var width = w || BOX_W;
    var g = svg("g", { "class": "mk-node " + cls });
    g.appendChild(svg("rect", { x: cx - width / 2, y: cy - BOX_H / 2, width: width, height: BOX_H, rx: 8 }));
    g.appendChild(svg("text", { x: cx, y: cy - 4, "class": "mk-label", "text-anchor": "middle" }, label));
    g.appendChild(svg("text", { x: cx, y: cy + 11, "class": "mk-hash", "text-anchor": "middle" }, short(hash)));
    var title = svg("title", {}, label + ": " + hash);
    g.appendChild(title);
    parent.appendChild(g);
  }
  function drawEdge(parent, x1, y1, x2, y2, bad) {
    parent.appendChild(svg("path", {
      d: "M" + x1 + " " + y1 + " C" + x1 + " " + (y1 + y2) / 2 + " " + x2 + " " + (y1 + y2) / 2 + " " + x2 + " " + y2,
      "class": "mk-edge" + (bad ? " bad" : "")
    }));
  }

  // ------------------------------------------------------------- analysis
  function changedLeaves(rec) {
    var out = [];
    if (!rec.baseline) return out;
    rec.cur.leaves.forEach(function (h, i) { if (h !== rec.baseline[i]) out.push(i); });
    if (!out.length && rec.tamperIndex !== null && rec.tamperIndex !== undefined && rec.verdict === "TAMPERED") out.push(rec.tamperIndex);
    return out;
  }

  // --------------------------------------------------------------- render
  function render() {
    var panel = $("merkle-panel");
    var rec = batches[openId];
    if (!panel || !rec || !rec.cur) { if (panel) panel.hidden = true; return; }
    panel.hidden = false;

    var verdict = rec.verdict;                       // INTACT | TAMPERED | UNVERIFIABLE | UNANCHORED | null
    var changed = changedLeaves(rec);
    var tampered = verdict === "TAMPERED";
    var tree = rec.cur;
    var n = tree.leaves.length;

    panel.className = "merkle" + (tampered ? " alarm" : "");
    var chip = $("merkle-chip");
    chip.className = "merkle-chip " + (verdict || "NONE");
    chip.textContent = verdict ? verdict : "not verified yet";

    var note = $("merkle-note");
    if (tampered) {
      note.textContent = changed.length
        ? "Attack detected. Log " + changed.join(", ") + " changed, so every hash above it up to the root changed too. " +
          "The chain stores only the root: it proves something was edited, and the red leaves are the ones that differ from the copy this console saw earlier."
        : "Attack detected. The root no longer matches the chain, but this console has no earlier copy to show which log changed.";
    } else if (verdict === "INTACT") {
      note.textContent = "Every leaf hashes up to the root that is anchored on-chain.";
    } else {
      note.textContent = "Run “Verify integrity on-chain” to compare this tree's root with the blockchain.";
    }

    var wrap = $("merkle-svg");
    clear(wrap);

    var rootCls = tampered ? "bad" : verdict === "INTACT" ? "ok" : (verdict ? "warn" : "idle");
    var onchain = rec.chainRoot;

    if (n <= MAX_FULL) drawFull(wrap, tree, changed, rootCls, onchain, tampered);
    else drawPath(wrap, tree, changed, rootCls, onchain, tampered);
  }

  function drawFull(wrap, tree, changed, rootCls, onchain, tampered) {
    var n = tree.leaves.length, levels = tree.levels;
    var step = BOX_W + GAP_X;
    var width = Math.max(n * step + PAD * 2 + (onchain ? BOX_W + 40 : 0), 320);
    var height = levels.length * (BOX_H + GAP_Y) - GAP_Y + PAD * 2;
    var s = svg("svg", { viewBox: "0 0 " + width + " " + height, width: width, height: height,
                         role: "img", "aria-label": "Merkle tree of the selected batch" });
    var xs = [levels[0].map(function (_, i) { return PAD + BOX_W / 2 + i * step; })];
    for (var L = 1; L < levels.length; L++) {
      var row = [];
      for (var i = 0; i < levels[L].length; i++) {
        var a = xs[L - 1][2 * i], b = xs[L - 1][2 * i + 1];
        row.push(b === undefined ? a : (a + b) / 2);
      }
      xs.push(row);
    }
    var yOf = function (L) { return height - PAD - BOX_H / 2 - L * (BOX_H + GAP_Y); };

    // which nodes lie on a changed path
    var bad = levels.map(function (lv) { return lv.map(function () { return false; }); });
    changed.forEach(function (idx) { var j = idx; for (var l = 0; l < levels.length; l++) { bad[l][j] = true; j = Math.floor(j / 2); } });
    if (tampered && !changed.length) bad[levels.length - 1][0] = true;

    var edges = svg("g", {}), nodes = svg("g", {});
    for (var l = 1; l < levels.length; l++) {
      for (var k = 0; k < levels[l - 1].length; k++) {
        var p = Math.floor(k / 2);
        drawEdge(edges, xs[l - 1][k], yOf(l - 1) - BOX_H / 2, xs[l][p], yOf(l) + BOX_H / 2, bad[l - 1][k] && bad[l][p]);
      }
    }
    for (var lv = 0; lv < levels.length; lv++) {
      for (var m = 0; m < levels[lv].length; m++) {
        var top = lv === levels.length - 1;
        var label = top ? "MERKLE ROOT" : lv === 0 ? "LEAF " + m : "NODE";
        var cls = top ? "root " + rootCls : (bad[lv][m] ? "bad" : (lv === 0 ? "leaf" : "inner"));
        if (lv === 0 && changed.indexOf(m) !== -1) cls = "bad hit";
        drawNode(nodes, xs[lv][m], yOf(lv), label, levels[lv][m], cls);
      }
    }
    s.appendChild(edges); s.appendChild(nodes);

    if (onchain) {   // the trusted value, drawn next to the recomputed root
      var rx = xs[levels.length - 1][0] + BOX_W + 28, ry = yOf(levels.length - 1);
      var link = svg("path", { d: "M" + (xs[levels.length - 1][0] + BOX_W / 2) + " " + ry + " H" + (rx - BOX_W / 2),
                               "class": "mk-edge " + (tampered ? "bad dashed" : "good") });
      s.insertBefore(link, edges);
      drawNode(nodes, rx, ry, "ON-CHAIN ROOT", onchain, "chain");
      s.appendChild(svg("text", { x: (xs[levels.length - 1][0] + BOX_W / 2 + rx - BOX_W / 2) / 2, y: ry - 8,
                                  "class": "mk-eq " + (tampered ? "bad" : "good"), "text-anchor": "middle" }, tampered ? "≠" : "="));
    }
    wrap.appendChild(s);
  }

  // Large batches: draw only the path from one leaf to the root (plus siblings).
  function drawPath(wrap, tree, changed, rootCls, onchain, tampered) {
    var idx = changed.length ? changed[0] : 0, levels = tree.levels;
    var depth = levels.length, colW = BOX_W + GAP_X;
    var width = 3 * colW + PAD * 2 + (onchain ? BOX_W + 40 : 0), height = depth * (BOX_H + GAP_Y) - GAP_Y + PAD * 2;
    var s = svg("svg", { viewBox: "0 0 " + width + " " + height, width: width, height: height, role: "img",
                         "aria-label": "Merkle proof path of the selected batch" });
    var edges = svg("g", {}), nodes = svg("g", {});
    var cx = PAD + colW + BOX_W / 2, sx = cx + colW;
    var yOf = function (L) { return height - PAD - BOX_H / 2 - L * (BOX_H + GAP_Y); };
    var j = idx;
    for (var L = 0; L < depth; L++) {
      var top = L === depth - 1;
      if (L > 0) drawEdge(edges, cx, yOf(L - 1) - BOX_H / 2, cx, yOf(L) + BOX_H / 2, changed.length > 0);
      var label = top ? "MERKLE ROOT" : L === 0 ? "LEAF " + idx : "NODE (level " + L + ")";
      var cls = top ? "root " + rootCls : (changed.length ? "bad" : (L === 0 ? "leaf" : "inner"));
      if (L === 0 && changed.length) cls = "bad hit";
      drawNode(nodes, cx, yOf(L), label, levels[L][j], cls);
      if (!top) {
        var sib = j % 2 === 1 ? j - 1 : j + 1;
        if (sib < levels[L].length) {
          drawEdge(edges, sx, yOf(L), cx, yOf(L + 1) + BOX_H / 2, false);
          drawNode(nodes, sx, yOf(L), "SIBLING", levels[L][sib], "inner");
        }
      }
      j = Math.floor(j / 2);
    }
    s.appendChild(edges); s.appendChild(nodes);
    if (onchain) {
      var rx = cx + colW * 2 + 8, ry = yOf(depth - 1);
      drawNode(nodes, rx, ry, "ON-CHAIN ROOT", onchain, "chain");
    }
    wrap.appendChild(s);
  }

  // ---------------------------------------------------------------- events
  function ensure(id) { if (!batches[id]) batches[id] = { baseline: null, cur: null, tamperIndex: null, verdict: null, chainRoot: null }; return batches[id]; }

  document.addEventListener("soc:batch", function (e) {
    var d = e.detail, rec = ensure(d.id);
    openId = d.id;
    rec.verdict = null; rec.chainRoot = null;
    if (!window.crypto || !crypto.subtle) { $("merkle-note").textContent = "Merkle view needs a secure page (use http://localhost:8000)."; return; }
    buildTree(d.logs).then(function (tree) {
      rec.cur = tree;
      if (!rec.baseline || rec.baseline.length !== tree.leaves.length) rec.baseline = tree.leaves.slice();
      if (openId === d.id) render();
    });
  });

  document.addEventListener("soc:integrity", function (e) {
    var r = e.detail, rec = ensure(r.batch_id);
    rec.verdict = r.verdict; rec.chainRoot = r.root_on_chain || null;
    if (r.verdict === "INTACT" && rec.cur) rec.baseline = rec.cur.leaves.slice();
    if (openId === r.batch_id) render();
  });

  document.addEventListener("soc:tamper", function (e) {
    ensure(e.detail.batch_id).tamperIndex = e.detail.index;
  });
})();
