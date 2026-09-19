/*
 * Scan progress overlay.
 *
 * The pipeline itself is fast, so without feedback a scan looks like it never
 * ran. This intercepts the upload form and the sample "Scan" links, shows a
 * spinner that walks through the real pipeline stages, then swaps in the
 * report page the server returns.
 */
(function () {
  "use strict";

  // Each stage gets its own duration so the bar moves at an uneven, realistic
  // pace instead of ticking like a metronome. Total is ~6s.
  var STAGES = [
    { label: "Reading packet capture…",         detail: "opening file and indexing frames",              ms: 700 },
    { label: "Reassembling TCP streams…",       detail: "grouping packets into sessions by 4-tuple",     ms: 1100 },
    { label: "Detecting STARTTLS upgrades…",    detail: "inspecting SMTP, IMAP and POP3 command streams", ms: 900 },
    { label: "Parsing TLS handshake…",          detail: "ClientHello / ServerHello, version and cipher", ms: 1300 },
    { label: "Validating server certificates…", detail: "expiry, key size, signature, self-signed check", ms: 1200 },
    { label: "Applying rule engine…",           detail: "scoring each session against rules.yaml",       ms: 600 },
    { label: "Building report…",                detail: "collecting findings",                       ms: 400 },
  ];

  function buildOverlay() {
    var el = document.getElementById("scan-overlay");
    if (el) return el;
    el = document.createElement("div");
    el.id = "scan-overlay";
    el.className = "scan-overlay";
    el.setAttribute("role", "status");
    el.setAttribute("aria-live", "polite");
    el.innerHTML =
      '<div class="scan-box">' +
      '<div class="scan-spinner"></div>' +
      '<div class="scan-title">Scanning capture</div>' +
      '<div class="scan-stage" id="scan-stage">Starting…</div>' +
      '<div class="scan-detail" id="scan-detail"></div>' +
      '<div class="scan-bar"><div class="scan-bar-fill" id="scan-bar-fill"></div></div>' +
      '<div class="scan-steps" id="scan-steps"></div>' +
      "</div>";
    document.body.appendChild(el);
    return el;
  }

  // Walk the stage messages; resolves once every stage has been shown.
  // The bar fills continuously within a stage (via CSS transition) so it is
  // always moving, and a checklist below ticks off completed stages.
  function runStages() {
    var stageEl = document.getElementById("scan-stage");
    var detailEl = document.getElementById("scan-detail");
    var fill = document.getElementById("scan-bar-fill");
    var stepsEl = document.getElementById("scan-steps");
    var total = STAGES.reduce(function (n, st) { return n + st.ms; }, 0);
    var elapsed = 0;
    var i = 0;

    stepsEl.innerHTML = "";
    STAGES.forEach(function (st) {
      var li = document.createElement("div");
      li.className = "scan-step";
      li.textContent = st.label.replace(/…$/, "");
      stepsEl.appendChild(li);
    });
    var stepEls = stepsEl.children;

    return new Promise(function (resolve) {
      (function tick() {
        if (i > 0) stepEls[i - 1].className = "scan-step done";
        if (i >= STAGES.length) {
          stageEl.textContent = "Scan complete";
          detailEl.textContent = "";
          resolve();
          return;
        }
        var st = STAGES[i];
        stepEls[i].className = "scan-step active";
        stageEl.textContent = st.label;
        detailEl.textContent = st.detail;
        elapsed += st.ms;
        fill.style.transitionDuration = st.ms + "ms";
        fill.style.width = Math.round((elapsed / total) * 100) + "%";
        i += 1;
        setTimeout(tick, st.ms);
      })();
    });
  }

  function swapDocument(html) {
    document.open();
    document.write(html);
    document.close();
  }

  // fallback: what to do if the fetch itself fails (network error). Must
  // re-issue the same request natively; a GET of the upload URL would 405.
  function scan(fetchPromise, fallback) {
    buildOverlay().classList.add("on");
    Promise.all([fetchPromise, runStages()])
      .then(function (results) {
        return results[0].text();
      })
      .then(function (html) {
        swapDocument(html);
      })
      .catch(function (err) {
        if (window.console) console.error("scan overlay failed, falling back:", err);
        fallback();
      });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var form = document.querySelector("form.upload");
    if (form) {
      form.addEventListener("submit", function (e) {
        var input = form.querySelector('input[type="file"]');
        if (!input || !input.files || input.files.length === 0) {
          return; // nothing picked: let the browser's required-field prompt fire
        }
        e.preventDefault();
        scan(
          fetch(form.action, { method: "POST", body: new FormData(form) }),
          function () { HTMLFormElement.prototype.submit.call(form); }
        );
      });
    }

    var links = document.querySelectorAll('a.btn[href^="/sample/"]');
    Array.prototype.forEach.call(links, function (a) {
      a.addEventListener("click", function (e) {
        e.preventDefault();
        scan(fetch(a.href), function () { window.location.href = a.href; });
      });
    });
  });
})();
