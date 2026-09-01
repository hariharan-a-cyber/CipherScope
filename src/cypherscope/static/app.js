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

  var STAGES = [
    "Reading packet capture…",
    "Reassembling TCP streams…",
    "Detecting STARTTLS upgrades…",
    "Parsing TLS handshake…",
    "Validating server certificates…",
    "Applying rule engine…",
  ];
  var STAGE_MS = 340; // time each stage is shown -> ~2s minimum

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
      '<div class="scan-bar"><div class="scan-bar-fill" id="scan-bar-fill"></div></div>' +
      "</div>";
    document.body.appendChild(el);
    return el;
  }

  // Walk the stage messages; resolves once every stage has been shown.
  function runStages() {
    var stageEl = document.getElementById("scan-stage");
    var fill = document.getElementById("scan-bar-fill");
    var i = 0;
    return new Promise(function (resolve) {
      (function tick() {
        if (i >= STAGES.length) {
          resolve();
          return;
        }
        stageEl.textContent = STAGES[i];
        fill.style.width = Math.round(((i + 1) / STAGES.length) * 100) + "%";
        i += 1;
        setTimeout(tick, STAGE_MS);
      })();
    });
  }

  function swapDocument(html) {
    document.open();
    document.write(html);
    document.close();
  }

  function scan(fetchPromise, fallbackUrl) {
    buildOverlay().classList.add("on");
    Promise.all([fetchPromise, runStages()])
      .then(function (results) {
        return results[0].text();
      })
      .then(function (html) {
        swapDocument(html);
      })
      .catch(function () {
        // network error talking to the local server: fall back to a plain load
        window.location.href = fallbackUrl;
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
          form.action
        );
      });
    }

    var links = document.querySelectorAll('a.btn[href^="/sample/"]');
    Array.prototype.forEach.call(links, function (a) {
      a.addEventListener("click", function (e) {
        e.preventDefault();
        scan(fetch(a.href), a.href);
      });
    });
  });
})();
