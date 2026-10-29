(function () {
  "use strict";
  // Progressive enhancement only: the page is complete without this script.
  var KEY = "driftwarden-theme";
  var root = document.documentElement;

  function each(sel, fn) {
    Array.prototype.forEach.call(document.querySelectorAll(sel), fn);
  }

  each("[data-dw-controls]", function (el) { el.hidden = false; });
  each("[data-dw-copy]", function (el) { el.hidden = false; });

  // ---- Theme: system -> light -> dark -> system --------------------------
  var themeBtn = document.querySelector("[data-dw-theme]");
  function currentTheme() {
    var t = root.getAttribute("data-theme");
    return t === "light" || t === "dark" ? t : "system";
  }
  function showTheme() {
    if (themeBtn) themeBtn.textContent = "Theme: " + currentTheme();
  }
  if (themeBtn) {
    showTheme();
    themeBtn.addEventListener("click", function () {
      var next = { system: "light", light: "dark", dark: "system" }[currentTheme()];
      if (next === "system") root.removeAttribute("data-theme");
      else root.setAttribute("data-theme", next);
      try {
        if (next === "system") window.localStorage.removeItem(KEY);
        else window.localStorage.setItem(KEY, next);
      } catch (e) {}
      showTheme();
    });
  }

  // ---- Filter ------------------------------------------------------------
  var input = document.querySelector("[data-dw-search]");
  var count = document.querySelector("[data-dw-count]");
  var items = document.querySelectorAll(".dw-filterable");
  var texts = null;
  function filter() {
    if (texts === null) {
      texts = Array.prototype.map.call(items, function (el) {
        return el.textContent.toLowerCase();
      });
    }
    var q = input.value.trim().toLowerCase();
    var shown = 0;
    for (var i = 0; i < items.length; i++) {
      var hit = !q || texts[i].indexOf(q) !== -1;
      items[i].hidden = !hit;
      if (hit) shown++;
    }
    if (q) {
      each("details.dw-fold", function (d) {
        if (d.querySelector(".dw-filterable:not([hidden])")) d.open = true;
      });
    }
    if (count) count.textContent = q ? shown + " of " + items.length + " shown" : "";
  }
  if (input) input.addEventListener("input", filter);

  // ---- Expand / collapse -------------------------------------------------
  function setAll(open) {
    each("details", function (d) { d.open = open; });
  }
  var ex = document.querySelector("[data-dw-expand]");
  var co = document.querySelector("[data-dw-collapse]");
  if (ex) ex.addEventListener("click", function () { setAll(true); });
  if (co) co.addEventListener("click", function () { setAll(false); });

  // Print: expand everything, then restore.
  var before = [];
  window.addEventListener("beforeprint", function () {
    before = [];
    each("details", function (d) { before.push(d.open); d.open = true; });
  });
  window.addEventListener("afterprint", function () {
    var i = 0;
    each("details", function (d) { if (i < before.length) d.open = before[i]; i++; });
  });

  // ---- Copy draft Markdown ----------------------------------------------
  function fallbackCopy(el) {
    var range = document.createRange();
    range.selectNodeContents(el);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) {}
    return ok;
  }
  each("[data-dw-copy]", function (btn) {
    btn.addEventListener("click", function () {
      var el = document.getElementById(btn.getAttribute("data-dw-copy"));
      if (!el) return;
      var text = el.textContent;
      function done(ok) {
        btn.textContent = ok ? "Copied" : "Selected: press Ctrl+C";
        window.setTimeout(function () { btn.textContent = "Copy Markdown"; }, 2000);
      }
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(
          function () { done(true); },
          function () { done(fallbackCopy(el)); }
        );
      } else {
        done(fallbackCopy(el));
      }
    });
  });
})();
