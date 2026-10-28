(function () {
  "use strict";
  // Apply a stored theme before first paint. Storage may be unavailable (file://,
  // private windows, blocked site data): fall back to the OS preference.
  try {
    var t = window.localStorage.getItem("driftwarden-theme");
    if (t === "light" || t === "dark") {
      document.documentElement.setAttribute("data-theme", t);
    }
  } catch (e) {}
  document.documentElement.classList.add("dw-js");
})();
