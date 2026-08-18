// Theme resolution, loaded synchronously in <head>.
//
// This is a separate file from app.js, and deliberately not deferred, because
// it has to run before the first paint: applying a stored dark preference from
// a DOMContentLoaded handler produces a white flash on every navigation. Under
// this app's Content Security Policy (`script-src 'self'`, no 'unsafe-inline')
// an inline <script> in <head> — the usual way to do this — is not an option,
// so it is a real file instead.
//
// Three states, not two. "system" is the default and means "follow the
// operating system", which a boolean toggle cannot express: a user whose
// system switches to dark in the evening wants the app to follow, and that is
// a different intent from having chosen light.

(function () {
  "use strict";

  var KEY = "authlab.theme";
  var VALID = { system: true, light: true, dark: true };
  var root = document.documentElement;

  function read() {
    try {
      var stored = window.localStorage.getItem(KEY);
      return VALID[stored] ? stored : "system";
    } catch (error) {
      // Private browsing modes throw on localStorage access. Following the
      // system preference is the right fallback, not an error.
      return "system";
    }
  }

  function resolved(mode) {
    if (mode === "system") {
      return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
    }
    return mode;
  }

  function paintBrowserChrome(mode) {
    // Colours the address bar on mobile so the page does not end at a
    // mismatched white strip.
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", resolved(mode) === "dark" ? "#0b0e14" : "#ffffff");
  }

  function apply(mode) {
    if (mode === "light" || mode === "dark") {
      root.setAttribute("data-theme", mode);
    } else {
      // No attribute at all, so the stylesheet's prefers-color-scheme rules
      // take over. That is what makes "system" live rather than a snapshot.
      root.removeAttribute("data-theme");
    }
    paintBrowserChrome(mode);
  }

  function set(mode) {
    if (!VALID[mode]) mode = "system";
    try {
      window.localStorage.setItem(KEY, mode);
    } catch (error) {
      // Preference does not persist; applying it to this page still works.
    }
    apply(mode);
    document.dispatchEvent(new CustomEvent("authlab:themechange", { detail: { mode: mode } }));
  }

  apply(read());

  // Another tab changed the preference.
  window.addEventListener("storage", function (event) {
    if (event.key === KEY) apply(read());
  });

  // The system flipped while "system" is selected — repaint the browser chrome
  // to match. The CSS handles itself.
  if (window.matchMedia) {
    var query = window.matchMedia("(prefers-color-scheme: dark)");
    var onChange = function () {
      if (read() === "system") paintBrowserChrome("system");
    };
    if (query.addEventListener) query.addEventListener("change", onChange);
    else if (query.addListener) query.addListener(onChange);
  }

  window.AuthLabTheme = { get: read, set: set, resolved: resolved };
})();
