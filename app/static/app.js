// Page behaviour. Loaded as a file rather than inlined so every page runs
// under a strict `script-src 'self'` policy with no nonce and no
// 'unsafe-inline'. Theme resolution lives in theme.js, which must run before
// paint; everything here can wait for the DOM.
//
// Loaded on every page, so each section checks for the elements it needs
// rather than assuming a particular page.

(function () {
  "use strict";

  // --- theme control -------------------------------------------------------

  function syncThemeButtons() {
    if (!window.AuthLabTheme) return;
    var current = window.AuthLabTheme.get();
    var buttons = document.querySelectorAll("[data-theme-set]");
    for (var i = 0; i < buttons.length; i++) {
      var button = buttons[i];
      button.setAttribute(
        "aria-pressed",
        button.getAttribute("data-theme-set") === current ? "true" : "false"
      );
    }
  }

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-theme-set]");
    if (!button || !window.AuthLabTheme) return;
    window.AuthLabTheme.set(button.getAttribute("data-theme-set"));
    syncThemeButtons();
  });

  document.addEventListener("authlab:themechange", syncThemeButtons);
  window.addEventListener("storage", syncThemeButtons);
  syncThemeButtons();

  // --- mobile navigation ---------------------------------------------------

  var header = document.querySelector(".app-header");
  var navToggle = document.querySelector(".nav-toggle");

  if (header && navToggle) {
    navToggle.addEventListener("click", function () {
      var open = header.classList.toggle("nav-open");
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
    });

    // A menu that stays open behind the page you just navigated to, or after
    // you tap away from it, feels broken on a phone.
    document.addEventListener("click", function (event) {
      if (!header.classList.contains("nav-open")) return;
      if (header.contains(event.target)) return;
      header.classList.remove("nav-open");
      navToggle.setAttribute("aria-expanded", "false");
    });

    document.addEventListener("keydown", function (event) {
      if (event.key !== "Escape") return;
      header.classList.remove("nav-open");
      navToggle.setAttribute("aria-expanded", "false");
    });
  }

  // --- password visibility -------------------------------------------------

  document.addEventListener("click", function (event) {
    var toggle = event.target.closest("[data-toggle-password]");
    if (!toggle) return;
    var field = document.getElementById(toggle.getAttribute("data-toggle-password"));
    if (!field) return;
    var showing = field.type === "text";
    field.type = showing ? "password" : "text";
    toggle.textContent = showing ? "Show" : "Hide";
    toggle.setAttribute("aria-label", showing ? "Show password" : "Hide password");
  });

  // --- copy to clipboard ---------------------------------------------------
  // Used for the redirect URI, ACS URL, SCIM token, and certificate PEMs —
  // values that get pasted into a provider console and are painful to retype.

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-copy-target]");
    if (!button) return;

    var field = document.getElementById(button.getAttribute("data-copy-target"));
    if (!field) return;

    field.select();
    if (field.setSelectionRange) field.setSelectionRange(0, 99999);

    var done = function () {
      var original = button.getAttribute("data-original-label") || button.textContent;
      button.setAttribute("data-original-label", original);
      button.textContent = "Copied";
      setTimeout(function () {
        button.textContent = original;
      }, 1400);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(field.value).then(done, function () {});
    }
  });

  // --- role mapping rule rows ----------------------------------------------

  var addRule = document.getElementById("add-rule");
  if (addRule) {
    addRule.addEventListener("click", function () {
      var list = document.getElementById("rule-list");
      var template = document.getElementById("rule-template");
      if (!list || !template) return;
      list.appendChild(template.content.cloneNode(true));
    });

    document.addEventListener("click", function (event) {
      if (!event.target.matches("[data-remove-rule]")) return;
      var row = event.target.closest(".rule-row");
      if (row) row.remove();
    });
  }

  // --- weather -------------------------------------------------------------
  // Geolocation happens in the browser (only the browser knows where you are),
  // but the weather lookup itself goes through our own /api/weather. That keeps
  // the CSP at connect-src 'self' and keeps the weather provider from seeing
  // the user's browser at all.

  var target = document.getElementById("weather");

  function message(text) {
    if (!target) return;
    target.textContent = "";
    var node = document.createElement("div");
    node.className = "muted small";
    node.textContent = text;
    target.appendChild(node);
  }

  function render(data) {
    if (!target) return;
    target.textContent = "";

    if (!data.available) {
      message(data.error || "Weather is unavailable right now.");
      return;
    }

    var row = document.createElement("div");
    row.className = "weather";

    var temperature = document.createElement("div");
    temperature.className = "weather-temp";
    temperature.textContent = Math.round(data.temperature) + data.units;
    row.appendChild(temperature);

    var description = document.createElement("div");
    description.textContent = data.description;
    row.appendChild(description);

    target.appendChild(row);

    var detail = document.createElement("div");
    detail.className = "muted small";
    detail.textContent =
      "Humidity " +
      data.humidity +
      "% · Wind " +
      Math.round(data.wind_speed) +
      " " +
      data.wind_units;
    target.appendChild(detail);
  }

  function fetchWeather(latitude, longitude) {
    var url =
      "/api/weather?latitude=" +
      encodeURIComponent(latitude) +
      "&longitude=" +
      encodeURIComponent(longitude);
    fetch(url, { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.json();
      })
      .then(render)
      .catch(function () {
        message("Could not reach the weather service.");
      });
  }

  if (target) {
    if (!navigator.geolocation) {
      message("This browser does not support geolocation.");
    } else {
      message("Locating…");
      navigator.geolocation.getCurrentPosition(
        function (position) {
          fetchWeather(position.coords.latitude, position.coords.longitude);
        },
        function (error) {
          // Permission denied is the common case and is not an app failure —
          // say so plainly rather than showing an error.
          message(
            error && error.code === 1
              ? "Location permission denied, so no local weather."
              : "Location unavailable."
          );
        },
        { timeout: 10000, maximumAge: 300000 }
      );
    }
  }
})();
