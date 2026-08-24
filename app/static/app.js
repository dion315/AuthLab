// Loaded as a file rather than inlined so the page runs under a strict
// `script-src 'self'` policy with no nonce and no 'unsafe-inline'.

(function () {
  "use strict";

  // --- weather -------------------------------------------------------------
  // Geolocation happens in the browser (only the browser knows where you are),
  // but the weather lookup itself goes through our own /api/weather. That keeps
  // the CSP at connect-src 'self' and keeps the weather provider from seeing
  // the user's browser at all.
  var target = document.getElementById("weather");

  function show(html, className) {
    if (!target) return;
    target.textContent = "";
    var node = document.createElement("div");
    if (className) node.className = className;
    node.textContent = html;
    target.appendChild(node);
  }

  function render(data) {
    if (!target) return;
    target.textContent = "";

    if (!data.available) {
      show(data.error || "Weather is unavailable right now.", "muted");
      return;
    }

    var line = document.createElement("div");
    line.className = "weather-line";
    line.textContent = Math.round(data.temperature) + data.units + " · " + data.description;
    target.appendChild(line);

    var detail = document.createElement("div");
    detail.className = "muted small";
    detail.textContent =
      "Humidity " + data.humidity + "% · Wind " +
      Math.round(data.wind_speed) + " " + data.wind_units;
    target.appendChild(detail);
  }

  function fetchWeather(latitude, longitude) {
    var url = "/api/weather?latitude=" + encodeURIComponent(latitude) +
              "&longitude=" + encodeURIComponent(longitude);
    fetch(url, { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.json();
      })
      .then(render)
      .catch(function () {
        show("Could not reach the weather service.", "muted");
      });
  }

  if (target) {
    if (!navigator.geolocation) {
      show("This browser does not support geolocation.", "muted");
    } else {
      show("Locating…", "muted");
      navigator.geolocation.getCurrentPosition(
        function (position) {
          fetchWeather(position.coords.latitude, position.coords.longitude);
        },
        function (error) {
          // Permission denied is the common case and is not an app failure —
          // say so plainly rather than showing an error.
          var message =
            error && error.code === 1
              ? "Location permission denied, so no local weather."
              : "Location unavailable.";
          show(message, "muted");
        },
        { timeout: 10000, maximumAge: 300000 }
      );
    }
  }

  // --- copy-to-clipboard ---------------------------------------------------
  // Used for the redirect URI, ACS URL, and SCIM token — values that get
  // pasted into an IdP console and are painful to retype.
  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-copy-target]");
    if (!button) return;

    var field = document.getElementById(button.getAttribute("data-copy-target"));
    if (!field) return;

    field.select();
    field.setSelectionRange(0, 99999);

    var done = function () {
      var original = button.textContent;
      button.textContent = "Copied";
      setTimeout(function () { button.textContent = original; }, 1400);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(field.value).then(done, function () {});
    }
  });

  // --- repeatable form rows -------------------------------------------------
  // Role mapping rules and expectation rows behave identically: clone a
  // <template> onto the end of a list, and remove a row on request.
  function wireRowAdder(buttonId, listId, templateId) {
    var button = document.getElementById(buttonId);
    if (!button) return;
    button.addEventListener("click", function () {
      var list = document.getElementById(listId);
      var template = document.getElementById(templateId);
      if (!list || !template) return;
      list.appendChild(template.content.cloneNode(true));
    });
  }

  wireRowAdder("add-rule", "rule-list", "rule-template");
  wireRowAdder("add-expectation", "expectation-list", "expectation-template");

  document.addEventListener("click", function (event) {
    if (!event.target.matches("[data-remove-rule]")) return;
    var row = event.target.closest(".rule-row");
    if (row) row.remove();
  });

  // --- per-provider terminology hints ---------------------------------------
  // Every provider's wording for every field is rendered up front and hidden;
  // choosing one just reveals the matching set. Doing it in the browser rather
  // than by reloading the form matters because the form is usually half filled
  // in by the time somebody realises they want the hints.
  var vocabSelect = document.querySelector("[data-vocab-select]");
  if (vocabSelect) {
    // Protocol and slug come from the container rather than from a form
    // field: the hidden protocol input only exists when creating a connection,
    // and the edit page still needs both in the link.
    var helpHolder = document.querySelector("[data-provider-help-link]");
    var helpLink = helpHolder ? helpHolder.querySelector("a") : null;
    var protocol = helpHolder ? helpHolder.getAttribute("data-protocol") || "" : "";
    var slug = helpHolder ? helpHolder.getAttribute("data-slug") || "" : "";

    var applyVocab = function () {
      var chosen = vocabSelect.value;
      var hints = document.querySelectorAll(".vocab");
      for (var i = 0; i < hints.length; i++) {
        var matches = chosen && hints[i].getAttribute("data-vocab-for") === chosen;
        hints[i].classList.toggle("shown", !!matches);
      }
      if (helpLink) {
        var query = [];
        if (protocol) query.push("protocol=" + encodeURIComponent(protocol));
        if (slug) query.push("slug=" + encodeURIComponent(slug));
        helpLink.href = chosen
          ? "/help/" + encodeURIComponent(chosen) + (query.length ? "?" + query.join("&") : "")
          : "/help";
        helpLink.textContent = chosen
          ? "Open the step-by-step guide for this provider →"
          : "Browse the setup guides →";
      }
    };

    vocabSelect.addEventListener("change", applyVocab);
    applyVocab();
  }
})();
