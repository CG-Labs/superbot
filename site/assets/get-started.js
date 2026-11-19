// The "Get started" form: checks fields as the server does, posts them to
// /api/signups, and shows what happens next. Turnstile loads only when the server has it on.
(function () {
  "use strict";

  var form = document.getElementById("form");
  var summary = document.getElementById("summary");
  var submit = document.getElementById("submit");
  var turnstileToken = "";
  var turnstileWidget = null;
  // The server's settings; null until loaded. A failed load is retried on submit, so a
  // dropped connection can't leave the form without the bot check the server requires.
  var config = null;
  var needsTurnstile = false;

  var LIMITS = { name: 100, email: 254, company: 120, useCase: 2000 };
  var LABELS = {
    name: "Full name",
    email: "Work email",
    company: "Company",
    teamSize: "Team size",
    useCase: "What you'd like SuperBot to do",
    signIn: "How you'd like to sign in",
    consent: "Consent",
    turnstileToken: "Verification",
  };

  function el(id) { return document.getElementById(id); }

  function value(name) {
    var f = form.elements[name];
    if (!f) return "";
    if (f instanceof RadioNodeList) return f.value || "";
    if (f.type === "checkbox") return f.checked;
    return f.value;
  }

  function control(field) {
    if (field === "signIn") return form.querySelector('input[name="signIn"]');
    return el(field);
  }

  function setError(field, msg) {
    var err = el(field + "-err");
    if (err) err.textContent = msg || "";
    var c = field === "signIn" ? null : el(field);
    if (c) {
      if (msg) c.setAttribute("aria-invalid", "true");
      else c.removeAttribute("aria-invalid");
    }
  }

  function clearErrors() {
    Object.keys(LABELS).forEach(function (f) { setError(f, ""); });
    summary.hidden = true;
    summary.textContent = "";
  }

  function showSummary(text) {
    summary.textContent = text;
    summary.hidden = false;
    summary.focus();
  }

  function check() {
    var errors = {};
    ["name", "email", "company", "useCase"].forEach(function (f) {
      var v = value(f).trim();
      if (!v) errors[f] = LABELS[f] + " is required.";
      else if (v.length > LIMITS[f]) errors[f] = LABELS[f] + " must be at most " + LIMITS[f] + " characters.";
    });
    var email = value("email").trim();
    if (!errors.email && !/^[^\s@]+@[^\s@.][^\s@]*\.[^\s@]+$/.test(email)) errors.email = "Enter a valid work email.";
    if (!value("teamSize")) errors.teamSize = "Pick a team size.";
    if (!value("signIn")) errors.signIn = "Pick how you'd like to sign in.";
    if (!value("consent")) errors.consent = "Please agree so we can store your request and contact you about it.";
    if (needsTurnstile && !turnstileToken) {
      errors.turnstileToken = turnstileWidget === null
        ? "The check above is still loading, or was blocked. Wait a moment, or allow challenges.cloudflare.com, then try again."
        : "Please complete the check above.";
    }
    return errors;
  }

  function report(errors) {
    var fields = Object.keys(errors);
    fields.forEach(function (f) { setError(f, errors[f]); });
    if (fields.length === 1) {
      var c = control(fields[0]);
      if (c) c.focus();
    } else if (fields.length > 1) {
      showSummary("Please fix " + fields.length + " fields: " + fields.map(function (f) { return LABELS[f]; }).join(", ") + ".");
    }
  }

  function list(names) {
    if (names.length < 2) return names.join("");
    return names.slice(0, -1).join(", ") + " or " + names[names.length - 1];
  }

  function done(email, sso) {
    el("request").hidden = true;
    el("done").hidden = false;
    el("done-email").textContent = email;
    var names = (sso || []).map(function (p) { return p.label; }).filter(Boolean);
    if (names.length) {
      var hint = el("done-sso");
      hint.textContent = "Your company sign-in works here too: once your account is connected to " + list(names) +
        " after approval, you can sign in with it instead of a code.";
      hint.hidden = false;
    }
    document.title = "Request received · SuperBot";
    window.scrollTo({ top: 0, behavior: "instant" });
    el("done-title").focus({ preventScroll: true });
  }

  function resetTurnstile() {
    turnstileToken = "";
    if (turnstileWidget !== null && window.turnstile) window.turnstile.reset(turnstileWidget);
  }

  function loadTurnstile(siteKey) {
    window.superbotTurnstile = function () {
      turnstileWidget = window.turnstile.render("#turnstile", {
        sitekey: siteKey,
        callback: function (t) { turnstileToken = t; setError("turnstileToken", ""); },
        "expired-callback": function () { turnstileToken = ""; },
        "error-callback": function () { turnstileToken = ""; },
      });
    };
    var s = document.createElement("script");
    s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=superbotTurnstile";
    s.async = true;
    document.head.appendChild(s);
  }

  function loadConfig() {
    return fetch("/api/signups/config", { credentials: "omit" })
      .then(function (r) {
        if (!r.ok) throw new Error("config " + r.status);
        return r.json();
      })
      .then(function (cfg) {
        config = cfg;
        if (!cfg.enabled) {
          form.hidden = true;
          el("closed").hidden = false;
          return;
        }
        if (cfg.turnstileSiteKey) {
          needsTurnstile = true;
          loadTurnstile(cfg.turnstileSiteKey);
        }
      });
  }

  function ready() {
    return config ? Promise.resolve() : loadConfig();
  }

  loadConfig().catch(function () {});

  form.addEventListener("input", function (e) {
    var name = e.target && e.target.name;
    if (name && el(name + "-err") && el(name + "-err").textContent) setError(name, "");
  });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    clearErrors();
    ready().then(send, function () {
      showSummary("We couldn't reach SuperBot. Check your connection and try again.");
    });
  });

  function send() {
    if (!config.enabled) return;
    var errors = check();
    if (Object.keys(errors).length) return report(errors);

    var body = {
      name: value("name").trim(),
      email: value("email").trim(),
      company: value("company").trim(),
      teamSize: value("teamSize"),
      useCase: value("useCase").trim(),
      signIn: value("signIn"),
      consent: true,
      website: value("website"),
    };
    if (turnstileToken) body.turnstileToken = turnstileToken;

    submit.disabled = true;
    submit.textContent = "Sending…";
    fetch("/api/signups", {
      method: "POST",
      credentials: "omit",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (data) { return { status: r.status, data: data }; });
      })
      .then(function (res) {
        if (res.status === 202) return done(body.email, res.data.sso);
        resetTurnstile();
        if (res.status === 400 && res.data.field && LABELS[res.data.field]) {
          var one = {};
          one[res.data.field] = res.data.error;
          return report(one);
        }
        if (res.status === 429) return showSummary("Too many requests from your network. Please try again in a little while.");
        showSummary(res.data.error || "Something went wrong. Please try again.");
      })
      .catch(function () {
        resetTurnstile();
        showSummary("We couldn't reach SuperBot. Check your connection and try again.");
      })
      .then(function () {
        submit.disabled = false;
        submit.textContent = "Request access";
      });
  }
})();
