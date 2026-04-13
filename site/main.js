/* SwarmTrap.net — stats fetch + signup form submission */
(function () {
  /* ---- stat formatting ---- */
  function fmt(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
    return String(n);
  }

  function set(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  /* ---- fetch live stats (proof page) ---- */
  var statsEl = document.getElementById("stats");
  if (statsEl) {
    fetch("/api/stats")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        set("s-ips", fmt(d.ips_tracked || 0));
        set("s-attackers", fmt(d.confirmed_attackers || 0));
        set("s-sensors", String(d.honeypot_sensors || 0));
        set("s-evidence", fmt(d.evidence_events || 0));
        set("s-accuracy", (d.model_accuracy || 0).toFixed(1) + "%");
        set("s-captured", fmt(d.training_samples || 0));
      })
      .catch(function () { /* stats show dashes on failure */ });
  }

  /* ---- signup form (join page) ---- */
  var form = document.getElementById("signup-form");
  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var errEl = document.getElementById("form-error");
      errEl.className = "form-error";
      errEl.textContent = "";

      var name = form.querySelector('[name="name"]').value.trim();
      var email = form.querySelector('[name="email"]').value.trim();
      var why = form.querySelector('[name="why"]').value.trim();
      var website = form.querySelector('[name="website"]').value;

      var roles = [];
      form.querySelectorAll('[name="roles"]:checked').forEach(function (cb) {
        roles.push(cb.value);
      });

      if (!name || !email) {
        errEl.textContent = "Name and email are required.";
        errEl.className = "form-error visible";
        return;
      }
      if (roles.length === 0) {
        errEl.textContent = "Select at least one role.";
        errEl.className = "form-error visible";
        return;
      }

      var btn = form.querySelector('button[type="submit"]');
      btn.disabled = true;
      btn.textContent = "Submitting...";

      fetch("/api/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name,
          email: email,
          roles: roles,
          why: why || "",
          website: website
        })
      })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
        .then(function (res) {
          if (res.ok) {
            window.location.href = "/welcome";
          } else {
            errEl.textContent = res.data.error || "Something went wrong.";
            errEl.className = "form-error visible";
            btn.disabled = false;
            btn.textContent = "Join the founding cohort";
          }
        })
        .catch(function () {
          errEl.textContent = "Network error. Please try again.";
          errEl.className = "form-error visible";
          btn.disabled = false;
          btn.textContent = "Join the founding cohort";
        });
    });
  }
})();
