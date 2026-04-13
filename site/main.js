// SwarmTrap.net — fetch live stats from API proxy
(function () {
  const API = '/api/stats';

  function fmt(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return String(n);
  }

  function set(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  fetch(API)
    .then(function (r) { return r.json(); })
    .then(function (d) {
      set('s-ips', fmt(d.ips_tracked || 0));
      set('s-attackers', fmt(d.confirmed_attackers || 0));
      set('s-sensors', String(d.honeypot_sensors || 0));
      set('s-evidence', fmt(d.evidence_events || 0));
      set('s-accuracy', (d.model_accuracy || 0).toFixed(1) + '%');
      set('s-captured', fmt(d.training_samples || 0));
    })
    .catch(function () {
      // Silently fail — stats just show dashes
    });
})();
