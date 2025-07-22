/*
 * Author: Tim Rice <tim.j.rice@hackrange.com>
 * Part of nextgen-dast. See README.md for license and overall architecture.
 *
 * Dashboard trend-chart helpers:
 *   1. Custom typeahead for the "filter by target" search box. Shows
 *      suggestions only after the user starts typing -- avoids the
 *      browser-native <datalist> behavior of dumping the whole list as
 *      a drop-down on focus.
 *   2. Hover tooltip + crosshair on the 30-day trend SVG. Maps cursor X
 *      to a day index, then renders the per-severity counts for that
 *      day in a floating box anchored near the cursor.
 *
 * Both scripts are progressive enhancement: if JS fails to load, the
 * form still submits as a normal GET and the chart still renders -- you
 * just don't get the niceties.
 */
(function () {
  "use strict";

  // ---------------------------------------------------------------
  // 1. Typeahead
  // ---------------------------------------------------------------
  // The form has data-targets (JSON string array). We attach handlers
  // to its <input.typeahead-input> + <ul.typeahead-suggest>. Suggestions
  // are computed on every keystroke from the in-memory targets list;
  // limit to MAX_RESULTS so very large deployments don't render 500
  // items.
  const MAX_RESULTS = 12;

  function setupTypeahead(form) {
    let targets = [];
    try {
      targets = JSON.parse(form.dataset.targets || "[]");
    } catch (_) {
      return; // bad JSON; leave the input as a plain text input
    }
    const input = form.querySelector(".typeahead-input");
    const ul = form.querySelector(".typeahead-suggest");
    if (!input || !ul) return;
    let activeIndex = -1;

    function render(matches) {
      ul.innerHTML = "";
      activeIndex = -1;
      if (!matches.length) {
        ul.hidden = true;
        return;
      }
      matches.forEach(function (m, i) {
        const li = document.createElement("li");
        li.textContent = m;
        li.setAttribute("role", "option");
        li.dataset.idx = String(i);
        li.addEventListener("mousedown", function (ev) {
          // mousedown not click: input's blur fires before click and
          // would hide the popup before the click registers.
          ev.preventDefault();
          input.value = m;
          ul.hidden = true;
          form.submit();
        });
        ul.appendChild(li);
      });
      ul.hidden = false;
    }

    function compute(q) {
      q = (q || "").trim().toLowerCase();
      if (!q) return [];
      const out = [];
      for (let i = 0; i < targets.length && out.length < MAX_RESULTS; i++) {
        if (targets[i].toLowerCase().indexOf(q) !== -1) out.push(targets[i]);
      }
      return out;
    }

    input.addEventListener("input", function () {
      render(compute(input.value));
    });
    input.addEventListener("focus", function () {
      // Only re-show if there's already typed text. Empty focus =
      // empty popup = no drop-down spam.
      if (input.value.trim()) render(compute(input.value));
    });
    input.addEventListener("blur", function () {
      // Slight delay so the mousedown handler on suggestions fires first.
      setTimeout(function () { ul.hidden = true; }, 120);
    });
    input.addEventListener("keydown", function (ev) {
      const items = ul.querySelectorAll("li");
      if (ev.key === "ArrowDown") {
        ev.preventDefault();
        if (!items.length) return;
        activeIndex = (activeIndex + 1) % items.length;
        items.forEach(function (li, i) {
          li.classList.toggle("active", i === activeIndex);
        });
      } else if (ev.key === "ArrowUp") {
        ev.preventDefault();
        if (!items.length) return;
        activeIndex = (activeIndex - 1 + items.length) % items.length;
        items.forEach(function (li, i) {
          li.classList.toggle("active", i === activeIndex);
        });
      } else if (ev.key === "Enter") {
        if (activeIndex >= 0 && items[activeIndex]) {
          ev.preventDefault();
          input.value = items[activeIndex].textContent;
          ul.hidden = true;
          form.submit();
        }
      } else if (ev.key === "Escape") {
        ul.hidden = true;
      }
    });
  }

  // ---------------------------------------------------------------
  // 2. Trend hover tooltip
  // ---------------------------------------------------------------
  // The chart wrapper holds two data attributes:
  //   data-days   = JSON array of 30 ISO dates ["2026-03-30", ...]
  //   data-series = JSON object {critical: [n,n,...], high: [...], ...}
  // We compute the day index from cursor X relative to the SVG's
  // bounding box, then render a small box with counts.
  const SEV_ORDER = ["critical", "high", "medium", "low"];
  const SEV_LABEL = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
  };

  function setupTooltip(grid) {
    let days, series;
    try {
      days = JSON.parse(grid.dataset.days || "[]");
      series = JSON.parse(grid.dataset.series || "{}");
    } catch (_) {
      return;
    }
    if (!days.length) return;
    const wrap = grid.querySelector(".trend-svg-wrap");
    const svg = grid.querySelector(".trend-svg");
    const tip = grid.querySelector(".trend-tooltip");
    const xhair = grid.querySelector(".trend-crosshair");
    if (!wrap || !svg || !tip || !xhair) return;

    function dayIndexFromX(x, width) {
      // X is in CSS pixels relative to the wrap; days are evenly
      // distributed across the chart width with one tick per day.
      const ratio = Math.max(0, Math.min(1, x / Math.max(1, width)));
      const idx = Math.round(ratio * (days.length - 1));
      return Math.max(0, Math.min(days.length - 1, idx));
    }

    function fmtDate(iso) {
      // ISO yyyy-mm-dd -> "Mon DD" e.g. "Apr 02".
      const parts = (iso || "").split("-");
      if (parts.length !== 3) return iso;
      const months = ["Jan","Feb","Mar","Apr","May","Jun",
                      "Jul","Aug","Sep","Oct","Nov","Dec"];
      const m = parseInt(parts[1], 10) - 1;
      const d = parseInt(parts[2], 10);
      if (isNaN(m) || isNaN(d) || m < 0 || m > 11) return iso;
      return months[m] + " " + (d < 10 ? "0" + d : d);
    }

    function show(idx, cursorX) {
      const total = SEV_ORDER.reduce(function (s, sev) {
        return s + ((series[sev] && series[sev][idx]) || 0);
      }, 0);
      let html = "<div class='tt-date'>" + fmtDate(days[idx]) + "</div>";
      html += "<div class='tt-total'>" + total + " open</div>";
      SEV_ORDER.forEach(function (sev) {
        const n = (series[sev] && series[sev][idx]) || 0;
        if (n > 0) {
          html += "<div class='tt-row'>" +
                  "<span class='sev-dot sev-" + sev + "'></span>" +
                  "<span class='tt-label'>" + SEV_LABEL[sev] + "</span>" +
                  "<span class='tt-n'>" + n + "</span>" +
                  "</div>";
        }
      });
      tip.innerHTML = html;
      tip.hidden = false;
      xhair.hidden = false;

      // Position crosshair at the day's actual chart-X (snapped to
      // the day grid, not the raw cursor X).
      const wrapBox = wrap.getBoundingClientRect();
      const chartX = (idx / Math.max(1, days.length - 1)) * wrapBox.width;
      xhair.style.left = chartX + "px";

      // Tooltip flips left of the cursor when too close to the right edge.
      const tipBox = tip.getBoundingClientRect();
      let left = chartX + 12;
      if (left + tipBox.width > wrapBox.width - 4) {
        left = chartX - tipBox.width - 12;
      }
      if (left < 4) left = 4;
      tip.style.left = left + "px";
      tip.style.top = "8px";
    }

    function hide() {
      tip.hidden = true;
      xhair.hidden = true;
    }

    wrap.addEventListener("mousemove", function (ev) {
      const box = wrap.getBoundingClientRect();
      const x = ev.clientX - box.left;
      if (x < 0 || x > box.width) { hide(); return; }
      const idx = dayIndexFromX(x, box.width);
      show(idx, x);
    });
    wrap.addEventListener("mouseleave", hide);
    // Touch: tap-to-show-day. No drag tracking; user taps near a date.
    wrap.addEventListener("touchstart", function (ev) {
      if (!ev.touches.length) return;
      const box = wrap.getBoundingClientRect();
      const x = ev.touches[0].clientX - box.left;
      const idx = dayIndexFromX(x, box.width);
      show(idx, x);
    }, { passive: true });
  }

  // ---------------------------------------------------------------
  // Bootstrap
  // ---------------------------------------------------------------
  function init() {
    document.querySelectorAll("form.typeahead").forEach(setupTypeahead);
    document.querySelectorAll(".trend-grid").forEach(setupTooltip);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
