/*
 * Author: Tim Rice <tim.j.rice@hackrange.com>
 * Part of nextgen-dast. See README.md for license and overall architecture.
 *
 * Help-modal layer for the Swagger UI playground at /api/v1/docs.
 *
 * Adds a circle-? button next to every known field name in the rendered
 * Swagger UI DOM. Clicking opens a modal that explains the field, lists
 * its valid values (for enums) or its live id->label table (for the
 * integer FK fields like llm_endpoint_id and user_agent_id), and shows
 * sample values.
 *
 * Help content is keyed by field name (the request-body / query-param
 * name as it appears in OpenAPI). Lookup tables are loaded once from
 * /api/v1/lookups on first interaction.
 */
(function () {
  "use strict";

  // ---- Help registry. Keyed by the OpenAPI field name. -------------------
  //
  // Each entry MAY have:
  //   summary    one-line description (rendered first)
  //   enum       array of {value, label} for documented enum values
  //   lookup     name of a /api/v1/lookups key whose array of
  //              {id, label} should be rendered as the value table
  //   examples   array of strings to render in an "Examples" section
  //   notes      array of strings rendered as a bulleted "Notes" list
  //   title      override the modal title (defaults to the field name)
  const HELP = {
    fqdn: {
      title: "fqdn — target hostname",
      summary:
        "The host the scanners aim at. May include a non-default port. " +
        "Any leading http:// or https:// is stripped before use.",
      examples: [
        "app.example.com",
        "app.example.com:8443",
        "127.0.0.1:10001",
      ],
      notes: [
        "scan_http and scan_https control which schemes are probed.",
        "For non-standard ports, set only the scheme that listens on " +
          "that port to avoid wasted scanner runs.",
      ],
    },
    application_id: {
      title: "application_id — caller-supplied identifier",
      summary:
        "Free-form, optional identifier for the application under test. " +
        "Indexed in the DB and round-tripped on every API response so " +
        "you can correlate scans back to your CMDB / app catalog.",
      examples: ["APP-1234", "svc.payments.checkout", "JIRA-PROJ-42"],
      notes: [
        "Searchable via the application_id query parameter on " +
          "GET /api/v1/scans.",
      ],
    },
    profile: {
      title: "profile — scan profile",
      summary:
        "Controls which scanners run and how aggressive they are. " +
        "Trade-off is run-time vs coverage.",
      lookup: "profiles",
      notes: ["Default is 'standard' if omitted."],
    },
    llm_tier: {
      title: "llm_tier — LLM analysis level",
      summary:
        "How much LLM analysis runs after the scanners finish. Default " +
        "is 'none' so callers never accrue LLM cost (or send scan " +
        "output off-box) without explicitly opting in.",
      lookup: "llm_tiers",
    },
    llm_endpoint_id: {
      title: "llm_endpoint_id — specific LLM endpoint",
      summary:
        "Integer id of the LLM endpoint to use, from the table below. " +
        "Omit (or set null) to use the default endpoint, which is the " +
        "row marked is_default=1 (or the lowest-id endpoint if no " +
        "default is set).",
      lookup: "llm_endpoints",
      notes: [
        "Manage endpoints at /llm in the web UI.",
        "Only consulted when llm_tier is 'basic' or 'advanced'.",
      ],
    },
    user_agent_id: {
      title: "user_agent_id — User-Agent string for scanners",
      summary:
        "Integer id of the User-Agent to present, from the table below. " +
        "Omit (or set null) to use the default UA.",
      lookup: "user_agents",
      notes: ["Manage UAs at /user-agents in the web UI."],
    },
    scan_http: {
      title: "scan_http — probe http://",
      summary:
        "When true, scanners run against http://<fqdn>. Set false for " +
        "HTTPS-only sites to skip a wasted unencrypted pass.",
    },
    scan_https: {
      title: "scan_https — probe https://",
      summary:
        "When true, scanners run against https://<fqdn>. Required for " +
        "testssl results and the post-quantum readiness section of the " +
        "PDF report.",
    },
    creds_username: {
      title: "creds_username — application username",
      summary:
        "Username for an authenticated scan. Pair with creds_password " +
        "and (for form login) login_url.",
      notes: [
        "For SSO / Okta FastPass / DUO targets, use the capture-then-" +
          "replay flow at /auth instead. Form-based credentials cannot " +
          "drive MFA.",
      ],
    },
    creds_password: {
      title: "creds_password — application password",
      summary:
        "Password for an authenticated scan. Stored alongside the " +
        "assessment row so the scanners and the validation toolkit " +
        "can re-establish a session.",
      notes: [
        "Audit your retention policy. Delete the assessment to remove " +
          "the stored password.",
      ],
    },
    login_url: {
      title: "login_url — form-POST login endpoint",
      summary:
        "When set, wapiti drives form-based authentication against this " +
        "URL. When omitted, the scan falls back to HTTP basic auth " +
        "using creds_username / creds_password.",
      examples: [
        "https://app.example.com/login",
        "https://app.example.com/api/auth/token",
      ],
    },
    format: {
      title: "format — response format",
      summary:
        "Output shape for GET /api/v1/scans/{scan_id}/results.",
      lookup: "formats",
    },
    include_false_positives: {
      title: "include_false_positives",
      summary:
        "When true, returns findings the analyst has marked as false " +
        "positive. Default false, matching the behavior of the score " +
        "rollup and the generated PDF report.",
    },
    include_info: {
      title: "include_info — include info-severity rows",
      summary:
        "When true (default), info-severity findings are included in " +
        "the response. Set false to suppress them, mirroring the " +
        "per-assessment 'hide info-severity findings' toggle that the " +
        "web UI and the PDF report honor.",
      notes: [
        "Info severity is high-volume / low-signal noise from scanners " +
          "(e.g. fingerprinted server banners). Suppressing it yields a " +
          "much shorter actionable list.",
      ],
    },
    include_accepted_risk: {
      title: "include_accepted_risk — include archived findings",
      summary:
        "When true, returns findings the analyst archived (set status = " +
        "accepted_risk). Default false, matching the workspace and PDF " +
        "report which exclude archived rows from the actionable view.",
      notes: [
        "Use true when reconciling a backlog or producing a complete " +
          "audit export, false (default) for an actionable oncall list.",
      ],
    },
    limit: {
      title: "limit — max scans to return",
      summary:
        "Maximum number of scans to return from GET /api/v1/scans. " +
        "Capped server-side at 500.",
      examples: ["10", "50", "200"],
    },
    scan_id: {
      title: "scan_id — assessment id",
      summary:
        "Integer id of an assessment, as echoed by POST /api/v1/scans " +
        "in the `scan_id` field of the response.",
    },
  };

  // ---- Lookup loader. Lazy + cached + best-effort. -----------------------
  let LOOKUPS = null;
  let lookupsPromise = null;

  // The lookups endpoint is sibling to /docs, so a relative URL works
  // regardless of UI_ROOT_PATH (whether the docs page was hit at
  // /api/v1/docs or /test/api/v1/docs).
  function ensureLookups() {
    if (LOOKUPS) return Promise.resolve(LOOKUPS);
    if (lookupsPromise) return lookupsPromise;
    lookupsPromise = fetch("lookups", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : {}; })
      .then(function (d) { LOOKUPS = d || {}; return LOOKUPS; })
      .catch(function () { LOOKUPS = {}; return LOOKUPS; });
    return lookupsPromise;
  }

  // ---- DOM utilities ------------------------------------------------------
  function escHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Strip Swagger-rendered decorations from a name cell:
  //   "fqdn *"            -> "fqdn"
  //   "fqdnstring"        -> "fqdn"      (type squashed onto end)
  //   "fqdn  required"    -> "fqdn"
  // We intentionally only keep the leading [a-z_][a-z0-9_]* run, which
  // matches every field name we issue.
  function extractFieldName(text) {
    if (!text) return null;
    const m = String(text).trim().match(/^([a-z_][a-z0-9_]*)/i);
    return m ? m[1] : null;
  }

  function makeBtn(name) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ngd-help-btn";
    btn.dataset.help = name;
    btn.title = "What is this field?";
    btn.setAttribute("aria-label", "Help for " + name);
    btn.textContent = "?";
    return btn;
  }

  // Walk the rendered DOM and attach a ? button to anything that looks
  // like a field name (parameter cells, schema property cells). Idempotent:
  // a row that already carries our button is skipped.
  function decorate() {
    // Combined selector covering Swagger UI 5.x parameter rows AND the
    // schema property tables rendered inside the request-body / response
    // sections. We deliberately cast a wide net and rely on the field-
    // name regex to filter out anything that isn't a known key.
    const sel = [
      ".parameter__name",
      ".parameters-col_name",
      ".model-box .property",
      ".model-box .prop",
      ".model .property",
      ".model .prop-name",
      ".prop-name",
    ].join(",");
    const nodes = document.querySelectorAll(sel);
    nodes.forEach(function (el) {
      if (el.querySelector(".ngd-help-btn")) return;
      const name = extractFieldName(el.textContent);
      if (!name || !HELP[name]) return;
      el.appendChild(makeBtn(name));
    });
  }

  // ---- Modal --------------------------------------------------------------
  let modal, modalTitle, modalFieldname, modalBody;

  function buildModal() {
    if (modal) return;
    modal = document.createElement("div");
    modal.id = "ngd-help-modal";
    modal.hidden = true;
    modal.innerHTML =
      '<div class="ngd-modal-backdrop" data-close="1"></div>' +
      '<div class="ngd-modal-card" role="dialog" aria-modal="true">' +
        '<button class="ngd-modal-close" data-close="1" aria-label="Close">&times;</button>' +
        '<h3 class="ngd-modal-title"></h3>' +
        '<div class="ngd-modal-fieldname"></div>' +
        '<div class="ngd-modal-body"></div>' +
      '</div>';
    document.body.appendChild(modal);
    modalTitle = modal.querySelector(".ngd-modal-title");
    modalFieldname = modal.querySelector(".ngd-modal-fieldname");
    modalBody = modal.querySelector(".ngd-modal-body");

    modal.addEventListener("click", function (e) {
      if (e.target.dataset.close === "1") closeModal();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !modal.hidden) closeModal();
    });
  }

  function closeModal() {
    if (modal) modal.hidden = true;
  }

  function renderEnum(items) {
    if (!items || !items.length) return "";
    let html =
      '<div class="ngd-help-section-title">Valid values</div>' +
      '<table class="ngd-help-table">' +
        '<thead><tr><th>Value</th><th>Meaning</th></tr></thead><tbody>';
    items.forEach(function (e) {
      html +=
        '<tr><td><code>' + escHtml(e.value) + '</code></td>' +
        '<td>' + escHtml(e.label) + '</td></tr>';
    });
    return html + "</tbody></table>";
  }

  function renderLookup(lookupKey) {
    const items = (LOOKUPS && LOOKUPS[lookupKey]) || [];
    // The "profiles" / "llm_tiers" / "formats" lookups are static enum
    // tables (value+label). The "llm_endpoints" / "user_agents" lookups
    // are live FK tables (id+label).
    const isStatic = items.length > 0 && items[0] && "value" in items[0];
    if (!items.length) {
      return (
        '<div class="ngd-help-empty">' +
        'No <code>' + escHtml(lookupKey) + '</code> are configured yet. ' +
        'Add one in the web UI first.' +
        '</div>'
      );
    }
    if (isStatic) return renderEnum(items);
    let html =
      '<div class="ngd-help-section-title">' +
      'Use the <code>id</code> in this column' +
      '</div>' +
      '<table class="ngd-help-table">' +
        '<thead><tr><th>id</th><th>What it means</th></tr></thead><tbody>';
    items.forEach(function (it) {
      html +=
        '<tr><td><code>' + escHtml(it.id) + '</code></td>' +
        '<td>' + escHtml(it.label) + '</td></tr>';
    });
    return html + "</tbody></table>";
  }

  function renderHelp(name) {
    const help = HELP[name];
    if (!help) return "";
    let html = "";
    if (help.summary) html += '<p>' + escHtml(help.summary) + '</p>';
    if (help.enum) html += renderEnum(help.enum);
    if (help.lookup) html += renderLookup(help.lookup);
    if (help.examples && help.examples.length) {
      html += '<div class="ngd-help-section-title">Examples</div><ul>';
      help.examples.forEach(function (ex) {
        html += '<li><code>' + escHtml(String(ex)) + '</code></li>';
      });
      html += '</ul>';
    }
    if (help.notes && help.notes.length) {
      html += '<div class="ngd-help-section-title">Notes</div>' +
        '<ul class="ngd-help-notes">';
      help.notes.forEach(function (n) {
        html += '<li>' + escHtml(n) + '</li>';
      });
      html += '</ul>';
    }
    return html;
  }

  function openHelp(name) {
    buildModal();
    const help = HELP[name];
    if (!help) return;
    modalTitle.textContent = help.title || name;
    modalFieldname.textContent = name;
    // Render an interim view, then re-render once the lookups have
    // arrived so live FK tables fill in.
    modalBody.innerHTML = renderHelp(name);
    modal.hidden = false;
    if (help.lookup) {
      ensureLookups().then(function () {
        if (modal.hidden) return; // operator already closed it
        modalBody.innerHTML = renderHelp(name);
      });
    }
  }

  // ---- Wiring -------------------------------------------------------------
  // Click delegation: any ? button on the page opens the modal. Using
  // document-level delegation means we don't need to re-bind every time
  // Swagger UI re-renders an operation card.
  document.addEventListener("click", function (e) {
    const t = e.target;
    if (t && t.classList && t.classList.contains("ngd-help-btn")) {
      e.preventDefault();
      e.stopPropagation();
      openHelp(t.dataset.help);
    }
  });

  // Trigger the lookups fetch eagerly so the first help-icon click
  // already has the live FK tables ready to render.
  setTimeout(ensureLookups, 200);

  // Swagger UI rebuilds chunks of its DOM as the operator expands /
  // collapses operations. A MutationObserver catches every change and
  // re-runs decorate() so newly-rendered field names get their ? icon.
  // We also kick off an initial scan once the page is ready.
  function start() {
    decorate();
    const obs = new MutationObserver(function () { decorate(); });
    obs.observe(document.body, { childList: true, subtree: true });
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
