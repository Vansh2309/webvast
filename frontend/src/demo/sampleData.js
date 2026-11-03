// AUTO-GENERATED demo fixtures captured from a real scan of the bundled
// vulnerable demo target. Used only when the dashboard runs in demo mode
// (no reachable backend).

export const SAMPLE_MODULES = [
  {
    "key": "sqli",
    "name": "SQL Injection",
    "description": "Error-, boolean- and time-based SQL injection detection."
  },
  {
    "key": "xss",
    "name": "Cross-Site Scripting",
    "description": "Reflected and stored XSS via unencoded-reflection canaries."
  },
  {
    "key": "misconfig",
    "name": "Security Misconfiguration",
    "description": "Security headers, cookie flags, exposed files, verbose errors."
  },
  {
    "key": "components",
    "name": "Vulnerable Components",
    "description": "Fingerprints libraries/server and flags known-vulnerable versions."
  }
];

export const SAMPLE_SCAN = {
  "id": "demo00000001",
  "target_url": "http://localhost:5001",
  "modules": [
    "sqli",
    "xss",
    "misconfig",
    "components"
  ],
  "status": "completed",
  "progress": 100,
  "stage": "done",
  "created_at": "2026-11-03T18:41:22+00:00",
  "finished_at": "2026-11-03T18:41:27+00:00",
  "pages_crawled": 5,
  "requests_sent": 41,
  "duration_s": 5.07,
  "severity_counts": {
    "critical": 1,
    "high": 4,
    "medium": 4,
    "low": 2,
    "info": 2
  },
  "error": null,
  "findings": [
    {
      "id": 1,
      "scan_id": "fd15e2db40b4",
      "type": "xss",
      "title": "Stored Cross-Site Scripting",
      "severity": "critical",
      "confidence": "firm",
      "url": "http://localhost:5001/guestbook",
      "parameter": "comment",
      "evidence": "canary '<wv1c3ab778>' submitted via form persisted on http://localhost:5001/guestbook",
      "description": "A value submitted through the 'comment' form field is stored and later rendered unencoded on http://localhost:5001/guestbook, allowing persistent script injection affecting every visitor to that page.",
      "remediation": "Contextually output-encode all user-controlled data (HTML, attribute, JS, URL contexts). Prefer a templating engine with auto-escaping, set a restrictive Content-Security-Policy, and sanitise rich input with a vetted library (e.g. DOMPurify) rather than allowlisting tags by hand.",
      "cwe": "CWE-79",
      "payload": "<wv1c3ab778>"
    },
    {
      "id": 2,
      "scan_id": "fd15e2db40b4",
      "type": "misconfig",
      "title": "Sensitive file exposed: /.env",
      "severity": "high",
      "confidence": "firm",
      "url": "http://localhost:5001/.env",
      "parameter": null,
      "evidence": "/.env returned 200 with matching content",
      "description": "/.env is publicly accessible and may leak secrets or source.",
      "remediation": "Block public access to /.env; move secrets out of the web root.",
      "cwe": "CWE-538",
      "payload": null
    },
    {
      "id": 3,
      "scan_id": "fd15e2db40b4",
      "type": "sqli",
      "title": "SQL Injection (error-based)",
      "severity": "high",
      "confidence": "firm",
      "url": "http://localhost:5001/search",
      "parameter": "q",
      "evidence": "</a></nav> <hr><pre>sqlite3.OperationalError: unrecognized token: \"'\"</pre></body></html>",
      "description": "Injecting \"'\" into the 'q' parameter (GET) produced a database error message, indicating the input reaches a SQL query unsanitised.",
      "remediation": "Use parameterised queries / prepared statements for all database access. Never build SQL by string concatenation with user input. Apply least-privilege database accounts and validate/allowlist input where a fixed set of values is expected.",
      "cwe": "CWE-89",
      "payload": "'"
    },
    {
      "id": 4,
      "scan_id": "fd15e2db40b4",
      "type": "xss",
      "title": "Reflected Cross-Site Scripting",
      "severity": "high",
      "confidence": "firm",
      "url": "http://localhost:5001/greet",
      "parameter": "name",
      "evidence": "canary '<wv13043519>' reflected unencoded in response",
      "description": "Input to the 'name' parameter (GET) is reflected into the response without HTML encoding, so an attacker-supplied script tag would execute in a victim's browser.",
      "remediation": "Contextually output-encode all user-controlled data (HTML, attribute, JS, URL contexts). Prefer a templating engine with auto-escaping, set a restrictive Content-Security-Policy, and sanitise rich input with a vetted library (e.g. DOMPurify) rather than allowlisting tags by hand.",
      "cwe": "CWE-79",
      "payload": "\"'><wv13043519>"
    },
    {
      "id": 5,
      "scan_id": "fd15e2db40b4",
      "type": "xss",
      "title": "Reflected Cross-Site Scripting",
      "severity": "high",
      "confidence": "firm",
      "url": "http://localhost:5001/guestbook",
      "parameter": "comment",
      "evidence": "canary '<wvd40962c1>' reflected unencoded in response",
      "description": "Input to the 'comment' parameter (POST) is reflected into the response without HTML encoding, so an attacker-supplied script tag would execute in a victim's browser.",
      "remediation": "Contextually output-encode all user-controlled data (HTML, attribute, JS, URL contexts). Prefer a templating engine with auto-escaping, set a restrictive Content-Security-Policy, and sanitise rich input with a vetted library (e.g. DOMPurify) rather than allowlisting tags by hand.",
      "cwe": "CWE-79",
      "payload": "\"'><wvd40962c1>"
    },
    {
      "id": 6,
      "scan_id": "fd15e2db40b4",
      "type": "components",
      "title": "Outdated jQuery 3.4.1 (CVE-2020-11022)",
      "severity": "medium",
      "confidence": "firm",
      "url": "http://localhost:5001",
      "parameter": null,
      "evidence": "detected jQuery 3.4.1 via /static/jquery-3.4.1.min.js; fixed in 3.5.0",
      "description": "jQuery 3.4.1 is in use. Potential XSS via jQuery.htmlPrefilter when passing HTML from untrusted sources. Fixed in jQuery 3.5.0.",
      "remediation": "Upgrade jQuery to 3.5.0 or later and establish a process (e.g. Dependabot / npm audit) to track component advisories.",
      "cwe": "CWE-1035",
      "payload": null
    },
    {
      "id": 7,
      "scan_id": "fd15e2db40b4",
      "type": "components",
      "title": "Outdated Bootstrap 3.3.7 (CVE-2019-8331)",
      "severity": "medium",
      "confidence": "firm",
      "url": "http://localhost:5001",
      "parameter": null,
      "evidence": "detected Bootstrap 3.3.7 via /static/bootstrap-3.3.7.min.css; fixed in 3.4.1",
      "description": "Bootstrap 3.3.7 is in use. XSS in the tooltip/popover data-template attribute. Fixed in Bootstrap 3.4.1.",
      "remediation": "Upgrade Bootstrap to 3.4.1 or later and establish a process (e.g. Dependabot / npm audit) to track component advisories.",
      "cwe": "CWE-1035",
      "payload": null
    },
    {
      "id": 8,
      "scan_id": "fd15e2db40b4",
      "type": "misconfig",
      "title": "Missing security header: content-security-policy",
      "severity": "medium",
      "confidence": "certain",
      "url": "http://localhost:5001",
      "parameter": null,
      "evidence": "response has no 'content-security-policy' header",
      "description": "No Content-Security-Policy, so the browser has no restriction on script/resource origins.",
      "remediation": "Add a restrictive Content-Security-Policy (e.g. default-src 'self').",
      "cwe": "CWE-693",
      "payload": null
    },
    {
      "id": 9,
      "scan_id": "fd15e2db40b4",
      "type": "misconfig",
      "title": "Insecure cookie attributes",
      "severity": "medium",
      "confidence": "firm",
      "url": "http://localhost:5001",
      "parameter": null,
      "evidence": "Set-Cookie missing: HttpOnly, SameSite",
      "description": "A cookie is set without: HttpOnly, SameSite.",
      "remediation": "Set cookies with HttpOnly (block JS access), Secure (HTTPS only) and an explicit SameSite attribute (Lax or Strict) to reduce XSS token theft and CSRF.",
      "cwe": "CWE-614",
      "payload": null
    },
    {
      "id": 10,
      "scan_id": "fd15e2db40b4",
      "type": "misconfig",
      "title": "Missing security header: x-frame-options",
      "severity": "low",
      "confidence": "certain",
      "url": "http://localhost:5001",
      "parameter": null,
      "evidence": "response has no 'x-frame-options' header",
      "description": "No X-Frame-Options / frame-ancestors, exposing the app to clickjacking.",
      "remediation": "Set X-Frame-Options: DENY or a CSP frame-ancestors directive.",
      "cwe": "CWE-693",
      "payload": null
    },
    {
      "id": 11,
      "scan_id": "fd15e2db40b4",
      "type": "misconfig",
      "title": "Missing security header: x-content-type-options",
      "severity": "low",
      "confidence": "certain",
      "url": "http://localhost:5001",
      "parameter": null,
      "evidence": "response has no 'x-content-type-options' header",
      "description": "No X-Content-Type-Options, allowing MIME-type sniffing.",
      "remediation": "Set X-Content-Type-Options: nosniff.",
      "cwe": "CWE-693",
      "payload": null
    },
    {
      "id": 12,
      "scan_id": "fd15e2db40b4",
      "type": "misconfig",
      "title": "Missing security header: referrer-policy",
      "severity": "info",
      "confidence": "certain",
      "url": "http://localhost:5001",
      "parameter": null,
      "evidence": "response has no 'referrer-policy' header",
      "description": "No Referrer-Policy; full URLs may leak to third parties.",
      "remediation": "Set Referrer-Policy: strict-origin-when-cross-origin or stricter.",
      "cwe": "CWE-693",
      "payload": null
    },
    {
      "id": 13,
      "scan_id": "fd15e2db40b4",
      "type": "misconfig",
      "title": "Version disclosure via 'server'",
      "severity": "info",
      "confidence": "certain",
      "url": "http://localhost:5001",
      "parameter": null,
      "evidence": "server: Werkzeug/3.1.9 Python/3.9.6",
      "description": "The 'server' header reveals software and version (Werkzeug/3.1.9 Python/3.9.6), aiding attackers.",
      "remediation": "Suppress or genericise the 'server' header in your server/framework config.",
      "cwe": "CWE-200",
      "payload": null
    }
  ]
};

export const SAMPLE_REPORT_HTML = "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<title>WebVAST Report - http://localhost:5001</title>\n<style>\n  body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;\n       margin:0;color:#111827;background:#f9fafb}\n  .wrap{max-width:960px;margin:0 auto;padding:32px}\n  h1{font-size:22px;margin:0 0 4px} .sub{color:#6b7280;margin-bottom:24px}\n  .cards{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0 28px}\n  .card{flex:1;min-width:110px;border-radius:10px;padding:14px;color:#fff;text-align:center}\n  .card .n{font-size:26px;font-weight:700} .card .l{font-size:12px;text-transform:uppercase;opacity:.9}\n  .meta{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin-bottom:24px;font-size:14px}\n  .meta div{margin:2px 0}\n  .finding{background:#fff;border:1px solid #e5e7eb;border-left-width:5px;border-radius:8px;\n           padding:16px;margin-bottom:14px}\n  .badge{display:inline-block;color:#fff;font-size:11px;font-weight:700;padding:2px 8px;\n         border-radius:999px;text-transform:uppercase;letter-spacing:.03em}\n  .ftitle{font-size:16px;font-weight:600;margin:8px 0 6px}\n  .kv{font-size:13px;color:#374151;margin:4px 0}\n  .kv b{color:#111827} code{background:#f3f4f6;padding:1px 5px;border-radius:4px;\n       font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}\n  .rem{background:#ecfdf5;border:1px solid #a7f3d0;border-radius:6px;padding:8px 10px;\n       font-size:13px;margin-top:8px}\n  footer{color:#9ca3af;font-size:12px;text-align:center;margin-top:28px}\n  @media print{body{background:#fff}.card{-webkit-print-color-adjust:exact;print-color-adjust:exact}}\n</style></head><body><div class=\"wrap\">\n  <h1>Web Application Vulnerability Report</h1>\n  <div class=\"sub\">Target: http://localhost:5001 &middot; Generated by WebVAST</div>\n\n  <div class=\"cards\">\n  \n    <div class=\"card\" style=\"background:#7f1d1d\">\n      <div class=\"n\">1</div>\n      <div class=\"l\">critical</div>\n    </div>\n  \n    <div class=\"card\" style=\"background:#b91c1c\">\n      <div class=\"n\">4</div>\n      <div class=\"l\">high</div>\n    </div>\n  \n    <div class=\"card\" style=\"background:#c2410c\">\n      <div class=\"n\">4</div>\n      <div class=\"l\">medium</div>\n    </div>\n  \n    <div class=\"card\" style=\"background:#a16207\">\n      <div class=\"n\">2</div>\n      <div class=\"l\">low</div>\n    </div>\n  \n    <div class=\"card\" style=\"background:#1d4ed8\">\n      <div class=\"n\">2</div>\n      <div class=\"l\">info</div>\n    </div>\n  \n  </div>\n\n  <div class=\"meta\">\n    <div><b>Status:</b> completed</div>\n    <div><b>Scanned:</b> 2026-11-03T18:41:22+00:00 &rarr; 2026-11-03T18:41:27+00:00</div>\n    <div><b>Modules:</b> sqli, xss, misconfig, components</div>\n    <div><b>Pages crawled:</b> 5 &middot;\n         <b>Requests sent:</b> 41 &middot;\n         <b>Duration:</b> 5.07s</div>\n    \n  </div>\n\n  <h2>Findings (13)</h2>\n  \n  \n    <div class=\"finding\" style=\"border-left-color:#7f1d1d\">\n      <span class=\"badge\" style=\"background:#7f1d1d\">critical</span>\n      <span class=\"badge\" style=\"background:#6b7280\">firm</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-79</span>\n      <div class=\"ftitle\">Stored Cross-Site Scripting</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001/guestbook</code></div>\n      <div class=\"kv\"><b>Parameter:</b> <code>comment</code></div>\n      <div class=\"kv\"><b>Payload:</b> <code>&lt;wv1c3ab778&gt;</code></div>\n      <div class=\"kv\">A value submitted through the &#39;comment&#39; form field is stored and later rendered unencoded on http://localhost:5001/guestbook, allowing persistent script injection affecting every visitor to that page.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>canary &#39;&lt;wv1c3ab778&gt;&#39; submitted via form persisted on http://localhost:5001/guestbook</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Contextually output-encode all user-controlled data (HTML, attribute, JS, URL contexts). Prefer a templating engine with auto-escaping, set a restrictive Content-Security-Policy, and sanitise rich input with a vetted library (e.g. DOMPurify) rather than allowlisting tags by hand.</div>\n    </div>\n  \n    <div class=\"finding\" style=\"border-left-color:#b91c1c\">\n      <span class=\"badge\" style=\"background:#b91c1c\">high</span>\n      <span class=\"badge\" style=\"background:#6b7280\">firm</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-538</span>\n      <div class=\"ftitle\">Sensitive file exposed: /.env</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001/.env</code></div>\n      \n      \n      <div class=\"kv\">/.env is publicly accessible and may leak secrets or source.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>/.env returned 200 with matching content</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Block public access to /.env; move secrets out of the web root.</div>\n    </div>\n  \n    <div class=\"finding\" style=\"border-left-color:#b91c1c\">\n      <span class=\"badge\" style=\"background:#b91c1c\">high</span>\n      <span class=\"badge\" style=\"background:#6b7280\">firm</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-89</span>\n      <div class=\"ftitle\">SQL Injection (error-based)</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001/search</code></div>\n      <div class=\"kv\"><b>Parameter:</b> <code>q</code></div>\n      <div class=\"kv\"><b>Payload:</b> <code>&#39;</code></div>\n      <div class=\"kv\">Injecting &#34;&#39;&#34; into the &#39;q&#39; parameter (GET) produced a database error message, indicating the input reaches a SQL query unsanitised.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>&lt;/a&gt;&lt;/nav&gt; &lt;hr&gt;&lt;pre&gt;sqlite3.OperationalError: unrecognized token: &#34;&#39;&#34;&lt;/pre&gt;&lt;/body&gt;&lt;/html&gt;</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Use parameterised queries / prepared statements for all database access. Never build SQL by string concatenation with user input. Apply least-privilege database accounts and validate/allowlist input where a fixed set of values is expected.</div>\n    </div>\n  \n    <div class=\"finding\" style=\"border-left-color:#b91c1c\">\n      <span class=\"badge\" style=\"background:#b91c1c\">high</span>\n      <span class=\"badge\" style=\"background:#6b7280\">firm</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-79</span>\n      <div class=\"ftitle\">Reflected Cross-Site Scripting</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001/greet</code></div>\n      <div class=\"kv\"><b>Parameter:</b> <code>name</code></div>\n      <div class=\"kv\"><b>Payload:</b> <code>&#34;&#39;&gt;&lt;wv13043519&gt;</code></div>\n      <div class=\"kv\">Input to the &#39;name&#39; parameter (GET) is reflected into the response without HTML encoding, so an attacker-supplied script tag would execute in a victim&#39;s browser.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>canary &#39;&lt;wv13043519&gt;&#39; reflected unencoded in response</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Contextually output-encode all user-controlled data (HTML, attribute, JS, URL contexts). Prefer a templating engine with auto-escaping, set a restrictive Content-Security-Policy, and sanitise rich input with a vetted library (e.g. DOMPurify) rather than allowlisting tags by hand.</div>\n    </div>\n  \n    <div class=\"finding\" style=\"border-left-color:#b91c1c\">\n      <span class=\"badge\" style=\"background:#b91c1c\">high</span>\n      <span class=\"badge\" style=\"background:#6b7280\">firm</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-79</span>\n      <div class=\"ftitle\">Reflected Cross-Site Scripting</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001/guestbook</code></div>\n      <div class=\"kv\"><b>Parameter:</b> <code>comment</code></div>\n      <div class=\"kv\"><b>Payload:</b> <code>&#34;&#39;&gt;&lt;wvd40962c1&gt;</code></div>\n      <div class=\"kv\">Input to the &#39;comment&#39; parameter (POST) is reflected into the response without HTML encoding, so an attacker-supplied script tag would execute in a victim&#39;s browser.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>canary &#39;&lt;wvd40962c1&gt;&#39; reflected unencoded in response</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Contextually output-encode all user-controlled data (HTML, attribute, JS, URL contexts). Prefer a templating engine with auto-escaping, set a restrictive Content-Security-Policy, and sanitise rich input with a vetted library (e.g. DOMPurify) rather than allowlisting tags by hand.</div>\n    </div>\n  \n    <div class=\"finding\" style=\"border-left-color:#c2410c\">\n      <span class=\"badge\" style=\"background:#c2410c\">medium</span>\n      <span class=\"badge\" style=\"background:#6b7280\">firm</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-1035</span>\n      <div class=\"ftitle\">Outdated jQuery 3.4.1 (CVE-2020-11022)</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001</code></div>\n      \n      \n      <div class=\"kv\">jQuery 3.4.1 is in use. Potential XSS via jQuery.htmlPrefilter when passing HTML from untrusted sources. Fixed in jQuery 3.5.0.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>detected jQuery 3.4.1 via /static/jquery-3.4.1.min.js; fixed in 3.5.0</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Upgrade jQuery to 3.5.0 or later and establish a process (e.g. Dependabot / npm audit) to track component advisories.</div>\n    </div>\n  \n    <div class=\"finding\" style=\"border-left-color:#c2410c\">\n      <span class=\"badge\" style=\"background:#c2410c\">medium</span>\n      <span class=\"badge\" style=\"background:#6b7280\">firm</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-1035</span>\n      <div class=\"ftitle\">Outdated Bootstrap 3.3.7 (CVE-2019-8331)</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001</code></div>\n      \n      \n      <div class=\"kv\">Bootstrap 3.3.7 is in use. XSS in the tooltip/popover data-template attribute. Fixed in Bootstrap 3.4.1.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>detected Bootstrap 3.3.7 via /static/bootstrap-3.3.7.min.css; fixed in 3.4.1</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Upgrade Bootstrap to 3.4.1 or later and establish a process (e.g. Dependabot / npm audit) to track component advisories.</div>\n    </div>\n  \n    <div class=\"finding\" style=\"border-left-color:#c2410c\">\n      <span class=\"badge\" style=\"background:#c2410c\">medium</span>\n      <span class=\"badge\" style=\"background:#6b7280\">certain</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-693</span>\n      <div class=\"ftitle\">Missing security header: content-security-policy</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001</code></div>\n      \n      \n      <div class=\"kv\">No Content-Security-Policy, so the browser has no restriction on script/resource origins.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>response has no &#39;content-security-policy&#39; header</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Add a restrictive Content-Security-Policy (e.g. default-src &#39;self&#39;).</div>\n    </div>\n  \n    <div class=\"finding\" style=\"border-left-color:#c2410c\">\n      <span class=\"badge\" style=\"background:#c2410c\">medium</span>\n      <span class=\"badge\" style=\"background:#6b7280\">firm</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-614</span>\n      <div class=\"ftitle\">Insecure cookie attributes</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001</code></div>\n      \n      \n      <div class=\"kv\">A cookie is set without: HttpOnly, SameSite.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>Set-Cookie missing: HttpOnly, SameSite</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Set cookies with HttpOnly (block JS access), Secure (HTTPS only) and an explicit SameSite attribute (Lax or Strict) to reduce XSS token theft and CSRF.</div>\n    </div>\n  \n    <div class=\"finding\" style=\"border-left-color:#a16207\">\n      <span class=\"badge\" style=\"background:#a16207\">low</span>\n      <span class=\"badge\" style=\"background:#6b7280\">certain</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-693</span>\n      <div class=\"ftitle\">Missing security header: x-frame-options</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001</code></div>\n      \n      \n      <div class=\"kv\">No X-Frame-Options / frame-ancestors, exposing the app to clickjacking.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>response has no &#39;x-frame-options&#39; header</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Set X-Frame-Options: DENY or a CSP frame-ancestors directive.</div>\n    </div>\n  \n    <div class=\"finding\" style=\"border-left-color:#a16207\">\n      <span class=\"badge\" style=\"background:#a16207\">low</span>\n      <span class=\"badge\" style=\"background:#6b7280\">certain</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-693</span>\n      <div class=\"ftitle\">Missing security header: x-content-type-options</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001</code></div>\n      \n      \n      <div class=\"kv\">No X-Content-Type-Options, allowing MIME-type sniffing.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>response has no &#39;x-content-type-options&#39; header</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Set X-Content-Type-Options: nosniff.</div>\n    </div>\n  \n    <div class=\"finding\" style=\"border-left-color:#1d4ed8\">\n      <span class=\"badge\" style=\"background:#1d4ed8\">info</span>\n      <span class=\"badge\" style=\"background:#6b7280\">certain</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-693</span>\n      <div class=\"ftitle\">Missing security header: referrer-policy</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001</code></div>\n      \n      \n      <div class=\"kv\">No Referrer-Policy; full URLs may leak to third parties.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>response has no &#39;referrer-policy&#39; header</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Set Referrer-Policy: strict-origin-when-cross-origin or stricter.</div>\n    </div>\n  \n    <div class=\"finding\" style=\"border-left-color:#1d4ed8\">\n      <span class=\"badge\" style=\"background:#1d4ed8\">info</span>\n      <span class=\"badge\" style=\"background:#6b7280\">certain</span>\n      <span class=\"badge\" style=\"background:#374151\">CWE-200</span>\n      <div class=\"ftitle\">Version disclosure via &#39;server&#39;</div>\n      <div class=\"kv\"><b>URL:</b> <code>http://localhost:5001</code></div>\n      \n      \n      <div class=\"kv\">The &#39;server&#39; header reveals software and version (Werkzeug/3.1.9 Python/3.9.6), aiding attackers.</div>\n      <div class=\"kv\"><b>Evidence:</b> <code>server: Werkzeug/3.1.9 Python/3.9.6</code></div>\n      <div class=\"rem\"><b>Remediation:</b> Suppress or genericise the &#39;server&#39; header in your server/framework config.</div>\n    </div>\n  \n\n  <footer>WebVAST &middot; For use only against systems you own or are authorized to test.</footer>\n</div></body></html>";
