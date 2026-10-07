const escape = (value) =>
  String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
    .replaceAll("{", "&#123;")
    .replaceAll("}", "&#125;");
export function formMarkup(form, jsx = false) {
  const markup = (form.fields || [])
    .map((f) => {
      const attrs = `name="${escape(f.name)}"${f.required ? " required" : ""} maxlength="${f.maxLength}"`;
      const label = escape(f.label);
      if (f.type === "radio")
        return `<fieldset><legend>${label}</legend>${f.options.map((o) => `<label><input type="radio" ${attrs} value="${escape(o.value)}" /> ${escape(o.label)}</label>`).join("")}</fieldset>`;
      if (f.type === "select")
        return `<label>${label}<select ${attrs}><option value="">Choose…</option>${f.options.map((o) => `<option value="${escape(o.value)}">${escape(o.label)}</option>`).join("")}</select></label>`;
      if (f.type === "textarea")
        return `<label>${label}<textarea ${attrs}></textarea></label>`;
      return `<label>${label}<input type="${f.type}" ${attrs}${f.type === "number" ? ' step="any"' : ""} /></label>`;
    })
    .join("\n  ");
  return `${markup}\n  <div hidden><label>Leave empty<input type="text" name="_formto_honeypot" tabIndex="-1" autoComplete="off" /></label></div>`
    .replaceAll("maxlength=", jsx ? "maxLength=" : "maxlength=")
    .replaceAll("tabIndex=", jsx ? "tabIndex=" : "tabindex=")
    .replaceAll("autoComplete=", jsx ? "autoComplete=" : "autocomplete=");
}
export function integrationSnippets(form, baseUrl) {
  const url = `${baseUrl}/f/${form.endpoint}`;
  if (form.submission_mode === "private") {
    const sample = Object.fromEntries(
      (form.fields || []).map((f) => [
        f.name,
        f.type === "checkbox"
          ? true
          : f.type === "number"
            ? 1
            : f.type === "email"
              ? "visitor@example.com"
              : f.type === "url"
                ? "https://example.com"
                : f.type === "date"
                  ? "2026-01-01"
                  : f.options?.[0]?.value || "Example",
      ]),
    );
    // Single quotes inside JSON need shell escaping, including custom choice values.
    const body = JSON.stringify(sample).replaceAll("'", "'\\''");
    return {
      Server: `# Run on your server. Set FORMTO_SUBMISSION_KEY in its secret environment.\n# Never embed this key in browser JavaScript.\ncurl --fail-with-body '${url.replaceAll("'", "'\\''")}' \\\n  -H "Authorization: Bearer $FORMTO_SUBMISSION_KEY" \\\n  -H 'Content-Type: application/json' \\\n  --data '${body}'`,
    };
  }
  const action = form.turnstile_action || `form_${form.id.replaceAll("-", "")}`;
  const widget = `<div class="cf-turnstile" data-sitekey="${escape(form.turnstile_site_key || "")}" data-action="${action}"></div>`;
  const markup = `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>\n<form id="contact-form" action="${escape(url)}" method="POST">\n  ${formMarkup(form)}\n  ${widget}\n  <button type="submit">Send</button>\n  <p role="status" id="form-status"></p>\n</form>`;
  const javascript = `${markup}\n<script>\ndocument.getElementById('contact-form').addEventListener('submit', async function(event) {\n  event.preventDefault();\n  const button = this.querySelector('button');\n  const status = document.getElementById('form-status');\n  button.disabled = true;\n  try {\n    const response = await fetch(this.action, {\n      method: 'POST', headers: { 'Content-Type': 'application/json' },\n      body: JSON.stringify(Object.fromEntries(new FormData(this)))\n    });\n    const result = await response.json();\n    if (!response.ok) throw new Error(result.message || result.error);\n    this.reset(); status.textContent = 'Message sent.';\n  } catch (error) { status.textContent = error.message || 'Please try again.'; }\n  finally { button.disabled = false; window.turnstile?.reset(); }\n});\n</script>`;
  const react = `import { useEffect, useRef, useState } from 'react';

export default function ContactForm() {
  const widget = useRef(null);
  const widgetId = useRef(null);
  const token = useRef('');
  const [status, setStatus] = useState('');
  const [sending, setSending] = useState(false);
  useEffect(() => {
    let stopped = false;
    const render = () => {
      if (stopped || widgetId.current !== null) return;
      widgetId.current = window.turnstile.render(widget.current, {
        sitekey: ${JSON.stringify(form.turnstile_site_key || "")}, action: ${JSON.stringify(action)},
        callback: value => { token.current = value; },
        'expired-callback': () => { token.current = ''; },
        'error-callback': () => { token.current = ''; setStatus('Verification unavailable. Please reload.'); }
      });
    };
    let script = document.querySelector('script[data-formto-turnstile]');
    if (!script) {
      script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      script.dataset.formtoTurnstile = 'true'; script.async = true;
      document.head.appendChild(script);
    }
    if (window.turnstile) render(); else script.addEventListener('load', render);
    return () => {
      stopped = true; script.removeEventListener('load', render);
      if (widgetId.current !== null) window.turnstile?.remove(widgetId.current);
      widgetId.current = null; token.current = '';
    };
  }, []);
  async function submit(event) {
    event.preventDefault();
    if (!token.current) { setStatus('Complete the verification first.'); return; }
    const form = event.currentTarget;
    setSending(true);
    try {
      const data = Object.fromEntries(new FormData(form));
      data['cf-turnstile-response'] = token.current;
      const response = await fetch(${JSON.stringify(url)}, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || result.error);
      form.reset(); setStatus('Message sent.');
    } catch (error) { setStatus(error.message || 'Please try again.'); }
    finally { setSending(false); token.current = ''; window.turnstile?.reset(widgetId.current); }
  }
  return <form onSubmit={submit}>
    ${formMarkup(form, true)}
    <div ref={widget} />
    <button disabled={sending}>Send</button>
    <p role="status">{status}</p>
  </form>;
}`;
  return { HTML: markup, JavaScript: javascript, React: react };
}
