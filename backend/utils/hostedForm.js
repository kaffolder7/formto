import escapeHtml from "escape-html";
import { HONEYPOT, turnstileAction } from "./submissionSecurity.js";

const scriptValue = (value) => JSON.stringify(value).replaceAll("<", "\\u003c");
export function renderHostedForm(form) {
  const legacy = form.submission_mode === "legacy";
  const fields = form.fields
    .map((field) => {
      const name = escapeHtml(field.name);
      const attributes = `id="${name}" name="${name}" ${field.required ? "required" : ""} maxlength="${field.maxLength}"`;
      const label = `<label for="${name}">${escapeHtml(field.label)}${field.required ? " *" : ""}</label>`;
      if (field.type === "radio")
        return `<fieldset><legend>${escapeHtml(field.label)}</legend>${field.options.map((o, i) => `<label><input type="radio" name="${name}" value="${escapeHtml(o.value)}" ${field.required && i === 0 ? "required" : ""}> ${escapeHtml(o.label)}</label>`).join("")}</fieldset>`;
      if (field.type === "select")
        return `${label}<select ${attributes}><option value="">Choose…</option>${field.options.map((o) => `<option value="${escapeHtml(o.value)}">${escapeHtml(o.label)}</option>`).join("")}</select>`;
      if (field.type === "textarea")
        return `${label}<textarea ${attributes} rows="5"></textarea>`;
      return `${label}<input type="${field.type}" ${attributes} ${field.type === "number" ? 'step="any"' : ""}>`;
    })
    .join("\n");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(form.name)}</title><style>
body{font:16px/1.5 system-ui,sans-serif;background:#f8fafc;color:#182230;margin:0;padding:24px}main{max-width:560px;margin:32px auto;padding:24px;background:white;border:1px solid #cbd5e1;border-radius:12px}label{display:block;margin-top:16px}input:not([type=checkbox]):not([type=radio]),textarea,select{box-sizing:border-box;width:100%;padding:10px;font:inherit;border:1px solid #64748b;border-radius:4px}button{padding:12px 20px;font:inherit;margin-top:20px}button:disabled{opacity:.6}.trap{display:none}
</style>${legacy ? "" : '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'}</head>
<body><main><h1>${escapeHtml(form.name)}</h1><form id="formto">${fields}
<div class="trap" aria-hidden="true"><label>Leave this empty<input name="${HONEYPOT}" tabindex="-1" autocomplete="off"></label></div>
${legacy ? "" : `<div class="cf-turnstile" data-sitekey="${escapeHtml(form.turnstile_site_key)}" data-action="${turnstileAction(form)}"></div>`}
<button type="submit">Send</button><p id="status" role="status" aria-live="polite"></p></form></main><script>
document.getElementById('formto').addEventListener('submit', async function(event) {
  event.preventDefault(); const button = this.querySelector('button'); const status = document.getElementById('status');
  button.disabled = true; status.textContent = 'Sending…';
  try {
    const response = await fetch(${scriptValue(`/f/${form.endpoint}`)}, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(Object.fromEntries(new FormData(this)))});
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || result.error || 'Please try again');
    status.textContent = 'Thank you. Your message has been sent.'; this.reset();
    const redirect = ${scriptValue(form.redirect_url || "")}; if (redirect) window.location.assign(redirect);
  } catch(error) { status.textContent = error.message || 'Network error. Please try again.'; }
  finally { button.disabled = false; if (window.turnstile) window.turnstile.reset(); }
});</script></body></html>`;
}
