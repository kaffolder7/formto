import { useState } from "react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import api from "@/lib/api";

const control =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring";
export default function FormSecuritySettings({
  form,
  value,
  onChange,
  onKeyChange,
  disabled,
}) {
  const [key, setKey] = useState("");
  const [keyError, setKeyError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState("");
  const set = (name, next) => onChange({ ...value, [name]: next });
  const field = (index, name, next) =>
    set(
      "fields",
      value.fields.map((f, i) => (i === index ? { ...f, [name]: next } : f)),
    );
  async function manageKey(action) {
    setBusy(true);
    setKeyError("");
    setKey("");
    try {
      if (action === "revoke") {
        await api.delete(`/api/forms/${form.id}/submission-key`);
        onKeyChange({
          submission_key_configured: false,
          submission_key_prefix: null,
          active: false,
          security_issue: "Generate a submission key",
        });
      } else {
        const { data } = await api.post(`/api/forms/${form.id}/submission-key`);
        setKey(data.token);
        onKeyChange({
          submission_key_configured: true,
          submission_key_prefix: data.submission_key_prefix,
          security_issue: null,
        });
      }
      setConfirm("");
    } catch (error) {
      setKeyError(
        error.response?.data?.message ||
          error.response?.data?.error ||
          "Key could not be changed. Try again.",
      );
    } finally {
      setBusy(false);
    }
  }
  if (value.submission_mode === "legacy")
    return (
      <Card className="border-amber-500">
        <CardHeader>
          <CardTitle>Legacy security — upgrade recommended</CardTitle>
          <CardDescription>
            Your existing integration continues to work. This form accepts
            anonymous submissions without origin restrictions, Turnstile, field
            rules, or daily quotas.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm">
            Upgrading is permanent. Saving the upgrade pauses submissions until
            you configure security, update your integration, and activate the
            form. Existing submissions are preserved.
          </p>
          <Button
            type="button"
            disabled={disabled}
            onClick={() =>
              onChange({
                ...value,
                submission_mode: "public",
                upgrade_security: true,
                active: false,
                hosted_enabled: false,
              })
            }
          >
            Set up security upgrade
          </Button>
        </CardContent>
      </Card>
    );
  return (
    <>
      {value.upgrade_security && (
        <p
          role="status"
          className="rounded-md border border-amber-500 p-4 text-sm"
        >
          Saving these changes permanently upgrades this form and pauses
          submissions. Finish setup and update your integration before
          activating it. Cancel to keep legacy behavior.
        </p>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Submission security</CardTitle>
          <CardDescription>
            {form.security_issue
              ? `Setup required: ${form.security_issue}.`
              : "Security is configured. Activate the form when your integration is ready."}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <fieldset disabled={disabled || busy} className="space-y-4">
            <legend className="text-sm font-medium mb-2">
              Who submits to this form?
            </legend>
            <label className="flex gap-3 items-start">
              <input
                type="radio"
                name="submission-mode"
                value="public"
                checked={value.submission_mode === "public"}
                onChange={() => {
                  set("submission_mode", "public");
                  setKey("");
                  setConfirm("");
                }}
                className="mt-1"
              />
              <span>
                <span className="block text-sm font-medium">
                  Public website
                </span>
                <span className="text-sm text-muted-foreground">
                  Visitors submit from allowed websites and complete Turnstile
                  verification.
                </span>
              </span>
            </label>
            <label className="flex gap-3 items-start">
              <input
                type="radio"
                name="submission-mode"
                value="private"
                checked={value.submission_mode === "private"}
                onChange={() => {
                  onChange({
                    ...value,
                    submission_mode: "private",
                    hosted_enabled: false,
                  });
                  setKey("");
                  setConfirm("");
                }}
                className="mt-1"
              />
              <span>
                <span className="block text-sm font-medium">
                  Private server integration
                </span>
                <span className="text-sm text-muted-foreground">
                  Your server submits with a private key. Never put this key in
                  a browser.
                </span>
              </span>
            </label>
          </fieldset>
          {value.submission_mode === "public" ? (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="allowed-origins">Allowed websites</Label>
                <textarea
                  id="allowed-origins"
                  className={control}
                  rows={3}
                  placeholder="https://example.com"
                  value={value.allowed_origins.join("\n")}
                  onChange={(e) =>
                    set("allowed_origins", e.target.value.split("\n"))
                  }
                  disabled={disabled}
                  aria-describedby="origins-help"
                />
                <p id="origins-help" className="text-sm text-muted-foreground">
                  One HTTPS origin per line, including any port. Paths and
                  wildcards are not allowed. This check works alongside
                  Turnstile.
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="turnstile-site-key">Turnstile site key</Label>
                <Input
                  id="turnstile-site-key"
                  value={value.turnstile_site_key}
                  onChange={(e) => set("turnstile_site_key", e.target.value)}
                  disabled={disabled}
                  autoComplete="off"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="turnstile-secret">Turnstile secret</Label>
                <Input
                  id="turnstile-secret"
                  type="password"
                  value={value.turnstile_secret || ""}
                  onChange={(e) => set("turnstile_secret", e.target.value)}
                  disabled={disabled}
                  autoComplete="new-password"
                  placeholder={
                    form.turnstile_secret_configured
                      ? "Leave blank to keep saved secret"
                      : "Enter the secret from Cloudflare"
                  }
                />
                <p className="text-sm text-muted-foreground">
                  {form.turnstile_secret_configured
                    ? "A secret is saved and will not be displayed."
                    : "Create a Turnstile widget in Cloudflare and register each allowed hostname."}
                </p>
              </div>
              <label className="flex items-start gap-3 text-sm">
                <input
                  type="checkbox"
                  checked={value.hosted_enabled}
                  onChange={(e) => set("hosted_enabled", e.target.checked)}
                  disabled={disabled}
                  className="mt-1"
                />
                <span>
                  Enable the FormTo-hosted page. Saving adds this instance’s
                  origin to the allowed websites. Include its hostname in your
                  Turnstile widget.
                </span>
              </label>
            </div>
          ) : (
            <div className="space-y-3">
              {form.submission_mode !== "private" ? (
                <p className="text-sm text-muted-foreground">
                  Save this mode first, then return here to generate a key.
                  Changing modes revokes any existing key.
                </p>
              ) : (
                <>
                  <p className="text-sm">
                    {form.submission_key_configured
                      ? `Saved key: ${form.submission_key_prefix}…`
                      : "No submission key is configured."}
                  </p>
                  {confirm ? (
                    <div className="space-y-2">
                      <p className="text-sm" role="alert">
                        {confirm === "revoke"
                          ? "Revoking the key also deactivates this form."
                          : "Rotating the key immediately invalidates the current key. Update your server before resuming submissions."}
                      </p>
                      <div className="flex gap-2">
                        <Button
                          type="button"
                          variant="destructive"
                          disabled={busy || disabled}
                          onClick={() => manageKey(confirm)}
                        >
                          {busy
                            ? "Updating…"
                            : confirm === "revoke"
                              ? "Revoke key now"
                              : "Rotate key now"}
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          disabled={busy}
                          onClick={() => setConfirm("")}
                        >
                          Cancel
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      <Button
                        type="button"
                        variant="outline"
                        disabled={busy || disabled}
                        onClick={() =>
                          form.submission_key_configured
                            ? setConfirm("rotate")
                            : manageKey("generate")
                        }
                      >
                        {busy
                          ? "Generating…"
                          : form.submission_key_configured
                            ? "Rotate key"
                            : "Generate key"}
                      </Button>
                      {form.submission_key_configured && (
                        <Button
                          type="button"
                          variant="outline"
                          disabled={busy || disabled}
                          onClick={() => setConfirm("revoke")}
                        >
                          Revoke key
                        </Button>
                      )}
                    </div>
                  )}
                  {key && (
                    <div className="space-y-2">
                      <Label htmlFor="new-submission-key">
                        Copy this key now. It is shown only once.
                      </Label>
                      <Input
                        id="new-submission-key"
                        readOnly
                        value={key}
                        onFocus={(e) => e.target.select()}
                      />
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => setKey("")}
                      >
                        Hide key
                      </Button>
                    </div>
                  )}
                  {keyError && (
                    <p role="alert" className="text-sm text-destructive">
                      {keyError}
                    </p>
                  )}
                </>
              )}
            </div>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Daily limits</CardTitle>
          <CardDescription>
            Limits reset at midnight UTC. Redeploying or deleting submissions
            does not reset usage.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="submission-quota">Accepted submissions</Label>
              <Input
                id="submission-quota"
                type="number"
                min="1"
                max="1000000"
                value={value.daily_submission_limit}
                onChange={(e) => set("daily_submission_limit", e.target.value)}
                disabled={disabled}
              />
              <p className="text-sm text-muted-foreground">
                {form.usage_today?.submissions || 0} accepted today
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="notification-quota">Notification events</Label>
              <Input
                id="notification-quota"
                type="number"
                min="0"
                max="1000000"
                value={value.daily_notification_limit}
                onChange={(e) =>
                  set("daily_notification_limit", e.target.value)
                }
                disabled={disabled}
              />
              <p className="text-sm text-muted-foreground">
                {form.usage_today?.notifications || 0} reserved today
              </p>
            </div>
          </div>
          <p className="text-sm text-muted-foreground">
            After the notification limit, submissions are still saved up to the
            submission limit. An event includes all configured delivery
            channels. Failed deliveries count toward the limit.
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Allowed fields</CardTitle>
          <CardDescription>
            Only these fields are accepted. Rules are checked on the server.
            File uploads are unavailable.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {value.fields.map((f, i) => (
            <fieldset
              key={i}
              className="space-y-3 border-t pt-4"
              disabled={disabled}
            >
              <legend className="text-sm font-medium px-1">
                {f.label || `Field ${i + 1}`}
              </legend>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <Label htmlFor={`field-name-${i}`}>Field name</Label>
                  <Input
                    id={`field-name-${i}`}
                    value={f.name}
                    onChange={(e) => field(i, "name", e.target.value)}
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor={`field-label-${i}`}>Label</Label>
                  <Input
                    id={`field-label-${i}`}
                    value={f.label}
                    onChange={(e) => field(i, "label", e.target.value)}
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor={`field-type-${i}`}>Type</Label>
                  <select
                    id={`field-type-${i}`}
                    className={control}
                    value={f.type}
                    onChange={(e) => field(i, "type", e.target.value)}
                  >
                    {[
                      "text",
                      "textarea",
                      "email",
                      "tel",
                      "number",
                      "checkbox",
                      "select",
                      "radio",
                      "date",
                      "url",
                    ].map((type) => (
                      <option key={type}>{type}</option>
                    ))}
                  </select>
                </div>
                <div className="space-y-1">
                  <Label htmlFor={`field-length-${i}`}>Maximum length</Label>
                  <Input
                    id={`field-length-${i}`}
                    type="number"
                    min="1"
                    max="10000"
                    value={f.maxLength}
                    onChange={(e) =>
                      field(i, "maxLength", Number(e.target.value))
                    }
                  />
                </div>
              </div>
              {["select", "radio"].includes(f.type) && (
                <div className="space-y-1">
                  <Label htmlFor={`field-options-${i}`}>
                    Choices, one per line
                  </Label>
                  <textarea
                    id={`field-options-${i}`}
                    className={control}
                    rows={3}
                    value={(f.options || [])
                      .map((o) => (typeof o === "string" ? o : o.value))
                      .join("\n")}
                    onChange={(e) =>
                      field(i, "options", e.target.value.split("\n"))
                    }
                  />
                </div>
              )}
              <div className="flex justify-between items-center">
                <label className="flex gap-2 items-center text-sm">
                  <input
                    type="checkbox"
                    checked={f.required}
                    onChange={(e) => field(i, "required", e.target.checked)}
                  />
                  Required
                </label>
                <Button
                  type="button"
                  variant="ghost"
                  disabled={value.fields.length <= 1 || disabled}
                  onClick={() =>
                    set(
                      "fields",
                      value.fields.filter((_, n) => n !== i),
                    )
                  }
                >
                  Remove field
                </Button>
              </div>
            </fieldset>
          ))}
          <Button
            type="button"
            variant="outline"
            disabled={disabled || value.fields.length >= 50}
            onClick={() =>
              set("fields", [
                ...value.fields,
                {
                  name: "",
                  label: "",
                  type: "text",
                  required: false,
                  maxLength: 500,
                },
              ])
            }
          >
            Add field
          </Button>
        </CardContent>
      </Card>
    </>
  );
}
