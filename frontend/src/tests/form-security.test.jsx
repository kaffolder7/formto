// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import FormSecuritySettings from "../components/FormSecuritySettings";
import { formMarkup, integrationSnippets } from "../lib/formSnippets";
import api from "../lib/api";
vi.mock("../lib/api", () => ({ default: { post: vi.fn(), delete: vi.fn() } }));
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
const form = {
  id: "1234",
  endpoint: "contact",
  submission_mode: "public",
  allowed_origins: ["https://example.com"],
  hosted_enabled: false,
  turnstile_site_key: "site-key",
  turnstile_secret: "",
  daily_submission_limit: 500,
  daily_notification_limit: 100,
  fields: [
    {
      name: "email",
      label: "Email",
      type: "email",
      required: true,
      maxLength: 254,
    },
  ],
};
function Settings({ initial = form }) {
  const [saved, setSaved] = useState(initial);
  const [value, setValue] = useState(initial);
  return (
    <FormSecuritySettings
      form={saved}
      value={value}
      onChange={setValue}
      onKeyChange={(changes) => setSaved((s) => ({ ...s, ...changes }))}
    />
  );
}
describe("security settings", () => {
  it("keeps legacy forms unchanged until the owner starts an explicit upgrade", () => {
    render(
      <Settings
        initial={{ ...form, submission_mode: "legacy", active: true }}
      />,
    );
    expect(screen.getByText(/Legacy security/)).toBeTruthy();
    expect(screen.queryByLabelText("Allowed websites")).toBeNull();
    expect(api.post).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole("button", { name: "Set up security upgrade" }),
    );
    expect(screen.getByRole("status").textContent).toContain(
      "permanently upgrades",
    );
    expect(screen.getByLabelText("Allowed websites")).toBeTruthy();
  });
  it("offers labeled public settings and updates mode-specific controls", () => {
    render(<Settings />);
    expect(screen.getByLabelText("Allowed websites").value).toBe(
      "https://example.com",
    );
    expect(screen.getByLabelText("Accepted submissions").value).toBe("500");
    fireEvent.click(
      screen.getByRole("radio", { name: /Private server integration/ }),
    );
    expect(screen.queryByLabelText("Turnstile secret")).toBeNull();
    expect(screen.getByText(/Save this mode first/)).toBeTruthy();
  });
  it("shows saved secret presence without placing it in an input", () => {
    render(
      <Settings initial={{ ...form, turnstile_secret_configured: true }} />,
    );
    expect(screen.getByLabelText("Turnstile secret").value).toBe("");
    expect(
      screen.getByPlaceholderText("Leave blank to keep saved secret"),
    ).toBeTruthy();
  });
  it("generates a key once and requires confirmation before rotating", async () => {
    api.post.mockResolvedValue({
      data: { token: "one-time-test-key", submission_key_prefix: "prefix" },
    });
    render(<Settings initial={{ ...form, submission_mode: "private" }} />);
    fireEvent.click(screen.getByRole("button", { name: "Generate key" }));
    expect(
      (
        await screen.findByLabelText(
          "Copy this key now. It is shown only once.",
        )
      ).value,
    ).toBe("one-time-test-key");
    fireEvent.click(screen.getByRole("button", { name: "Hide key" }));
    expect(screen.queryByDisplayValue("one-time-test-key")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Rotate key" }));
    expect(api.post).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Rotate key now" })).toBeTruthy();
  });
  it("edits field rules through labeled controls", () => {
    render(<Settings />);
    fireEvent.click(screen.getByRole("button", { name: "Add field" }));
    expect(screen.getAllByLabelText("Field name")).toHaveLength(2);
    fireEvent.change(screen.getAllByLabelText("Type")[1], {
      target: { value: "select" },
    });
    expect(screen.getByLabelText("Choices, one per line")).toBeTruthy();
  });
});
describe("integration examples", () => {
  it("public snippets include verification, configured fields and honeypots", async () => {
    const snippets = integrationSnippets(form, "https://forms.example.com");
    for (const source of Object.values(snippets)) {
      expect(source).toContain("_formto_honeypot");
      expect(source).toContain("site-key");
      expect(source).toContain("1234");
      expect(source).not.toContain("form_1234");
      expect(source).not.toContain("Authorization");
    }
    expect(snippets.React).toContain("window.turnstile.render");
  });
  it("private examples contain only an environment placeholder", () => {
    const snippets = integrationSnippets(
      {
        ...form,
        submission_mode: "private",
        submission_key_hash: "never-show",
        turnstile_secret: "secret",
      },
      "https://forms.example.com",
    );
    expect(Object.keys(snippets)).toEqual(["Server"]);
    expect(snippets.Server).toContain("$FORMTO_SUBMISSION_KEY");
    expect(snippets.Server).not.toContain("never-show");
    expect(snippets.Server).not.toContain("Bearer secret");
  });
  it("escapes JSX expressions and HTML markup in user-defined labels", async () => {
    const unusual = {
      ...form,
      fields: [{ ...form.fields[0], label: '<img onerror="bad"> {alert(1)}' }],
    };
    expect(formMarkup(unusual, true)).not.toContain("<img");
    expect(formMarkup(unusual, true)).not.toContain("{alert(1)}");
    expect(
      integrationSnippets(unusual, "https://forms.example.com").React,
    ).not.toContain("{alert(1)}");
  });
});
