import { expect, it } from "vitest";
import { transform } from "esbuild";
import { integrationSnippets } from "../lib/formSnippets";
it("public snippets use a Cloudflare-valid action for real UUIDs", () => {
  const form = { id: "d9d39bed-c631-46e9-9151-a11bda3fc966", endpoint: "contact", submission_mode: "public", turnstile_site_key: "public-key", fields: [] };
  const action = "d9d39bedc63146e99151a11bda3fc966";
  expect(action.length).toBeLessThanOrEqual(32);
  for (const snippet of Object.values(integrationSnippets(form, "https://forms.example.com"))) {
    expect(snippet).toContain(action);
    expect(snippet).not.toContain(`form_${action}`);
  }
});
it("generated React example compiles with all supported field types", async () => {
  const types = [
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
  ];
  const form = {
    id: "1234",
    endpoint: "test",
    submission_mode: "public",
    turnstile_site_key: "site-key",
    fields: types.map((type) => ({
      name: type,
      type,
      label: "Unusual <label> {expression}",
      maxLength: 100,
      required: true,
      options: [{ value: "O'Reilly", label: "A & B" }],
    })),
  };
  await expect(
    transform(integrationSnippets(form, "https://forms.example.com").React, {
      loader: "jsx",
    }),
  ).resolves.toBeTruthy();
});
