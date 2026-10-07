import { expect, it } from "vitest";
import { transform } from "esbuild";
import { integrationSnippets } from "../lib/formSnippets";
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
