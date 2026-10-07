import { useState } from "react";
import { Copy, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { integrationSnippets } from "@/lib/formSnippets";

export default function CodeSnippet({ form }) {
  const [copied, setCopied] = useState("");
  const [error, setError] = useState("");
  const snippets = integrationSnippets(
    form,
    import.meta.env.VITE_API_BASE_URL || window.location.origin,
  );
  async function copy(name, snippet) {
    try {
      await navigator.clipboard.writeText(snippet);
      setCopied(name);
      setError("");
    } catch {
      setError("Copy failed. Select the code and copy it manually.");
    }
  }
  if (form.submission_mode === "legacy")
    return (
      <Card className="border-amber-500">
        <CardHeader>
          <CardTitle>Legacy security — upgrade recommended</CardTitle>
          <CardDescription>
            This form still accepts submissions through its existing
            integration. Open Form Settings to explicitly upgrade it before
            using the new integration examples. Upgrading cannot be undone.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  return (
    <Card>
      <CardHeader>
        <CardTitle>Connect your form</CardTitle>
        <CardDescription>
          {form.submission_mode === "private"
            ? "Run this integration on your server using its secret environment."
            : "Register your website in Allowed websites and in your Cloudflare Turnstile widget. These examples include verification."}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {form.security_issue && (
          <p role="status" className="text-sm text-destructive">
            Complete security setup before using these examples:{" "}
            {form.security_issue}.
          </p>
        )}
        <Tabs
          key={form.submission_mode}
          defaultValue={Object.keys(snippets)[0]}
        >
          <TabsList>
            {Object.keys(snippets).map((name) => (
              <TabsTrigger key={name} value={name}>
                {name}
              </TabsTrigger>
            ))}
          </TabsList>
          {Object.entries(snippets).map(([name, snippet]) => (
            <TabsContent key={name} value={name} className="space-y-3">
              <Button
                type="button"
                variant="outline"
                onClick={() => copy(name, snippet)}
              >
                {copied === name ? (
                  <Check className="mr-2 h-4 w-4" />
                ) : (
                  <Copy className="mr-2 h-4 w-4" />
                )}
                {copied === name ? "Copied" : "Copy code"}
              </Button>
              <pre
                tabIndex={0}
                aria-label={`${name} integration code`}
                className="max-h-96 overflow-auto rounded-md bg-muted p-4 text-xs"
              >
                <code>{snippet}</code>
              </pre>
            </TabsContent>
          ))}
        </Tabs>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
