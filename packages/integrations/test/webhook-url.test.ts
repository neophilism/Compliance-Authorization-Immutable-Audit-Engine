import assert from "node:assert/strict";
import test from "node:test";
import { validateWebhookUrl } from "../src/index.js";

test("webhook URL policy accepts HTTPS DNS destinations only", () => {
  assert.equal(validateWebhookUrl("https://example.invalid/callback"), "https://example.invalid/callback");
  assert.equal(validateWebhookUrl("https://events.example.com/hooks?token=abc"), "https://events.example.com/hooks?token=abc");
  for (const candidate of [
    "http://example.com/",
    "https://localhost/hook",
    "https://localhost.localdomain/hook",
    "https://dev.local/hook",
    "https://router.internal/hook",
    "https://127.0.0.1/hook",
    "https://0x7f000001/hook",
    "https://[::1]/hook",
    "https://192.168.1.4/hook",
    "https://8.8.8.8/hook",
    "https://example.com:8443/hook",
    "https://user:pass@example.com/hook",
    "https://example.com/hook#fragment",
  ]) {
    assert.throws(() => validateWebhookUrl(candidate), { name: "IntegrationError" }, candidate);
  }
});
