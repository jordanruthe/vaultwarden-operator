// Fetches the personal API key (client_id/client_secret) for a Vaultwarden
// account by driving the web vault's Settings > Security > Keys > "View API
// key" flow with a headless browser.
//
// Why: this is the same constraint as register.js — issuing an API key
// requires re-hashing the master password client-side, which only the web
// vault / official clients do. `bw` has no CLI command for it, and hand-
// rolling Vaultwarden's PBKDF2/Argon2id hash in a shell script would just
// duplicate crypto logic the Rust operator already implements correctly.
//
// Usage: node get-api-key.js <httpsBaseUrl> <email> <password>
// Prints {"clientId":"...","clientSecret":"..."} as JSON to stdout.
const { chromium } = require("playwright");

const [, , BASE, EMAIL, PASSWORD] = process.argv;
if (!BASE || !EMAIL || !PASSWORD) {
  console.error("usage: node get-api-key.js <httpsBaseUrl> <email> <password>");
  process.exit(1);
}

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  page.on("pageerror", (err) => console.error("PAGE ERROR:", err.message));

  await page.goto(`${BASE}/#/login`, { waitUntil: "networkidle" });
  await page.getByLabel(/Email address/i).fill(EMAIL);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.waitForTimeout(1500);

  await page.getByLabel("Master password (required)", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Log in with master password" }).click();
  await page.waitForTimeout(2000);

  await page.goto(`${BASE}/#/settings/security/security-keys`, { waitUntil: "networkidle" });
  await page.waitForTimeout(1000);

  await page.getByRole("button", { name: "View API key" }).click();
  await page.waitForTimeout(500);
  // Re-confirms identity with the master password before revealing the key.
  await page.getByLabel("Master password (required)", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "View API key" }).click();
  await page.waitForTimeout(1000);

  const codeTexts = await page.locator("code").allTextContents();
  await browser.close();

  const [clientId, clientSecret] = codeTexts;
  if (!clientId?.startsWith("user.") || !clientSecret) {
    console.error("failed to extract API key; got code elements:", JSON.stringify(codeTexts));
    process.exit(1);
  }
  console.log(JSON.stringify({ clientId, clientSecret }));
})().catch((err) => {
  console.error("get-api-key failed:", err.message);
  process.exit(1);
});
