// Registers a throwaway account against a Vaultwarden instance by driving the
// actual web vault signup form with a headless browser.
//
// Why: `bw` (the Bitwarden CLI) has no non-interactive `register` command —
// account creation requires client-side crypto (master-password hashing, key
// generation) that only the web vault / official clients perform. The web
// vault also refuses to run over plain HTTP even on loopback, so the target
// URL must be the HTTPS TLS proxy (see tlsproxy.js), not the raw HTTP service.
//
// Usage: node register.js <httpsBaseUrl> <email> <name> <password>
const { chromium } = require("playwright");

const [, , BASE, EMAIL, NAME, PASSWORD] = process.argv;
if (!BASE || !EMAIL || !NAME || !PASSWORD) {
  console.error("usage: node register.js <httpsBaseUrl> <email> <name> <password>");
  process.exit(1);
}

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  page.on("pageerror", (err) => console.error("PAGE ERROR:", err.message));

  await page.goto(`${BASE}/#/signup`, { waitUntil: "networkidle" });
  await page.getByLabel("Email address").fill(EMAIL);
  await page.getByLabel("Name").fill(NAME);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.waitForTimeout(1500);

  await page.getByLabel("Master password (required)", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Confirm master password (required)", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: /Create account|Submit/i }).click();

  // The success toast ("Your new account has been created!") appears before
  // the app finishes navigating away from #/finish-signup, so wait on the
  // toast rather than racing the URL.
  await page.getByText("Your new account has been created", { exact: false }).waitFor({ timeout: 15000 });
  await browser.close();

  console.log("registration succeeded");
})().catch((err) => {
  console.error("registration failed:", err.message);
  process.exit(1);
});
