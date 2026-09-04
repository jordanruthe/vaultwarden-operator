// Creates an organization in a Vaultwarden instance by driving the web
// vault's "New organization" form with a headless browser.
//
// Why: same constraint as register.js — creating an organization requires
// client-side crypto (the org symmetric key is generated locally and
// encrypted with the account's RSA public key), which only the web vault /
// official clients perform. `bw` has no CLI command for it.
//
// Usage: node create-org.js <httpsBaseUrl> <email> <password> <orgName>
const { chromium } = require("playwright");
const { dismissOnboarding } = require("./dismiss-onboarding");

const [, , BASE, EMAIL, PASSWORD, ORG_NAME] = process.argv;
if (!BASE || !EMAIL || !PASSWORD || !ORG_NAME) {
  console.error("usage: node create-org.js <httpsBaseUrl> <email> <password> <orgName>");
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

  // Matched by id / formcontrolname rather than accessible label text: the
  // web vault's label markup adds a "*" required marker inline, which
  // changes the computed accessible name (e.g. "Master password (required)"
  // became "Master password * (required)"), while these attributes have
  // stayed stable.
  await page.locator("#masterPassword").fill(PASSWORD);
  await page.getByRole("button", { name: "Log in" }).click();
  await page.waitForTimeout(2000);
  await dismissOnboarding(page);

  await page.goto(`${BASE}/#/create-organization`, { waitUntil: "networkidle" });
  await page.locator('input[formcontrolname="name"]').fill(ORG_NAME);
  await page.locator('input[formcontrolname="billingEmail"]').fill(EMAIL);
  await page.getByRole("button", { name: "Submit" }).click();

  // Success lands in the new organization's admin console vault.
  await page.waitForURL(/#\/organizations\//, { timeout: 15000 });
  await browser.close();

  console.log(`organization ${JSON.stringify(ORG_NAME)} created`);
})().catch((err) => {
  console.error("create-org failed:", err.message);
  process.exit(1);
});
