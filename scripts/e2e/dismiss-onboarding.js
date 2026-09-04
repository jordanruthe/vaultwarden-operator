// Dismisses the web vault's first-login onboarding flow: an "install the
// browser extension" interstitial (which redirects any navigation back to
// itself until dismissed, via a confirmation dialog with a "Skip to web app"
// link) followed by a "Welcome to Bitwarden" product-tour dialog. Neither
// existed when register.js/create-org.js/get-api-key.js were first written;
// a fresh account now lands on this flow immediately after login.
//
// Call right after logging in, before navigating anywhere else.
async function dismissOnboarding(page) {
  await page.waitForURL(/#\/setup-extension/, { timeout: 10000 }).catch(() => {});
  if (/#\/setup-extension/.test(page.url())) {
    await page.getByRole("button", { name: "Add it later" }).click();
    await page.getByRole("link", { name: "Skip to web app" }).click();
    await page.waitForURL(/#\/vault/, { timeout: 10000 });
  }
  await page.getByRole("button", { name: "Skip" }).click({ timeout: 5000 }).catch(() => {});
}

module.exports = { dismissOnboarding };
