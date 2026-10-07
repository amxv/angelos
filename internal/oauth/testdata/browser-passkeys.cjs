// Optional real-browser contract test. Every URL is intercepted and served by
// the ephemeral loopback fixture; no production network or credentials are used.
'use strict';
const assert = require('node:assert/strict');
const {chromium} = require('playwright');
const issuer = 'https://api.angelos.ashray.xyz';
async function main() {
 const browser = await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE_PATH || undefined,args:['--no-sandbox']});
 try {
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => {if (m.type()==='error') errors.push(m.text());});
  await context.route('**/*', async route => {
   const request = route.request();
   const url = new URL(request.url());
   if (url.origin === 'https://client.example.com') {
    assert.equal(url.pathname, '/callback');
    return route.fulfill({status:200,contentType:'text/plain',body:'OAuth callback received'});
   }
   if (url.origin !== issuer) { errors.push('Unexpected outbound browser URL: ' + url.origin); return route.abort('blockedbyclient'); }
   const response = await context.request.fetch(process.env.BROWSER_FIXTURE_URL + url.pathname + url.search, {method:request.method(),headers:request.headers(),data:request.postDataBuffer() || undefined,maxRedirects:0,failOnStatusCode:false});
   await route.fulfill({response});
  });
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const options = {protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true};
  const first = await cdp.send('WebAuthn.addVirtualAuthenticator',{options});
  await page.goto(issuer + process.env.BROWSER_AUTHORIZE_PATH);
  await page.getByLabel('One-time enrollment token').fill(process.env.BROWSER_BOOTSTRAP);
  await page.getByRole('button',{name:'Enroll owner passkey'}).click();
  await page.waitForURL(issuer + '/oauth/consent?request=*');
  assert.match(await page.locator('main').innerText(), /test@example.com/);
  await page.locator('input[value="mail.write"]').uncheck();
  await page.locator('input[value="mail.send"]').uncheck();
  await page.getByRole('button',{name:'Approve selected permissions'}).click();
  await page.waitForURL('https://client.example.com/callback?*');
  const callback = new URL(page.url());
  assert.equal(callback.searchParams.get('iss'),issuer);
  assert.equal(callback.searchParams.get('state'),'browser-js-state');
  assert.ok(callback.searchParams.get('code'));
  await page.goto(issuer + '/oauth/grants');
  assert.match(await page.locator('main').innerText(), /Permissions: mail.read/);
  const oldCookie = (await context.cookies(issuer)).find(c => c.name==='__Host-angelos');
  assert.ok(oldCookie.secure && oldCookie.httpOnly && oldCookie.sameSite==='Lax');
  await page.getByRole('button',{name:'Sign out'}).click();
  await page.waitForURL(issuer + '/oauth/login');
  await page.getByRole('button',{name:'Sign in with a passkey'}).click();
  await page.waitForURL(issuer + '/oauth/grants');
  const newCookie = (await context.cookies(issuer)).find(c => c.name==='__Host-angelos');
  assert.notEqual(newCookie.value,oldCookie.value);
  // Switch to a second virtual authenticator for the backup enrollment.
  await cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:first.authenticatorId});
  await cdp.send('WebAuthn.addVirtualAuthenticator',{options});
  await page.getByRole('button',{name:'Add another passkey'}).click();
  await page.waitForFunction(() => document.body.innerText.includes('2 enrolled.'));
  await page.getByRole('button',{name:'Revoke this access'}).click();
  await page.waitForFunction(() => document.body.innerText.includes('No connected clients.'));
  assert.deepEqual(errors,[], 'Browser console/CSP errors');
  console.log('Chromium virtual WebAuthn: enrollment, exact consent, cross-origin callback, sign-in rotation, second authenticator, grant revocation passed.');
 } finally { await browser.close(); }
}
main().catch(error => {console.error(error);process.exitCode=1;});
