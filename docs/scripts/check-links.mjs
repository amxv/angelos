import { readdir, readFile, stat } from 'node:fs/promises';
import { resolve, join, relative, sep } from 'node:path';

// Verify the published HTML, not just source Markdown. No network or dependencies.
const root = resolve('dist');
// Keep the visible release label aligned with the maintained tool reference.
const toolReference = await readFile('src/content/docs/tools.md', 'utf8');
const release = toolReference.match(/Angelos (\d+\.\d+)\.\d+ exposes/)?.[1];
if (!release) throw new Error('Tool reference must declare the current Angelos release.');
async function walk(dir) {
  const files = await readdir(dir, { withFileTypes: true });
  return (await Promise.all(files.map(entry => entry.isDirectory() ? walk(join(dir, entry.name)) : join(dir, entry.name)))).flat();
}
const files = await walk(root);
const html = new Map(await Promise.all(files.filter(path => path.endsWith('.html')).map(async path => {
  const text = (await readFile(path, 'utf8')).replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<!--[\s\S]*?-->/g, '');
  return [path, { text, ids: new Set([...text.matchAll(/\bid="([^"]+)"/g)].map(match => match[1])) }];
})));
const errors = [];
// Documentation must not contact Google Fonts as a side effect of a page view.
// Check generated HTML resource tags and CSS, so dependency imports are covered.
const remoteFonts = /(?:fonts\.googleapis\.com|fonts\.gstatic\.com)/i;
for (const path of files.filter(path => path.endsWith('.css'))) {
  if (remoteFonts.test(await readFile(path, 'utf8'))) errors.push(`${relative(root, path)}: external font dependency`);
}
for (const [path, page] of html) {
  const name = relative(root, path);
  for (const resource of page.text.matchAll(/<link\b[^>]*>|<style\b[^>]*>[\s\S]*?<\/style>/gi)) {
    if (remoteFonts.test(resource[0])) errors.push(`${name}: external font dependency`);
  }
  const footer = page.text.match(/<footer\b[^>]*>[\s\S]*?<\/footer>/i)?.[0] || '';
  if (!footer.includes(`v${release} ·`)) errors.push(`${name}: expected v${release} footer matching the tool reference`);
  const h1s = [...page.text.matchAll(/<h1(?:\s|>)/g)].length;
  if (h1s !== 1) errors.push(`${name}: expected one H1, found ${h1s}`);
  for (const match of page.text.matchAll(/<a\b[^>]*\bhref="([^"]+)"/g)) {
    const href = match[1].replaceAll('&amp;', '&');
    if (/^(?:[a-z]+:|\/\/)/i.test(href)) continue;
    const url = new URL(href, `https://docs.invalid/${relative(root, path).split(sep).join('/')}`);
    let target = resolve(root, `.${decodeURIComponent(url.pathname)}`);
    if (!target.startsWith(`${root}${sep}`) && target !== root) { errors.push(`${name}: path outside site ${href}`); continue; }
    try {
      if ((await stat(target)).isDirectory()) target = join(target, 'index.html');
    } catch {
      if (!target.endsWith('.html') && !target.endsWith('.md')) target = join(target, 'index.html');
    }
    try { await stat(target); } catch { errors.push(`${name}: missing route ${href}`); continue; }
    if (url.hash && html.has(target) && !html.get(target).ids.has(decodeURIComponent(url.hash.slice(1)))) errors.push(`${name}: missing anchor ${href}`);
  }
}
if (errors.length) { console.error(errors.join('\n')); process.exitCode = 1; }
else console.log(`Verified ${html.size} HTML pages: local links, anchors, release footer, one H1 per page, and no external Google Fonts.`);
