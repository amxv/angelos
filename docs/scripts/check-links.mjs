import { readdir, readFile, stat } from 'node:fs/promises';
import { resolve, join, relative, sep } from 'node:path';

// Verify the published HTML, not just source Markdown. No network or dependencies.
const root = resolve('dist');
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
for (const [path, page] of html) {
  const name = relative(root, path);
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
else console.log(`Verified ${html.size} HTML pages: local links, anchors, and one H1 per page.`);
