import { readFileSync } from 'node:fs';
const metadata = JSON.parse(readFileSync('dependency-metadata.json', 'utf8'));
const manifest = readFileSync('Cargo.toml', 'utf8');
for (const name of ['crlt', 'cpsd', 'csgn']) {
  const revision = manifest.match(new RegExp(`^${name} = .*rev = "([a-f0-9]{40})"`, 'm'))?.[1];
  const packages = metadata.packages.filter(p => p.name === name);
  if (!revision || packages.length !== 1 || !packages[0].source?.endsWith(`#${revision}`)) {
    throw new Error(`Unreviewed or duplicated leaf revision: ${name}`);
  }
}
console.log('All leaf revisions match the reviewed manifest pins');
