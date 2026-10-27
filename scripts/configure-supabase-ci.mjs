// Isolate the disposable app checkout; never change a developer's running stack.
import { randomUUID } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { resolve } from 'node:path';

if (!process.argv[2]) throw new Error('Pass the disposable app checkout directory');
const configPath = resolve(process.argv[2], 'supabase/config.toml');
const source = await readFile(configPath, 'utf8');
const localPorts = new Set([
  'api.port', 'db.port', 'db.shadow_port', 'db.pooler.port', 'studio.port',
  'inbucket.port', 'inbucket.smtp_port', 'inbucket.pop3_port',
  'edge_runtime.inspector_port', 'analytics.port',
]);
const reservations = [];
let section = '';
let projectFound = false;
let portCount = 0;
const lines = [];
try {
  for (let line of source.split('\n')) {
    const heading = line.match(/^\s*\[([^\]]+)\]\s*(?:#.*)?$/);
    if (heading) section = heading[1];
    if (!section && /^project_id\s*=/.test(line)) {
      line = `project_id = "security-graph-ci-${randomUUID()}"`;
      projectFound = true;
    }
    const setting = line.match(/^(\s*(\w+)\s*=\s*)\d+(\s*(?:#.*)?)$/);
    if (setting && localPorts.has(`${section}.${setting[2]}`)) {
      const server = createServer();
      await new Promise((accept, reject) => {
        server.once('error', reject);
        server.listen(0, '0.0.0.0', accept);
      });
      reservations.push(server);
      line = `${setting[1]}${server.address().port}${setting[3]}`;
      portCount++;
    }
    lines.push(line);
  }
  if (!projectFound || portCount === 0) throw new Error('Missing local Supabase project/ports');
  await writeFile(configPath, lines.join('\n'));
  console.log(`Configured an isolated Supabase project with ${portCount} available ports`);
} finally {
  await Promise.all(reservations.map(server => new Promise((accept, reject) => {
    server.close(error => error ? reject(error) : accept());
  })));
}
