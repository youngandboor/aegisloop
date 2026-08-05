'use strict';

const assert = require('assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');

function copyDir(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    if (['.git', 'jobs', 'logs', 'state.json', 'config.json'].includes(entry.name)) continue;
    const source = path.join(from, entry.name);
    const target = path.join(to, entry.name);
    if (entry.isDirectory()) copyDir(source, target);
    else fs.copyFileSync(source, target);
  }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

async function waitForBridge(base, child, output) {
  for (let index = 0; index < 40; index++) {
    if (child.exitCode !== null) throw new Error(`server exited early: ${output()}`);
    try {
      const response = await fetch(`${base}/health`);
      if (response.ok) return;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`server did not start: ${output()}`);
}

async function main() {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'aegisloop-ui-security-'));
  const repo = path.join(parent, 'repo');
  const workspace = path.join(parent, 'workspace');
  const port = await freePort();
  const token = 'configured-token-must-never-appear-in-ui-responses';
  const conversationId = '33333333-3333-4333-8333-333333333333';
  fs.mkdirSync(workspace, { recursive: true });
  copyDir(ROOT, repo);

  fs.writeFileSync(path.join(repo, 'config.json'), JSON.stringify({
    port,
    contractVersion: 'le-3.3',
    apiToken: token,
    runtimeRoot: path.join(parent, 'runtime'),
    bindings: [{
      conversationId,
      codexSessionId: 'session-ui-security',
      workspaceDir: workspace,
      conversationMode: 'chat',
    }],
    codex: {
      bin: process.execPath,
      args: ['-e', 'process.stdin.resume()'],
      executorAdapter: 'legacy',
      stdinFlag: '-',
      timeoutMs: 5000,
    },
    breaker: { maxConsecutiveFailures: 4 },
    denylist: [],
  }, null, 2), 'utf8');

  const child = spawn(process.execPath, ['server.js'], {
    cwd: repo,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });

  try {
    const base = `http://127.0.0.1:${port}`;
    await waitForBridge(base, child, () => output);

    const appSource = fs.readFileSync(path.join(repo, 'ui', 'app.js'), 'utf8');
    assert(!appSource.includes('X-AegisLoop-Token'), 'UI JavaScript must not handle the configured apiToken');
    for (const contractField of ['armId', 'turnNonce', 'assistantMessageSig', 'codeBlockHash']) {
      assert(appSource.includes(contractField), `UI must preserve ${contractField} dispatch checks`);
    }
    assert.match(appSource, /action: maxRuns === 1 \? 'arm_once' : 'arm_loop'/);
    assert.match(appSource, /clientId=\$\{encodeURIComponent\(clientId\)\}/);

    const uiFiles = fs.readdirSync(path.join(repo, 'ui'), { withFileTypes: true })
      .filter(entry => entry.isFile())
      .map(entry => `/ui/${entry.name}`);
    const routes = ['/ui', '/ui/', '/ui/index.html', '/ui/config.js', ...uiFiles];
    let sessionCookie = '';

    for (const route of [...new Set(routes)]) {
      const response = await fetch(base + route);
      const body = await response.text();
      assert(!body.includes(token), `${route} exposed the configured apiToken`);
      assert(!JSON.stringify([...response.headers]).includes(token), `${route} exposed the configured apiToken in headers`);
      assert.strictEqual(response.headers.get('x-content-type-options'), 'nosniff');
      assert.strictEqual(response.headers.get('cross-origin-resource-policy'), 'same-origin');
      if (route === '/ui/') {
        const setCookie = response.headers.get('set-cookie') || '';
        assert.match(setCookie, /aegisloop_ui_session=/);
        assert.match(setCookie, /HttpOnly/i);
        assert.match(setCookie, /SameSite=Strict/i);
        assert(!setCookie.includes(token), 'UI session cookie must not reuse the configured apiToken');
        sessionCookie = setCookie.split(';', 1)[0];
      }
      if (route === '/ui/config.js') assert.strictEqual(response.status, 404);
      if (route.endsWith('index.html') || route === '/ui' || route === '/ui/') {
        assert(!body.includes('/ui/config.js'), `${route} still loads the removed token bootstrap`);
      }
    }

    assert(sessionCookie, 'UI navigation did not issue an HttpOnly session');

    const noSession = await fetch(`${base}/api/conversations`);
    assert.strictEqual(noSession.status, 401);

    const sameOrigin = await fetch(`${base}/api/conversations`, {
      headers: {
        Cookie: sessionCookie,
        Origin: base,
        'Sec-Fetch-Site': 'same-origin',
      },
    });
    assert.strictEqual(sameOrigin.status, 200, 'same-origin HttpOnly UI session should authorize the API');
    assert(!await sameOrigin.text().then(text => text.includes(token)), 'authorized API response exposed the configured apiToken');

    const sameOriginHeaders = {
      Cookie: sessionCookie,
      Origin: base,
      'Sec-Fetch-Site': 'same-origin',
      'Content-Type': 'application/json',
    };
    const armed = await fetch(`${base}/api/mode`, {
      method: 'POST',
      headers: sameOriginHeaders,
      body: JSON.stringify({
        conversationId,
        clientId: 'client-ui-security',
        action: 'arm_loop',
        maxDispatches: 2,
      }),
    });
    assert.strictEqual(armed.status, 200, 'same-origin UI session should authorize control writes');
    const armedBody = await armed.json();
    assert(armedBody.armId, 'UI control flow must preserve armId');
    assert(armedBody.turnNonce, 'UI control flow must preserve exact turnNonce');

    const missingOrigin = await fetch(`${base}/api/mode`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Sec-Fetch-Site': 'same-origin',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ conversationId, clientId: 'client-ui-security', action: 'chat' }),
    });
    assert.notStrictEqual(missingOrigin.status, 200, 'UI session control writes require an exact same-origin Origin header');

    const crossOrigin = await fetch(`${base}/api/conversations`, {
      headers: {
        Cookie: sessionCookie,
        Origin: 'https://example.com',
        'Sec-Fetch-Site': 'cross-site',
      },
    });
    assert.notStrictEqual(crossOrigin.status, 200, 'cross-origin requests must not reuse the UI session');

    const rawToken = await fetch(`${base}/api/conversations`, {
      headers: { 'X-AegisLoop-Token': token },
    });
    assert.strictEqual(rawToken.status, 200, 'existing extension token authorization must remain supported');

    console.log('UI same-origin authorization and token non-disclosure test passed');
  } finally {
    child.kill();
    await new Promise(resolve => setTimeout(resolve, 100));
    fs.rmSync(parent, { recursive: true, force: true });
  }
}

main().catch(error => {
  console.error(error && error.stack || error);
  process.exit(1);
});
