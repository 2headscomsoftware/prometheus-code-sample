'use strict';
// Attack-scenario tests for lib/fs-gate.js — real tmpdirs + symlinks, no Electron.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { fsAllowed, listDir, assertReadSize, assertWriteSize, MAX_DIR_ENTRIES, MAX_READ_BYTES, MAX_WRITE_BYTES } = require('../lib/fs-gate.js');

// Simulated environment: fake HOME, project, approved dir, and an outside dir.
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'fsgate-'));
const fakeHome = path.join(base, 'home');
const project  = path.join(fakeHome, 'proyecto');           // project inside HOME
const approved = path.join(base, 'approved');                // dialog-approved dir outside HOME
const outside  = path.join(base, 'outside');                 // nowhere authorized
const dataDir  = path.join(base, 'data');
const fakeTmp  = path.join(base, 'tmp');                     // stand-in for os.tmpdir()
const cfgDir   = path.join(fakeHome, '.config', 'prometheus-ide');
for (const d of [project, approved, outside, dataDir, fakeTmp, cfgDir,
                 path.join(fakeHome, '.ssh')]) fs.mkdirSync(d, { recursive: true });
fs.writeFileSync(path.join(project, 'a.txt'), 'hola');
fs.writeFileSync(path.join(outside, 'secret.txt'), 'pwn');
fs.symlinkSync(outside, path.join(fakeHome, 'sneaky'));       // HOME -> outside
fs.symlinkSync(outside, path.join(project, 'link-out'));      // project -> outside
const ctx = () => ({ home: fakeHome, dataDir, tmp: fakeTmp, approvedRoots: [approved], projectRoot: project });

test('read/list inside roots allowed; outside denied', () => {
  assert.ok(fsAllowed(path.join(project, 'a.txt'), 'read', ctx()));
  assert.ok(fsAllowed(path.join(fakeHome, '.bashrc'), 'read', ctx()));   // loose HOME file ok
  assert.ok(fsAllowed(path.join(approved, 'x'), 'read', ctx()));
  assert.ok(!fsAllowed(path.join(outside, 'secret.txt'), 'read', ctx()));
  assert.ok(!fsAllowed('/etc/shadow', 'read', ctx()));
});

test('write: no HOME blanket — project/approved only; credential dirs denied', () => {
  assert.ok(fsAllowed(path.join(project, 'new.js'), 'write', ctx()));
  assert.ok(fsAllowed(path.join(approved, 'x'), 'write', ctx()));
  assert.ok(!fsAllowed(path.join(fakeHome, 'notas.txt'), 'write', ctx()));   // loose HOME: denied
  assert.ok(!fsAllowed(path.join(fakeHome, '.ssh', 'authorized_keys'), 'write', ctx()));
  assert.ok(!fsAllowed(path.join(fakeHome, '.ssh', 'new file.txt'), 'write', ctx()));
});

test('delete has no HOME blanket — only project/app/approved dirs', () => {
  assert.ok(fsAllowed(path.join(project, 'a.txt'), 'delete', ctx()));
  assert.ok(fsAllowed(path.join(approved, 'x'), 'delete', ctx()));
  assert.ok(fsAllowed(path.join(dataDir, 'cache.bin'), 'delete', ctx()));
  assert.ok(!fsAllowed(path.join(fakeHome, 'notas.txt'), 'delete', ctx()));   // HOME no
  assert.ok(!fsAllowed(path.join(fakeHome, '.bashrc'), 'delete', ctx()));
  assert.ok(!fsAllowed(path.join(outside, 'secret.txt'), 'delete', ctx()));
});

test('traversal: repeated .. cannot escape', () => {
  assert.ok(!fsAllowed(project + '/../../../../outside/secret.txt', 'read', ctx()));
  assert.ok(!fsAllowed(project + '/../' + path.basename(fakeHome) + '/../..' + '/outside/x', 'write', ctx()));
  assert.ok(fsAllowed(project + '/subdir/../a.txt', 'read', ctx()));          // .. that stays inside ok
});

test('symlinks inside roots resolving outside are denied', () => {
  assert.ok(!fsAllowed(path.join(fakeHome, 'sneaky', 'secret.txt'), 'read', ctx()));
  assert.ok(!fsAllowed(path.join(fakeHome, 'sneaky', 'new.txt'), 'write', ctx()));   // new file via link
  assert.ok(!fsAllowed(path.join(project, 'link-out', 'evil.js'), 'write', ctx()));
  assert.ok(!fsAllowed(path.join(project, 'link-out', 'evil.js'), 'delete', ctx()));
});

test('literal ~ and $HOME do not expand — resolve outside roots', () => {
  assert.ok(!fsAllowed('~/.ssh/config', 'read', ctx()));
  assert.ok(!fsAllowed('$HOME/.bashrc', 'write', ctx()));
});

test('unicode, spaces, unusual chars inside project work', () => {
  const weird = ['árbol ñandú.js', 'file with spaces.txt', 'emoj😀i.js', "comilla's.js", 'a;b&c$d.js'];
  for (const n of weird) {
    const p = path.join(project, n);
    assert.ok(fsAllowed(p, 'write', ctx()), n);
    fs.writeFileSync(p, 'x');
    assert.ok(fsAllowed(p, 'read', ctx()), n);
    assert.ok(fsAllowed(p, 'delete', ctx()), n);
  }
});

test('mkdir follows write policy (credential dirs denied)', () => {
  assert.ok(fsAllowed(path.join(project, 'src'), 'mkdir', ctx()));
  assert.ok(!fsAllowed(path.join(fakeHome, '.ssh', 'newdir'), 'mkdir', ctx()));
});

test('sensitive files stay denied even if HOME itself is approved', () => {
  const wide = { ...ctx(), approvedRoots: [fakeHome] };   // user opened ~ as folder
  assert.ok(fsAllowed(path.join(fakeHome, 'notas.txt'), 'write', wide));      // normal files ok
  for (const p of ['.bashrc', '.zshrc', '.netrc', '.gitconfig', '.npmrc'])
    assert.ok(!fsAllowed(path.join(fakeHome, p), 'write', wide), p);
  for (const d of ['.ssh', '.config/gh', '.config/autostart', '.config/systemd'])
    assert.ok(!fsAllowed(path.join(fakeHome, d, 'x'), 'write', wide), d);
  assert.ok(!fsAllowed(path.join(fakeHome, '.bashrc'), 'delete', wide));      // delete too
});

test('~/.local/share denied except the app data dir itself', () => {
  const ownData = path.join(fakeHome, '.local', 'share', 'prometheus-ide');
  fs.mkdirSync(ownData, { recursive: true });
  const wide = { ...ctx(), dataDir: ownData, approvedRoots: [fakeHome] };
  assert.ok(fsAllowed(path.join(ownData, 'sessions.json'), 'write', wide));   // own dir ok
  assert.ok(fsAllowed(path.join(ownData, 'deep', 'file'), 'write', wide));
  assert.ok(!fsAllowed(path.join(fakeHome, '.local', 'share', 'other-app', 'x'), 'write', wide));
  assert.ok(!fsAllowed(path.join(fakeHome, '.local', 'share', 'keyrings', 'k'), 'write', wide));
});

test('listDir caps entries and hides dotfiles', () => {
  const big = path.join(base, 'big');
  fs.mkdirSync(big);
  for (let i = 0; i < 120; i++) fs.writeFileSync(path.join(big, `f${String(i).padStart(3, '0')}.txt`), '');
  fs.writeFileSync(path.join(big, '.hidden'), '');
  const ents = listDir(big, 100);
  assert.equal(ents.length, 100);                    // capped
  assert.ok(!ents.some(e => e.name === '.hidden'));  // dotfiles filtered
  const sub = path.join(big, 'zz_dir');
  fs.mkdirSync(sub);
  assert.ok(listDir(big, 500)[0].isDirectory());     // dirs first
});

test('size caps reject oversized ops', () => {
  const big = path.join(project, 'big.bin');
  const fd = fs.openSync(big, 'w');
  fs.ftruncateSync(fd, MAX_READ_BYTES + 1);
  fs.closeSync(fd);
  assert.throws(() => assertReadSize(big), /too large/);
  assert.doesNotThrow(() => assertReadSize(path.join(project, 'a.txt')));
  assert.throws(() => assertWriteSize('x'.repeat(MAX_WRITE_BYTES + 1)), /too large/);
});
