'use strict';
// fs bridge authorization policy — pure functions, no electron deps.
// Wired from electron.js fs-* IPC handlers; unit-tested in tests/fs-bridge.test.js.
const fs = require('fs');
const path = require('path');

const MAX_READ_BYTES = 32 * 1024 * 1024;      // readFileSync cap
const MAX_WRITE_BYTES = 64 * 1024 * 1024;     // writeFileSync payload cap
const MAX_DIR_ENTRIES = 5000;                  // readdir truncation cap

// Operation modes with distinct root policies:
//   read/list : readRoots — HOME included (opening loose files is core UX)
//   write/mkdir: strict roots only (project + app dirs + dialog-approved) —
//                no HOME blanket; an XSS can't plant files anywhere in HOME
//   delete    : same strict roots
//   rename    : src=delete, dst=write   (copy removed — unused)
function buildRoots(ctx) {
  const home = ctx.home;
  const configDir = path.join(home, '.config', 'prometheus-ide');
  const approved = [...(ctx.approvedRoots || [])];
  const project = ctx.projectRoot ? [ctx.projectRoot] : [];
  const strict = [ctx.dataDir, ctx.tmp, configDir, ...approved, ...project];
  return { read: [home, ...strict], strict };
}

// Write denylist: credential dirs + persistence/credential files under HOME.
// Still needed despite strict write roots — a user can approve HOME (or a dir
// containing these) via the native folder dialog, which would otherwise
// reopen them.
const writeDenyDirs = (home) =>
  ['.ssh', '.gnupg', '.aws', '.kube', '.docker',
   '.config/gh', '.config/autostart', '.config/systemd', '.config/environment.d',
   '.config/Code/User', '.config/VSCodium/User', '.config/fish',
   '.local/share'].map(d => path.join(home, d));
const writeDenyFiles = (home) =>
  ['.bashrc', '.bash_profile', '.bash_login', '.zshrc', '.zprofile', '.zshenv',
   '.zlogin', '.profile', '.xprofile', '.xinitrc', '.xsession', '.pam_environment',
   '.netrc', '.npmrc', '.pypirc', '.gitconfig', '.git-credentials']
   .map(f => path.join(home, f));

function writeDenied(real, ctx) {
  // the app's own data dir (~/.local/share/prometheus-ide) must stay writable
  // even though the rest of ~/.local/share is denied
  let dd = '';
  try { dd = fs.realpathSync.native(path.resolve(ctx.dataDir)); }
  catch (e) { if (ctx.dataDir) dd = path.resolve(ctx.dataDir); }
  if (dd && (real === dd || real.startsWith(dd + path.sep))) return false;
  const fr = fold(real);
  return writeDenyDirs(ctx.home).some(d => { const fd = fold(d); return fr === fd || fr.startsWith(fd + path.sep); }) ||
         writeDenyFiles(ctx.home).some(f => fr === fold(f));
}

// Resolve p to its real on-disk path: deepest existing ancestor is
// realpath'd (defeats symlink escapes incl. links mid-path); the
// not-yet-existing tail is reappended literally.
function realTarget(p) {
  const resolved = path.resolve(String(p));
  let probe = resolved;
  while (!fs.existsSync(probe) && probe !== path.dirname(probe)) probe = path.dirname(probe);
  if (!fs.existsSync(probe)) return null;
  return fs.realpathSync.native(probe) + resolved.slice(probe.length);
}

// NTFS and default APFS are case-insensitive — string compares must fold case
// or 'C:\Users\X\.SSH\keys' bypasses the '.ssh' denylist.
const CASE_FOLD = process.platform === 'win32' || process.platform === 'darwin';
const fold = (s) => CASE_FOLD ? s.toLowerCase() : s;

function underRoot(real, root) {
  let rr;
  try { rr = fs.realpathSync.native(path.resolve(root)); } catch (e) { return false; }
  const a = fold(real), b = fold(rr);
  return a === b || a.startsWith(b + path.sep);
}

function fsAllowed(p, mode, ctx) {
  try {
    const real = realTarget(p);
    if (!real) return false;
    if ((mode === 'write' || mode === 'mkdir' || mode === 'delete') && writeDenied(real, ctx)) return false;
    const roots = buildRoots(ctx);
    const list = (mode === 'read' || mode === 'list') ? roots.read : roots.strict;
    return list.some(r => underRoot(real, r));
  } catch (e) { return false; }
}

// Anti-DoS caps — called from IPC handlers in electron.js
function assertReadSize(p) {
  if (fs.statSync(p).size > MAX_READ_BYTES)
    throw Object.assign(new Error('file too large'), { code: 'EFBIG' });
}
function assertWriteSize(data, enc) {
  if (Buffer.byteLength(String(data), enc || 'utf-8') > MAX_WRITE_BYTES)
    throw Object.assign(new Error('payload too large'), { code: 'EFBIG' });
}

// Directory listing pipeline: hides dotfiles, dirs-first sort, hard cap.
function listDir(p, max = MAX_DIR_ENTRIES) {
  return fs.readdirSync(p, { withFileTypes: true })
    .filter(en => !en.name.startsWith('.'))
    .sort((a, b) => a.isDirectory() !== b.isDirectory() ? (a.isDirectory() ? -1 : 1) : a.name.localeCompare(b.name))
    .slice(0, max);
}

// node --test + electron.js both need these
module.exports = { fsAllowed, realTarget, buildRoots, listDir, assertReadSize, assertWriteSize,
  MAX_READ_BYTES, MAX_WRITE_BYTES, MAX_DIR_ENTRIES };
