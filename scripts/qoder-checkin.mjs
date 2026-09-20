#!/usr/bin/env node
// Qoder 每日签到（CN / Global 双端）：
//   token 来源优先级：环境变量直传（CI 场景）> 本机 IDE 凭据解密（macOS/Windows 场景）。
//   自动续签：access token 剩余 <3 天主动续签；claim 遇 401 被动续签重试一次。
//   续签轮换出的新 token/refreshToken 写入 data/refreshed.json，供 workflow 回写 GitHub Secrets。
//   结果写 data/result.json 供邮件通知使用。
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const DAY = 86400e3;
const REFRESH_AHEAD_MS = 3 * DAY; // 剩余不足 3 天主动续签

const PROFILES = {
  cn: {
    label: 'Qoder CN',
    tokenEnv: 'QODER_TOKEN_CN',
    refreshEnv: 'QODER_REFRESH_TOKEN_CN',
    apiBase: process.env.QODER_API_BASE || process.env.QODER_API_BASE_CN || 'https://gateway.qoder.com.cn',
    openApiBase: process.env.QODER_OPENAPI_BASE || process.env.QODER_OPENAPI_BASE_CN || 'https://openapi.qoder.com.cn',
    dataDir: process.env.QODER_DATA_DIR || process.env.QODER_DATA_DIR_CN
      || path.join(os.homedir(), 'Library/Application Support/com.qodercn.app.stable'),
    keychainServices: (process.env.QODER_KEYCHAIN_SERVICES || process.env.QODER_KEYCHAIN_SERVICES_CN
      || 'Qoder CN App Safe Storage').split(',').map(s => s.trim()).filter(Boolean),
  },
  global: {
    label: 'Qoder Global',
    tokenEnv: 'QODER_TOKEN_GLOBAL',
    refreshEnv: 'QODER_REFRESH_TOKEN_GLOBAL',
    apiBase: process.env.QODER_API_BASE_GLOBAL || 'https://gateway.qoder.com',
    openApiBase: process.env.QODER_OPENAPI_BASE_GLOBAL || 'https://openapi.qoder.sh',
    dataDir: process.env.QODER_DATA_DIR_GLOBAL
      || path.join(os.homedir(), 'Library/Application Support/com.qoder.app.stable'),
    keychainServices: (process.env.QODER_KEYCHAIN_SERVICES_GLOBAL || 'Qoder Safe Storage')
      .split(',').map(s => s.trim()).filter(Boolean),
  },
};

const STATUS_PATH = '/sash/api/v1/me/daily-check-in/status';
const CLAIM_PATH = '/sash/api/v1/me/daily-check-in/claim';
const REFRESH_PATH = '/api/v1/deviceToken/refresh';
const LOG_FILE = process.env.QODER_CHECKIN_LOG || path.join(REPO_ROOT, 'data', 'checkin.log');
const RESULT_FILE = process.env.QODER_RESULT_FILE || path.join(REPO_ROOT, 'data', 'result.json');
const REFRESHED_FILE = process.env.QODER_REFRESHED_FILE || path.join(REPO_ROOT, 'data', 'refreshed.json');

function decryptSafeStorage(buf, password) {
  if (buf.slice(0, 3).toString() !== 'v10') throw new Error('unexpected prefix (not v10)');
  const key = crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), Buffer.from('saltysalt'), 1003, 16, 'sha1');
  const iv = Buffer.alloc(16, 0x20);
  const d = crypto.createDecipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([d.update(buf.slice(3)), d.final()]).toString('utf8');
}

function loadLocalAuth(profile) {
  const file = path.join(profile.dataDir, 'auth.v1.dat');
  if (!existsSync(file)) throw Object.assign(new Error(`missing ${file}`), { kind: 'NO_AUTH_FILE' });
  if (process.platform !== 'darwin') throw Object.assign(new Error('local credential decryption needs macOS keychain'), { kind: 'NO_AUTH_FILE' });
  const buf = readFileSync(file);
  let lastErr;
  for (const service of profile.keychainServices) {
    try {
      const password = execFileSync('security', ['find-generic-password', '-s', service, '-w']).toString().trim();
      return JSON.parse(decryptSafeStorage(buf, password));
    } catch (e) { lastErr = e; }
  }
  throw Object.assign(lastErr ?? new Error('keychain decrypt failed'), { kind: 'AUTH_FAIL' });
}

function jwtExpiry(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    return payload.exp ? payload.exp * 1000 : null;
  } catch { return null; }
}

const toMs = v => v == null ? null : (typeof v === 'number' || /^\d+$/.test(String(v))
  ? Number(v) * (String(v).length <= 11 ? 1000 : 1)
  : Date.parse(String(v)) || null);

// 返回 { token, refreshToken, expiresAt, refreshTokenExpiresAt, source }；来源为环境变量或本机凭据文件。
function acquireToken(profile) {
  const fromEnv = (process.env[profile.tokenEnv] || '').trim();
  if (fromEnv) {
    const rt = (process.env[profile.refreshEnv] || '').trim() || null;
    return { token: fromEnv, refreshToken: rt, expiresAt: jwtExpiry(fromEnv), refreshTokenExpiresAt: rt ? jwtExpiry(rt) : null, source: 'env' };
  }
  const auth = loadLocalAuth(profile);
  return {
    token: auth.token,
    refreshToken: auth.refreshToken || null,
    expiresAt: toMs(auth.expiresAt),
    refreshTokenExpiresAt: toMs(auth.refreshTokenExpiresAt),
    source: 'local',
  };
}

function hasCredential(profile) {
  return !!((process.env[profile.tokenEnv] || '').trim() || existsSync(path.join(profile.dataDir, 'auth.v1.dat')));
}

async function httpJson(url, method, body, token) {
  const res = await fetch(url, {
    method,
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(15000),
  });
  const text = await res.text();
  let parsed; try { parsed = JSON.parse(text); } catch { parsed = text; }
  return { status: res.status, body: parsed };
}

// 官方客户端同构：POST {openApi}/api/v1/deviceToken/refresh，响应为 snake_case 且 refreshToken 会轮换。
async function refreshSession(profile, refreshToken) {
  if (!refreshToken) return { ok: false, reason: '无 refreshToken 可用' };
  try {
    const r = await httpJson(profile.openApiBase + REFRESH_PATH, 'POST', { refresh_token: refreshToken });
    const b = typeof r.body === 'object' && r.body ? r.body : {};
    const token = b.device_token || b.token;
    const rt = b.refresh_token;
    if (!r.ok || !token || !rt) {
      return { ok: false, http: r.status, reason: typeof r.body === 'string' ? r.body.slice(0, 200) : (b.message || b.error || '响应缺少 token/refresh_token') };
    }
    return {
      ok: true, token, refreshToken: rt,
      expiresAt: toMs(b.expires_at) ?? (b.expires_in ? Date.now() + Number(b.expires_in) * 1000 : null),
      refreshTokenExpiresAt: toMs(b.refresh_token_expires_at) ?? (b.refresh_token_expires_in ? Date.now() + Number(b.refresh_token_expires_in) * 1000 : null),
    };
  } catch (e) {
    return { ok: false, reason: `续签请求异常：${String(e.message ?? e).split('\n')[0]}` };
  }
}

function applyRefresh(profile, sess, refreshed, entry) {
  if (!sess.ok) {
    entry.refresh = { ok: false, reason: sess.reason, http: sess.http };
    return;
  }
  sess.rotatedEnv = { [profile.tokenEnv]: sess.token, [profile.refreshEnv]: sess.refreshToken };
  Object.assign(refreshed, sess.rotatedEnv);
  entry.refresh = { ok: true, note: '续签成功，新凭据已写入 refreshed.json（CI 环境会自动回写 Secrets）' };
}

function log(entry) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry });
  console.log(line);
  try { mkdirSync(path.dirname(LOG_FILE), { recursive: true }); } catch {}
  try { appendFileSync(LOG_FILE, line + '\n'); } catch {}
}

function writeSummary(results) {
  const count = (r) => results.filter(x => r.includes(x.result)).length;
  const summary = {
    ts: new Date().toISOString(),
    results,
    ok: count(['OK', 'ALREADY_CLAIMED']),
    skipped: count(['SKIPPED']),
    failed: count(['AUTH_FAIL', 'TOKEN_EXPIRED', 'FAIL', 'API_ERROR']),
  };
  try { mkdirSync(path.dirname(RESULT_FILE), { recursive: true }); writeFileSync(RESULT_FILE, JSON.stringify(summary, null, 2)); } catch {}
  return summary;
}

function addExpiryInfo(entry, sess) {
  if (sess.expiresAt) entry.tokenDaysLeft = Math.max(0, Math.round((sess.expiresAt - Date.now()) / DAY));
  if (sess.refreshTokenExpiresAt) entry.refreshTokenDaysLeft = Math.max(0, Math.round((sess.refreshTokenExpiresAt - Date.now()) / DAY));
}

async function runProfile(cmd, name, rotatedOut) {
  const profile = PROFILES[name];
  const entry = { profile: name, label: profile.label };
  let sess;
  try {
    sess = acquireToken(profile);
  } catch (e) {
    const kind = e.kind === 'NO_AUTH_FILE' ? 'SKIPPED' : 'AUTH_FAIL';
    Object.assign(entry, { result: kind, reason: e.message.split('\n')[0] });
    log({ ...entry });
    return entry;
  }
  addExpiryInfo(entry, sess);
  if (sess.expiresAt && sess.expiresAt < Date.now()) {
    // 已过期：先尝试续签自救，失败才报 TOKEN_EXPIRED
    const sess2 = await refreshSession(profile, sess.refreshToken);
    if (sess2.ok) {
      applyRefresh(profile, sess2, rotatedOut, entry);
      Object.assign(sess, sess2);
      addExpiryInfo(entry, sess);
    } else {
      Object.assign(entry, { result: 'TOKEN_EXPIRED', hint: '本地：打开一次 IDE 刷新；CI：检查 QODER_REFRESH_TOKEN_* 是否配置/已轮换' , refreshFail: sess2.reason });
      log({ ...entry });
      return entry;
    }
  }
  // 主动续签：剩余 <3 天且能确知过期时间（env 直传的 dt- token 无法预知，靠 401 被动续签兜底）
  if (cmd === 'claim' && sess.expiresAt && sess.expiresAt - Date.now() < REFRESH_AHEAD_MS) {
    const sess2 = await refreshSession(profile, sess.refreshToken);
    applyRefresh(profile, sess2, rotatedOut, entry);
    if (sess2.ok) { Object.assign(sess, sess2); addExpiryInfo(entry, sess); }
    log({ cmd: 'refresh', profile: name, ok: sess2.ok, reason: sess2.reason });
  }
  try {
    if (cmd === 'status') {
      const r = await httpJson(profile.apiBase + STATUS_PATH, 'GET', null, sess.token);
      Object.assign(entry, { result: 'INFO', http: r.status, detail: r.body });
      log({ ...entry });
      return entry;
    }
    let r = await httpJson(profile.apiBase + CLAIM_PATH, 'POST', null, sess.token);
    if (r.status === 401) {
      // 被动续签：本地凭据重读 或 refresh 接口换新
      const sess2 = sess.source === 'local' ? (() => { try { return { ok: true, ...acquireToken(profile) }; } catch (e) { return { ok: false, reason: e.message }; } })()
        : await refreshSession(profile, sess.refreshToken);
      if (sess2.ok && sess2.token && sess2.token !== sess.token) {
        applyRefresh(profile, sess2, rotatedOut, entry);
        if (sess2.rotatedEnv) Object.assign(sess, sess2);
        r = await httpJson(profile.apiBase + CLAIM_PATH, 'POST', null, sess.token);
      }
    }
    const ok = r.status === 200 || (r.status === 409 && r.body?.errorCode === 'AlreadyExists');
    Object.assign(entry, {
      result: r.status === 409 ? 'ALREADY_CLAIMED' : ok ? 'OK' : 'FAIL',
      http: r.status,
      detail: r.body,
    });
    log({ ...entry });
    return entry;
  } catch (e) {
    Object.assign(entry, { result: 'API_ERROR', reason: String(e.message ?? e).split('\n')[0] });
    log({ ...entry });
    return entry;
  }
}

function exitCodeFor(results) {
  const has = k => results.some(r => r.result === k);
  if (has('FAIL') || has('API_ERROR')) return 4;
  if (has('AUTH_FAIL')) return 2;
  if (has('TOKEN_EXPIRED')) return 3;
  return 0;
}

async function main() {
  const cmd = process.argv[2] || 'status';
  const profileArg = process.argv[3] || 'all';
  // 不用 process.exit：Windows 下会与 fetch 连接句柄清理冲突触发 libuv 断言，改为自然退出。
  if (cmd === 'token') {
    // 仅供本地查看 token、复制到 GitHub Secrets 用，不参与定时任务。
    const name = profileArg === 'all' ? 'cn' : profileArg;
    if (!PROFILES[name]) { console.error(`unknown profile: ${name}`); return void (process.exitCode = 1); }
    try { console.log(acquireToken(PROFILES[name]).token); }
    catch (e) { console.error(e.message); process.exitCode = 2; }
    return;
  }
  if (!['status', 'claim'].includes(cmd)) {
    console.error('usage: qoder-checkin.mjs status|claim|token [cn|global|all]');
    return void (process.exitCode = 1);
  }
  const names = profileArg === 'all' ? Object.keys(PROFILES) : [profileArg];
  for (const n of names) if (!PROFILES[n]) { console.error(`unknown profile: ${n}`); return void (process.exitCode = 1); }

  // 签到要求至少一端有凭据（env token 或本机登录凭据文件），否则直接退出。
  if (cmd === 'claim' && !names.some(n => hasCredential(PROFILES[n]))) {
    log({ cmd, result: 'NO_TOKEN', error: '所有选中端均无任何 token 输入（环境变量 QODER_TOKEN_* 与本机凭据都不存在），退出' });
    writeSummary([{ profile: '*', label: '全部', result: 'AUTH_FAIL', reason: '未提供任何 token' }]);
    return void (process.exitCode = 2);
  }

  const rotated = {};
  const results = [];
  for (const n of names) results.push(await runProfile(cmd, n, rotated));
  if (cmd === 'claim') {
    if (Object.keys(rotated).length) {
      try { mkdirSync(path.dirname(REFRESHED_FILE), { recursive: true }); writeFileSync(REFRESHED_FILE, JSON.stringify(rotated, null, 2)); } catch {}
      log({ cmd: 'refresh', wrote: REFRESHED_FILE, keys: Object.keys(rotated) });
    }
    const s = writeSummary(results);
    log({ cmd: 'summary', ok: s.ok, skipped: s.skipped, failed: s.failed });
  }
  process.exitCode = exitCodeFor(results);
}
main();
