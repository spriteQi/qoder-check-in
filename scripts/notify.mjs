#!/usr/bin/env node
// 邮件通知：读取 data/result.json（qoder-checkin.mjs claim 产出），通过 SMTP 发送签到结果汇总。
// 配置来源：单个 Secret/env `MAIL_CONFIG`（多行 KEY=VALUE），也可用同名独立 env 覆盖单项；
// 缺 SMTP_HOST 或 MAIL_TO 时静默跳过（本地场景不需要邮件）。
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const RESULT_FILE = process.env.QODER_RESULT_FILE || path.join(REPO_ROOT, 'data', 'result.json');
const WRITEBACK_FILE = process.env.QODER_WRITEBACK_FILE || path.join(REPO_ROOT, 'data', 'writeback.txt');

const MAIL_CONFIG = (() => {
  const cfg = {};
  for (const line of (process.env.MAIL_CONFIG || '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const m = t.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
    if (m) cfg[m[1]] = m[2].trim();
  }
  return cfg;
})();
const conf = k => process.env[k] || MAIL_CONFIG[k] || '';

const SMTP_HOST = conf('SMTP_HOST');
const SMTP_PORT = Number(conf('SMTP_PORT') || 465);
const SMTP_SECURE = (conf('SMTP_SECURE') || String(SMTP_PORT === 465)) !== 'false';
const SMTP_USER = conf('SMTP_USER');
const SMTP_PASS = conf('SMTP_PASS');
const MAIL_TO = conf('MAIL_TO').split(',').map(s => s.trim()).filter(Boolean);
const MAIL_FROM = conf('MAIL_FROM') || SMTP_USER;

function loadResults() {
  if (!existsSync(RESULT_FILE)) return { summary: null, note: `缺少结果文件 ${RESULT_FILE}` };
  try { return { summary: JSON.parse(readFileSync(RESULT_FILE, 'utf8')) }; }
  catch (e) { return { summary: null, note: `结果文件解析失败：${e.message}` }; }
}

const RESULT_LABEL = {
  OK: '签到成功',
  ALREADY_CLAIMED: '今日已领（幂等跳过）',
  SKIPPED: '未配置该端，已跳过',
  AUTH_FAIL: '凭据获取失败',
  TOKEN_EXPIRED: 'token 已过期',
  FAIL: '接口返回失败',
  API_ERROR: '网络/接口异常',
};

function esc(s) {
  return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function detailOf(r) {
  const d = r.detail ?? r.reason ?? '-';
  if (typeof d === 'object' && d) return `${d.code ?? ''} ${d.message ?? ''}`.trim() || JSON.stringify(d).slice(0, 160);
  return String(d).slice(0, 160);
}

function buildMail(summary) {
  const results = summary?.results ?? [];
  const day = (summary?.ts ?? new Date().toISOString()).slice(0, 10);
  const failed = results.filter(r => ['AUTH_FAIL', 'TOKEN_EXPIRED', 'FAIL', 'API_ERROR'].includes(r.result));
  const refreshed = results.filter(r => r.refresh?.ok || r.refreshFail);
  const statusIcon = r => (['OK', 'ALREADY_CLAIMED'].includes(r.result) ? '✅' : r.result === 'SKIPPED' ? '⏭️' : '❌');
  const days = n => (n == null ? '-' : `${n} 天`);
  const subject = `[Qoder签到] ${day} ${failed.length ? `失败 ${failed.length}` : '全部完成'}（成功 ${summary?.ok ?? 0} / 跳过 ${summary?.skipped ?? 0} / 失败 ${failed.length}${refreshed.length ? ` / 续签 ${refreshed.length}` : ''}）`;

  const rows = results.map(r => `<tr>
      <td>${esc(r.label ?? r.profile)}</td>
      <td>${statusIcon(r)} ${esc(RESULT_LABEL[r.result] ?? r.result)}</td>
      <td>${esc(r.http ?? '-')}</td>
      <td>${esc(days(r.tokenDaysLeft))}${r.refreshTokenDaysLeft != null ? `（续签令牌 ${esc(days(r.refreshTokenDaysLeft))}）` : ''}${
        r.refresh?.ok ? `<br>🔄 ${esc(r.refresh.note)}` : r.refresh ? `<br>🔄 续签失败：${esc(r.refresh.reason)}` : r.refreshFail ? `<br>🔄 续签失败：${esc(r.refreshFail)}` : ''}</td>
      <td>${esc(detailOf(r))}</td>
    </tr>`).join('');
  const html = `<h3>Qoder 每日签到结果（${esc(day)}）</h3>
    <table border="1" cellspacing="0" cellpadding="6">
      <tr><th>端</th><th>结果</th><th>HTTP</th><th>剩余有效期 / 续签</th><th>详情</th></tr>
      ${rows || '<tr><td colspan="5">无结果</td></tr>'}
    </table>
    <p>说明：token 剩余不足 3 天时脚本会自动调用 deviceToken/refresh 续签；续签会轮换 refreshToken，CI 环境通过 refreshed.json + gh secret set 自动回写 Secrets，无需手动处理。</p>
    <p style="color:#888;font-size:12px">由 GitHub Actions / qoder-checkin 自动发送。</p>`;
  const text = results.map(r => [
    `${r.label}: ${RESULT_LABEL[r.result] ?? r.result}${r.http ? ` (HTTP ${r.http})` : ''}`,
    r.tokenDaysLeft != null ? ` token 剩余 ${r.tokenDaysLeft} 天` : '',
    r.refresh?.ok ? ` | 🔄 ${r.refresh.note}` : r.refresh ? ` | 🔄 续签失败：${r.refresh.reason}` : r.refreshFail ? ` | 🔄 续签失败：${r.refreshFail}` : '',
    r.detail ? ` ${detailOf(r)}` : '',
  ].join('')).join('\n');
  return { subject, html, text: text || subject };
}

async function main() {
  if (!SMTP_HOST || !MAIL_TO.length) {
    console.log('未配置 MAIL_CONFIG（需含 SMTP_HOST 与 MAIL_TO），跳过邮件通知');
    return;
  }
  let { summary, note } = loadResults();
  if (!summary) {
    console.log(note);
    // 没有结果文件也发一封告警邮件，避免 CI 静默失败
    summary = {
      ts: new Date().toISOString(),
      results: [{ profile: 'runner', label: '执行器', result: 'API_ERROR', reason: note }],
      ok: 0, skipped: 0, failed: 1,
    };
  }
  let nodemailer;
  try { nodemailer = (await import('nodemailer')).default; }
  catch { console.error('缺少依赖 nodemailer，请先 npm install'); process.exit(1); }

  const mail = buildMail(summary);
  let writeback = '';
  try { if (existsSync(WRITEBACK_FILE)) writeback = readFileSync(WRITEBACK_FILE, 'utf8').trim(); } catch {}
  if (writeback) {
    mail.html += `<p>Secrets 回写状态：<br>${writeback.split('\n').map(esc).join('<br>')}</p>`;
    mail.text += `\nSecrets 回写状态：\n${writeback}`;
  }
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
  });
  await transporter.sendMail({ from: MAIL_FROM, to: MAIL_TO.join(','), subject: mail.subject, text: mail.text, html: mail.html });
  console.log(`✓ 结果邮件已发送至 ${MAIL_TO.join(', ')}`);
}
main().catch(e => { console.error('邮件通知失败:', e.message); process.exit(1); });
