/* JSLeakWatch 控制台前端
   说明: 图标为 lucide (ISC) 的路径数据, 内联以避免外部 CDN 依赖。 */

const SVG_ATTRS = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';

const ICONS = {
  dashboard: '<rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18z"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
  filecode: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="m10 13-2 2 2 2"/><path d="m14 17 2-2-2-2"/>',
  sliders: '<path d="M4 6h10"/><path d="M18 6h2"/><path d="M4 12h4"/><path d="M12 12h8"/><path d="M4 18h12"/><path d="M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
  list: '<path d="M8 6h13"/><path d="M8 12h13"/><path d="M8 18h13"/><path d="M3 6h.01"/><path d="M3 12h.01"/><path d="M3 18h.01"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
  x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
  plus: '<path d="M12 5v14"/><path d="M5 12h14"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 4v5h-5"/>',
  play: '<path d="m6 4 14 8-14 8z"/>',
  trash: '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/>',
  check: '<path d="m20 6-11 11-5-5"/>',
  download: '<path d="M12 3v12"/><path d="m7 11 5 5 5-5"/><path d="M5 21h14"/>',
  alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  zap: '<path d="M13 2 3 14h8l-1 8 10-12h-8z"/>',
  activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 8 3 8H3s3-1 3-8"/><path d="M10.3 21a2 2 0 0 0 3.4 0"/>',
  send: '<path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4z"/>',
  folder: '<path d="M4 20h16a1 1 0 0 0 1-1V8a1 1 0 0 0-1-1h-7l-2-2H4a1 1 0 0 0-1 1v13a1 1 0 0 0 1 1z"/>',
  layers: '<path d="m12 2 9 5-9 5-9-5 9-5z"/><path d="m3 12 9 5 9-5"/><path d="m3 17 9 5 9-5"/>',
  external: '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5"/>',
  copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/>',
  chevron: '<path d="m9 18 6-6-6-6"/>',
  pause: '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>',
  plug: '<path d="M9 2v6"/><path d="M15 2v6"/><path d="M6 8h12v3a6 6 0 0 1-12 0z"/><path d="M12 17v5"/>',
  filter: '<path d="M3 5h18l-7 8v6l-4 2v-8z"/>',
  upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/>',
};

function icon(name, size) {
  const d = ICONS[name] || ICONS.alert;
  const s = size ? ` width="${size}" height="${size}"` : '';
  return `<svg ${SVG_ATTRS}${s}>${d}</svg>`;
}

/* ------------------------------------------------------------------ 常量 */

const SEVERITY = {
  critical: { label: '严重', order: 4 },
  high: { label: '高危', order: 3 },
  medium: { label: '中危', order: 2 },
  low: { label: '低危', order: 1 },
  info: { label: '提示', order: 0 },
};
const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#e0b012', low: '#4d8cf5', info: '#64748b' };

const STATUS = {
  new: '待确认', open: '已确认', false_positive: '误报', resolved: '已失效', ignored: '已忽略',
};
const STATUS_TAG = { new: 'tag-err', open: 'tag-warn', false_positive: '', resolved: 'tag-ok', ignored: '' };

const VERDICT = {
  real: { label: '真凭证', cls: 'chip-critical' },
  fake: { label: '误报', cls: 'chip-info' },
  public: { label: '公开密钥', cls: 'chip-low' },
  uncertain: { label: '待人工确认', cls: 'chip-medium' },
};

const NAV = [
  { path: 'overview', label: '概览', icon: 'dashboard' },
  { path: 'targets', label: '监测站点', icon: 'globe' },
  { path: 'findings', label: '泄露发现', icon: 'shield' },
  { path: 'assets', label: 'JS 资产', icon: 'filecode' },
  { path: 'rules', label: '检测规则', icon: 'filter' },
  { path: 'settings', label: '系统设置', icon: 'sliders' },
];

const TITLES = {
  overview: ['概览', '持续监测总览与最近变化'],
  targets: ['监测站点', '按周期自动巡检的站点列表'],
  findings: ['泄露发现', '命中的硬编码凭证与复核状态'],
  assets: ['JS 资产', '已采集的脚本/映射文件清单'],
  rules: ['检测规则', '内置规则开关与外部规则导入'],
  settings: ['系统设置', '采集参数、告警通道与白名单'],
};

/* ------------------------------------------------------------------ 工具 */

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

function esc(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/* 字节数转成 MB 显示; 0 原样返回, 因为它表示"不限制"而不是"0 MB" */
function bytesToMb(bytes) {
  const n = Number(bytes || 0);
  return n ? Math.round((n / 1024 / 1024) * 100) / 100 : 0;
}

function fromNow(iso) {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const diff = Date.now() - t;
  const abs = Math.abs(diff);
  const units = [[86400000, '天'], [3600000, '小时'], [60000, '分钟'], [1000, '秒']];
  for (const [ms, name] of units) {
    if (abs >= ms) {
      const v = Math.floor(abs / ms);
      return diff >= 0 ? `${v} ${name}前` : `${v} ${name}后`;
    }
  }
  return '刚刚';
}

function sevChip(sev) {
  const s = SEVERITY[sev] ? sev : 'info';
  return `<span class="chip chip-${s}">${SEVERITY[s].label}</span>`;
}

function statusTag(status) {
  return `<span class="tag ${STATUS_TAG[status] || ''}">${STATUS[status] || status}</span>`;
}

function verdictChip(row) {
  if (!row.ai_verdict) return '<span class="muted">—</span>';
  const v = VERDICT[row.ai_verdict] || VERDICT.uncertain;
  const conf = row.ai_confidence ? ` ${Math.round(row.ai_confidence * 100)}%` : '';
  return `<span class="chip ${v.cls}" title="${esc(row.ai_reason || '')}">${v.label}${conf}</span>`;
}

function sourceTag(row) {
  const labels = (row.found_by || "").split(",").filter(Boolean);
  const external = labels.filter((item) => item !== 'builtin');
  if (!external.length) return '';
  const title = `发现来源: ${labels.join(' + ')}`;
  return `<span class="tag tag-run" title="${esc(title)}" style="margin-left:6px">+${esc(external.join(','))}</span>`;
}

/* 高误报来源的 AI 预筛提示条 */
function gatedBar(info, showGated) {
  if (!info) return '';
  const hidden = info.hidden || 0;
  const sources = info.sources || 0;
  const threshold = Math.round((state.cache.gateThreshold ?? 0.6) * 100);
  if (!hidden && !showGated) return '';
  return `<div style="display:flex;align-items:center;gap:9px;padding:8px 13px;border-bottom:1px solid var(--line-soft);background:#14181f;font-size:12.5px">
    <span class="tag tag-run">AI 预筛</span>
    ${hidden
      ? `<span class="muted">已隐藏 <b>${hidden}</b> 条来自 ${sources} 个高误报来源的发现（历史误报率 &gt; ${threshold}%），AI 判定通过后自动出现在列表里</span>`
      : '<span class="muted">当前显示全部（含未通过 AI 预筛的发现）</span>'}
    <div class="spacer" style="flex:1"></div>
    <button class="btn btn-sm" data-act="toggle-gated">${showGated ? '只看已确认' : '显示全部'}</button>
  </div>`;
}

function gateBarText(summary) {
  if (!summary) return '按来源的历史误报率决定是否预筛；样本不足的来源不会被闸掉。';
  const sources = summary.gated_sources || [];
  const fake = summary.hidden?.ai_fake ?? 0;
  if (!sources.length) {
    return fake ? `当前没有需要预筛的来源；另有 ${fake} 条已被 AI 判定为误报，默认不展示。`
                : '当前没有被预筛的来源（各来源误报率均在阈值以下）。';
  }
  const items = sources.map((s) => `${s.rule_id}（${s.judged} 次判定中 ${s.fake} 条误报）`).join('、');
  return `当前被预筛的来源：${items}。已隐藏 ${summary.hidden?.hidden ?? 0} 条（含 ${fake} 条 AI 判定为误报）。`;
}

async function api(path, options) {
  const opts = options || {};
  const method = (opts.method || 'GET').toUpperCase();
  // GET 幂等: 偶发的网络抖动/服务端短暂拥塞自动重试一次, 别让页面直接掉进"加载失败"
  const attempts = method === 'GET' ? 2 : 1;
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await apiOnce(path, opts);
    } catch (err) {
      lastError = err;
      if (attempt + 1 < attempts) await new Promise((r) => setTimeout(r, 400));
    }
  }
  throw lastError;
}

async function apiOnce(path, options) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (e) { /* ignore */ }
    throw new Error(detail);
  }
  if (res.status === 204) return null;
  return res.json();
}

/* 列表型接口统一入口: 有的返回数组, 有的返回 {total, items} —— 这里抹平差异,
   避免调用方拿到对象去 .map 报 "xxx.map is not a function"。 */
async function apiList(path, options) {
  const data = await api(path, options);
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.items)) return data.items;
  return [];
}

function toast(message, kind) {
  const el = document.createElement('div');
  el.className = 'toast' + (kind ? ' ' + kind : '');
  el.innerHTML = esc(message);
  $('#toasts').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .4s'; }, 3600);
  setTimeout(() => el.remove(), 4200);
}

/* 悬停说明气泡: 元素带 data-tip 时, 悬停就把它贴在元素下方显示(放不下就翻到上方)。
   用 fixed 定位, 所以不会把表格行撑开; 内容里的换行由 CSS 的 pre-line 保留。 */
function hideTip() {
  const box = $('#tipbox');
  if (!box || box.hidden) return;
  box.hidden = true;
  box.textContent = '';
}

function showTip(host) {
  const box = $('#tipbox');
  if (!box) return;
  box.textContent = host.dataset.tip;
  box.hidden = false;
  const r = host.getBoundingClientRect();
  const b = box.getBoundingClientRect();
  const left = Math.max(10, Math.min(r.left + r.width / 2 - b.width / 2, window.innerWidth - b.width - 10));
  let top = r.bottom + 8;
  if (top + b.height > window.innerHeight - 10) top = Math.max(10, r.top - b.height - 8);
  box.style.left = `${Math.round(left)}px`;
  box.style.top = `${Math.round(top)}px`;
}

document.addEventListener('mouseover', (event) => {
  const el = event.target.closest('[data-tip]');
  if (el && !el.contains(event.relatedTarget)) showTip(el);
});

document.addEventListener('mouseout', (event) => {
  const el = event.target.closest('[data-tip]');
  if (el && !el.contains(event.relatedTarget)) hideTip();
});

window.addEventListener('scroll', hideTip, true);

/* ------------------------------------------------------------------ 状态 */

const state = {
  hash: '',
  overview: null,
  live: null,
  filters: { severity: new Set(), status: 'new,open', target: '', rule: '', q: '', sort: 'recent', page: 0, ai: '', showGated: false },
  selected: new Set(),
  selectedTargets: new Set(),
  bulkBusy: false,
  targetsBulkAll: false,      // 批量操作作用于"当前筛选下全部站点", 而非仅勾选的 id
  cache: {},
};

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '') || 'overview';
  const [path, qs] = raw.split('?');
  const query = {};
  new URLSearchParams(qs || '').forEach((v, k) => { query[k] = v; });
  return { path: path || 'overview', query };
}

function goto(path, query) {
  const qs = query ? '?' + new URLSearchParams(query).toString() : '';
  location.hash = `#/${path}${qs}`;
}

/* ------------------------------------------------------------------ 图表 */

function barChart(series) {
  const w = 640, h = 150, padL = 26, padB = 20, padT = 10;
  const max = Math.max(1, ...series.map((d) => d.count));
  const innerW = w - padL - 6, innerH = h - padB - padT;
  const step = innerW / series.length;
  const bars = series.map((d, i) => {
    const bh = Math.max(1, Math.round((d.count / max) * innerH));
    const x = padL + i * step + step * 0.15;
    const bw = Math.max(2, step * 0.7);
    return `<rect class="bar" x="${x.toFixed(1)}" y="${(padT + innerH - bh).toFixed(1)}" width="${bw.toFixed(1)}" height="${bh}" rx="1.5"><title>${esc(d.date)}: ${d.count} 条</title></rect>`;
  }).join('');
  const grid = [0, 0.5, 1].map((f) => {
    const y = padT + innerH - f * innerH;
    return `<line class="axis" x1="${padL}" y1="${y}" x2="${w - 6}" y2="${y}"/>` +
      `<text class="lbl" x="4" y="${y + 3}">${Math.round(max * f)}</text>`;
  }).join('');
  const labels = series.map((d, i) => (i % 7 === 0 || i === series.length - 1)
    ? `<text class="lbl" x="${(padL + i * step + step / 2 - 12).toFixed(1)}" y="${h - 5}">${d.date.slice(5)}</text>`
    : '').join('');
  return `<svg class="chart" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="height:150px">${grid}${bars}${labels}</svg>`;
}

function donut(counts) {
  const entries = Object.keys(SEVERITY)
    .map((k) => ({ key: k, count: counts[k] || 0 }))
    .filter((e) => e.count > 0);
  const total = entries.reduce((acc, e) => acc + e.count, 0);
  const r = 42, c = 2 * Math.PI * r;
  let offset = 0;
  const arcs = entries.map((e) => {
    const len = (e.count / total) * c;
    const seg = `<circle cx="60" cy="60" r="${r}" fill="none" stroke="${SEV_COLOR[e.key]}" stroke-width="13"
      stroke-dasharray="${len.toFixed(2)} ${(c - len).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}"
      transform="rotate(-90 60 60)"><title>${SEVERITY[e.key].label}: ${e.count}</title></circle>`;
    offset += len;
    return seg;
  }).join('');
  const svg = `<svg viewBox="0 0 120 120" width="132" height="132">${total
    ? arcs
    : '<circle cx="60" cy="60" r="42" fill="none" stroke="#232a33" stroke-width="13"/>'}
    <text x="60" y="57" text-anchor="middle" fill="#e7ebf0" font-size="21" font-family="ui-monospace, monospace">${total}</text>
    <text x="60" y="73" text-anchor="middle" fill="#6c7787" font-size="10">待处理</text></svg>`;
  const legend = Object.keys(SEVERITY).map((k) => `
    <div class="legend-item"><span class="legend-swatch" style="background:${SEV_COLOR[k]}"></span>
    ${SEVERITY[k].label} <b>${counts[k] || 0}</b></div>`).join('');
  return `<div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap">${svg}<div>${legend}</div></div>`;
}

function severityBar(counts) {
  const total = Object.keys(SEVERITY).reduce((a, k) => a + (counts[k] || 0), 0);
  if (!total) return '<div class="sev-bar"></div>';
  return '<div class="sev-bar">' + Object.keys(SEVERITY).map((k) => {
    const v = counts[k] || 0;
    return v ? `<span style="width:${(v / total * 100).toFixed(1)}%;background:${SEV_COLOR[k]}"></span>` : '';
  }).join('') + '</div>';
}

/* ------------------------------------------------------------------ 概览 */

async function renderOverview() {
  const view = $('#view');
  const page = state.overviewPage || { recent: 0, targets: 0 };
  const per = 10;
  const query = `?recent_limit=${per}&recent_offset=${page.recent * per}`
    + `&targets_limit=${per}&targets_offset=${page.targets * per}`;
  const data = await api('/api/overview' + query);
  state.overview = data;
  const k = data.kpis;
  const kpis = [
    { label: '监测站点', value: `${k.targets_enabled}/${k.targets}`, foot: '启用 / 总数', tone: 'primary', ico: 'globe' },
    { label: '待处理发现', value: k.open_findings, foot: `${k.critical_open} 条中高危`, tone: k.critical_open ? 'high' : 'teal', ico: 'shield' },
    { label: '24 小时新增', value: k.new_24h, foot: `近 7 天 ${k.new_7d} 条`, tone: k.new_24h ? 'high' : 'teal', ico: 'zap' },
    { label: '24 小时扫描', value: k.scans_24h, foot: `平均 ${(k.avg_scan_ms / 1000).toFixed(1)} 秒`, tone: 'teal', ico: 'activity' },
  ];

  view.innerHTML = `
    <div class="grid kpis" style="margin-bottom:12px">
      ${kpis.map((x) => `
        <div class="kpi tone-${x.tone}">
          <div class="k-label">${icon(x.ico)}${esc(x.label)}</div>
          <div class="k-value">${esc(x.value)}</div>
          <div class="k-foot">${esc(x.foot)}</div>
        </div>`).join('')}
    </div>

    <div class="grid cols-2" style="margin-bottom:12px">
      <section class="card">
        <div class="card-head"><h2>近 30 天新增发现</h2><span class="sub">按首次发现时间统计</span></div>
        <div class="card-body">${barChart(data.timeline)}</div>
      </section>
      <section class="card">
        <div class="card-head"><h2>严重级别分布</h2><span class="sub">仅统计待处理</span></div>
        <div class="card-body">${donut(data.severity)}</div>
      </section>
    </div>

    <div class="grid cols-2">
      <section class="card">
        <div class="card-head">
          <h2>最近发现</h2>
          <span class="sub">${data.recent_total} 条待处理</span>
        </div>
        <div class="table-wrap">
          ${data.recent.length ? `<table>
            <thead><tr><th class="shrink">等级</th><th>规则</th><th>命中值</th><th>站点</th><th class="shrink">时间</th></tr></thead>
            <tbody>${data.recent.map((f) => `
              <tr class="clickable" data-act="open-finding" data-id="${f.id}">
                <td class="shrink">${sevChip(f.severity)}</td>
                <td>${esc(f.rule_name)}</td>
                <td><span class="val-mask">${esc(f.match_masked)}</span></td>
                <td class="muted">${esc(f.target_name || '')}</td>
                <td class="shrink muted nowrap">${fromNow(f.first_seen_at)}</td>
              </tr>`).join('')}</tbody></table>`
            : `<div class="empty">${icon('shield')}暂无待处理的泄露发现</div>`}
        </div>
        ${listPager('recent', page.recent, data.recent_total, data.recent.length, per, 'findings', '全部发现')}
      </section>

      <section class="card">
        <div class="card-head">
          <h2>站点健康度</h2>
          <span class="sub">${data.targets_total} 个站点</span>
        </div>
        <div class="table-wrap">
          ${data.targets.length ? `<table>
            <thead><tr><th>站点</th><th class="shrink">状态</th><th class="shrink">待处理</th><th class="shrink">下次</th></tr></thead>
            <tbody>${data.targets.map((t) => `
              <tr class="clickable" data-act="nav" data-to="findings" data-query="target=${t.id}">
                <td>
                  <div style="display:flex;flex-direction:column;gap:2px">
                    <span>${esc(t.name)}</span>
                    <span class="muted mono" style="font-size:11px">${esc(t.base_url)}</span>
                  </div>
                </td>
                <td class="shrink">${targetStatusTag(t)}</td>
                <td class="shrink">${t.open_count ? `<b style="color:#ffb877">${t.open_count}</b>` : '<span class="muted">0</span>'}</td>
                <td class="shrink muted nowrap" style="font-size:11.5px">${fromNow(t.next_scan_at)}</td>
              </tr>`).join('')}</tbody></table>`
            : `<div class="empty">${icon('globe')}还没有监测站点，去「监测站点」新增一个</div>`}
        </div>
        ${listPager('health', page.targets, data.targets_total, data.targets.length, per, 'targets', '管理站点')}
      </section>
    </div>

    ${data.top_rules.length ? `
    <section class="card" style="margin-top:12px">
      <div class="card-head"><h2>高频规则</h2><span class="sub">待处理发现中的规则排行</span></div>
      <div class="card-body" style="display:flex;flex-direction:column;gap:9px">
        ${data.top_rules.map((r) => {
          const max = data.top_rules[0].count || 1;
          return `<div style="display:grid;grid-template-columns:minmax(120px,1.6fr) minmax(80px,2fr) 40px;gap:12px;align-items:center">
            <div style="display:flex;gap:7px;align-items:center;min-width:0">
              ${sevChip(r.severity)}<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.rule_name)}</span>
            </div>
            <div class="bar-mini"><span style="width:${(r.count / max * 100).toFixed(1)}%"></span></div>
            <div class="mono muted" style="text-align:right">${r.count}</div>
          </div>`;
        }).join('')}
      </div>
    </section>` : ''}

    ${externalToolsCard(data.integrations)}
  `;
}

/* 列表分页条: block 决定翻页时重渲染哪一块, linkTo 可选（跳转到完整页面） */
function listPager(block, current, total, shown, per, linkTo, linkLabel) {
  const pages = Math.max(1, Math.ceil(total / per));
  return `<div class="pager">
    <span>第 ${current + 1} / ${pages} 页 · 共 ${total} 条，本页 ${shown}</span>
    <div class="spacer"></div>
    <button class="btn btn-sm" data-act="list-page" data-block="${block}" data-page="0" ${current === 0 ? 'disabled' : ''}>首页</button>
    <button class="btn btn-sm" data-act="list-page" data-block="${block}" data-page="${current - 1}" ${current === 0 ? 'disabled' : ''}>上一页</button>
    <button class="btn btn-sm" data-act="list-page" data-block="${block}" data-page="${current + 1}" ${current + 1 >= pages ? 'disabled' : ''}>下一页</button>
    ${linkTo ? `<button class="btn btn-sm" data-act="nav" data-to="${linkTo}">${linkLabel || '全部'}${icon('chevron', 12)}</button>` : ''}
  </div>`;
}

function targetStatusTag(t) {
  if (t.scanning) return '<span class="tag tag-run">扫描中</span>';
  if (t.queued) return '<span class="tag tag-run">排队中</span>';
  if (!t.enabled) return '<span class="tag">已暂停</span>';
  // 失败/部分成功把原因挂成悬停提示: 鼠标停在标签上就能看到这次扫描为什么没成
  const reason = (t.last_error || '').trim();
  const tip = reason ? ` data-tip="${esc(statusTip(t, reason))}"` : '';
  const mark = tip ? ' tag-tip' : '';
  if (t.last_status === 'failed') return `<span class="tag tag-err${mark}"${tip}>失败</span>`;
  if (t.last_status === 'partial') return `<span class="tag tag-warn${mark}"${tip}>部分成功</span>`;
  if (t.last_status === 'ok') return '<span class="tag tag-ok">正常</span>';
  return '<span class="tag">待扫描</span>';
}

/* 悬停提示的文案: 原因 + 连续失败次数 + 最近一次扫描时间 */
function statusTip(t, reason) {
  // 原始 last_error 可能是几十条资产错误用 "; " 拼起来的, 取前三条并去掉重复的主机名
  const parts = reason.split(/;\s*/).map((s) => {
    const line = s.trim();
    if (!line) return "";
    // "https://站点/路径.js: ConnectTimeout: " → "路径.js: ConnectTimeout:"; 入口页显示成"入口页面"
    const [loc, ...tail] = line.split(/: /);
    const path = loc.replace(/^https?:\/\/[^\s/]+/, "").replace(/\/$/, "");
    const label = path || "入口页面";
    return tail.length ? `${label}: ${tail.join(": ").trim()}` : label;
  }).filter(Boolean);
  const bits = parts.slice(0, 3);
  if (parts.length > bits.length) bits.push(`…… 另有 ${parts.length - bits.length} 条错误`);
  const failures = Number(t.consecutive_failures || 0);
  if (failures > 1) bits.push(`已连续失败 ${failures} 次`);
  if (t.last_scan_at) bits.push(`最近一次扫描 ${fmtTime(t.last_scan_at)}`);
  bits.push('可在站点详情里改入口地址或手动重试');
  return bits.join('\n');
}
function externalToolsCard(info) {
  if (!info) return '';
  const tools = Object.keys(info.external_tools || {});
  const ai = info.ai || {};
  const stats = info.analyzer_stats || {};
  return `
  <section class="card" style="margin-top:12px">
    <div class="card-head"><h2>可接入的开源工具</h2><span class="sub">在本机安装后自动识别</span></div>
    <div class="card-body" style="display:flex;flex-direction:column;gap:9px">
      <div class="list-row">
        <span class="grow"><b>AI 复核</b> <span class="muted">· 新发现误报判定、语义补漏、由样例反推规则</span></span>
        <span class="tag ${ai.enabled ? 'tag-ok' : ''}">${ai.enabled ? esc(ai.model || '已启用') : '未启用'}</span>
      </div>
      <div class="list-row">
        <span class="grow"><b>Katana</b> <span class="muted">· MIT · 采集阶段补充种子 (参数/表单/XHR/已知文件)</span></span>
        <span class="tag ${info.katana_available ? 'tag-ok' : ''}">${info.katana_available ? '已就绪' : '未安装'}</span>
      </div>
      ${Object.keys(stats).length ? `
      <div class="list-row">
        <span class="grow"><b>发现来源贡献</b>
          <div class="muted" style="font-size:11.5px;margin-top:3px">
            ${Object.entries(stats).map(([name, item]) => `${esc(name)} ${item.total} 条（独占 ${item.exclusive}）`).join(' · ')}
          </div>
        </span>
        <span class="tag${info.analyzers_run_in_scan ? ' tag-ok' : ''}">${info.analyzers_run_in_scan ? '并联中' : '仅内置'}</span>
      </div>` : ''}
      <div class="list-row">
        <span class="grow"><b>gitleaks</b> <span class="muted">· MIT · 规则库可直接导入, 命中片段可二次确认</span></span>
        <span class="tag ${tools.includes('gitleaks') ? 'tag-ok' : ''}">${tools.includes('gitleaks') ? '已检测到' : '未安装'}</span>
      </div>
      <div class="list-row">
        <span class="grow"><b>trufflehog</b> <span class="muted">· 凭据验证能力强, 可作为主动验证的扩展位</span></span>
        <span class="tag ${tools.includes('trufflehog') ? 'tag-ok' : ''}">${tools.includes('trufflehog') ? '已检测到' : '未安装'}</span>
      </div>
      <div class="muted" style="font-size:11.5px">规则导入入口见「检测规则」页, 支持 gitleaks 的 TOML 规则文件。</div>
    </div>
  </section>`;
}

/* ------------------------------------------------------------------ 站点 */

async function renderTargets() {
  let page = state.targetsPage || 0;
  const keyword = state.targetsQuery || '';
  const per = state.targetsPerPage || 25;
  const params = new URLSearchParams({ limit: String(per), offset: String(page * per) });
  if (keyword) params.set('q', keyword);
  const data = await api('/api/targets?' + params);
  const items = Array.isArray(data) ? data : (data.items || []);
  const total = data.total != null ? data.total : items.length;
  // 删掉最后一页上的全部站点后, 当前页会越界: 不回到最后一页的话, 界面会显示
  // "还没有监测站点", 让人以为整批都没了(实测踩过)
  const lastPage = Math.max(0, Math.ceil(total / per) - 1);
  if (page > lastPage) {
    state.targetsPage = lastPage;
    return renderTargets();
  }
  state.cache.targets = items;      // 编辑按钮要按 id 回查, 之前只有发现页缓存过
  const view = $('#view');
  view.innerHTML = `
    <section class="card">
      <div class="toolbar">
        <span class="muted">共 ${total} 个站点${keyword ? `（筛选: ${esc(keyword)}）` : ''}</span>
        <div class="search" style="width:200px">${icon('search')}
          <input type="text" id="t-q" placeholder="按名称 / 地址筛选" value="${esc(keyword)}">
        </div>
        <div class="spacer"></div>
        <button class="btn btn-sm" data-act="bulk-add-target">${icon('upload', 13)}批量新增</button>
        <button class="btn btn-sm" data-act="scan-all">${icon('play', 13)}全部立即扫描</button>
        <button class="btn btn-sm" data-act="all-sites-state" data-value="disable">${icon('pause', 13)}全部暂停</button>
        <button class="btn btn-sm" data-act="all-sites-state" data-value="enable">${icon('play', 13)}全部恢复</button>
      </div>
      ${bulkBar(items, total)}
      <div class="table-wrap">
        ${items.length ? `<table>
          <thead><tr>
            <th class="shrink"><input type="checkbox" class="check" data-act="target-select-all" ${items.length && items.every((t) => state.selectedTargets.has(t.id)) ? 'checked' : ''}></th>
            <th>站点</th><th class="shrink">状态</th><th class="shrink">周期</th>
            <th class="shrink">待处理</th><th class="shrink">资产</th>
            <th class="shrink">上次扫描</th><th class="shrink">下次扫描</th><th class="shrink">操作</th>
          </tr></thead>
          <tbody>${items.map((t) => `
            <tr>
              <td class="shrink"><input type="checkbox" class="check" data-act="target-select" data-id="${t.id}" ${state.selectedTargets.has(t.id) ? 'checked' : ''}></td>
              <td>
                <div style="display:flex;flex-direction:column;gap:2px">
                  <span>${esc(t.name)}</span>
                  <a class="muted mono" style="font-size:11px" href="${esc(t.base_url)}" target="_blank" rel="noreferrer">${esc(t.base_url)}</a>
                </div>
              </td>
              <td class="shrink">${targetStatusTag(t)}</td>
              <td class="shrink muted">${fmtInterval(t.interval_minutes)}</td>
              <td class="shrink">${t.open_count ? `<b style="color:#ffb877">${t.open_count}</b>` : '<span class="muted">0</span>'}</td>
              <td class="shrink muted mono">${t.asset_count}</td>
              <td class="shrink muted nowrap" style="font-size:11.5px">${fromNow(t.last_scan_at)}</td>
              <td class="shrink muted nowrap" style="font-size:11.5px">${t.enabled ? fromNow(t.next_scan_at) : '—'}</td>
              <td class="shrink nowrap">
                <button class="btn btn-icon btn-sm" title="立即扫描" data-act="scan" data-id="${t.id}" ${t.scanning ? 'disabled' : ''}>${icon('refresh', 13)}</button>
                <button class="btn btn-icon btn-sm" title="编辑" data-act="edit-target" data-id="${t.id}">${icon('sliders', 13)}</button>
                <button class="btn btn-icon btn-sm" title="${t.enabled ? '暂停监测' : '恢复监测'}" data-act="toggle-target" data-id="${t.id}" data-enabled="${t.enabled ? 1 : 0}">${icon(t.enabled ? 'pause' : 'play', 13)}</button>
                <button class="btn btn-icon btn-sm btn-danger" title="删除" data-act="del-target" data-id="${t.id}" data-name="${esc(t.name)}">${icon('trash', 13)}</button>
              </td>
            </tr>`).join('')}</tbody></table>`
          : `<div class="empty">${icon('globe')}还没有监测站点。点击「新增站点」开始持续监测。</div>`}
      </div>
      ${items.length ? listPager('sites', page, total, items.length, per) : ''}
    </section>`;
  const search = $('#t-q');
  let timer = null;
  search.oninput = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      state.targetsQuery = search.value.trim();
      state.targetsPage = 0;
      clearTargetSelection();
      renderTargets();
    }, 300);
  };
}

/* 巡检周期: 库里统一存分钟, 界面按 分钟/小时/天/周 输入, 大周期默认落到天与周 */
const INTERVAL_UNITS = [
  { key: 'minute', label: '分钟', minutes: 1 },
  { key: 'hour', label: '小时', minutes: 60 },
  { key: 'day', label: '天', minutes: 1440 },
  { key: 'week', label: '周', minutes: 10080 },
];
const INTERVAL_LABEL = { minute: '分钟', hour: '小时', day: '天', week: '周' };

/* 1440 → 1 天, 10080 → 1 周, 90 → 90 分钟: 取最大且能整除的那个单位 */
function splitInterval(minutes) {
  const value = Math.max(1, Math.round(Number(minutes) || 0));
  for (const unit of [...INTERVAL_UNITS].reverse()) {
    if (value >= unit.minutes && value % unit.minutes === 0) {
      return { value: value / unit.minutes, unit: unit.key };
    }
  }
  return { value, unit: 'minute' };
}

function fmtInterval(minutes) {
  const { value, unit } = splitInterval(minutes);
  return `${value} ${INTERVAL_LABEL[unit]}`;
}

function intervalField(id, minutes, label = '巡检周期', hint = '') {
  const { value, unit } = splitInterval(minutes);
  return `<label class="field">${label}
    <div class="interval-row">
      <input type="number" id="${id}" min="1" max="43200" value="${value}">
      <select id="${id}-unit">
        ${INTERVAL_UNITS.map((u) => `<option value="${u.key}"${u.key === unit ? ' selected' : ''}>${u.label}</option>`).join('')}
      </select>
    </div>
    ${hint ? `<span class="field-hint">${hint}</span>` : ''}
  </label>`;
}

function readInterval(id) {
  const value = Math.max(1, Number($('#' + id).value || 1));
  const unit = $('#' + id + '-unit').value;
  const factor = (INTERVAL_UNITS.find((u) => u.key === unit) || INTERVAL_UNITS[0]).minutes;
  return Math.min(43200, Math.round(value * factor));   // 上限 30 天, 与后端一致
}

/* 站点批量操作条: 有选中项时才出现 */
function clearTargetSelection() {
  state.selectedTargets.clear();
  state.targetsBulkAll = false;
}

function bulkBar(items, total) {
  const count = state.selectedTargets.size;
  if (!count) {
    return `<div class="toolbar" style="padding-top:0">
      <span class="field-hint">勾选左侧复选框可批量启用 / 暂停 / 改周期 / 立即扫描 / 删除</span>
    </div>`;
  }
  const disabled = state.bulkBusy ? 'disabled' : '';
  const scope = state.targetsBulkAll
    ? `已选当前筛选下全部 ${total} 个站点`
    : `已选 ${count} 个站点`;
  // 本页全选 + 还有别的页 或 有筛选词时, 才提示"选择全部匹配"
  const pageAll = items.length && items.every((t) => state.selectedTargets.has(t.id));
  let scopeSwitch = '';
  if (state.targetsBulkAll) {
    scopeSwitch = `<button class="btn btn-sm btn-ghost" data-act="targets-select-page" ${disabled}>只选本页</button>`;
  } else if (pageAll && total > items.length) {
    scopeSwitch = `<button class="btn btn-sm btn-ghost" data-act="targets-select-all-matching" ${disabled}>选择全部 ${total} 个</button>`;
  }
  return `<div class="toolbar" style="background:#1b2432;border-bottom-color:#2b3a4e">
    <b>${scope}</b>
    ${scopeSwitch}
    <div class="spacer"></div>
    <button class="btn btn-sm" data-act="targets-bulk" data-op="scan" ${disabled}>${icon('play', 13)}立即扫描</button>
    <button class="btn btn-sm" data-act="targets-bulk" data-op="enable" ${disabled}>恢复监测</button>
    <button class="btn btn-sm" data-act="targets-bulk" data-op="disable" ${disabled}>暂停监测</button>
    <button class="btn btn-sm" data-act="targets-bulk" data-op="interval" ${disabled}>${icon('sliders', 13)}改周期</button>
    <button class="btn btn-sm btn-danger" data-act="targets-bulk" data-op="delete" ${disabled}>${icon('trash', 13)}删除</button>
    <button class="btn btn-sm btn-ghost" data-act="targets-clear" ${disabled}>取消选择</button>
  </div>`;
}

async function runBulk(op, extra) {
  const ids = Array.from(state.selectedTargets);
  if (!ids.length) return;
  const scopeText = state.targetsBulkAll ? '当前筛选下的全部' : `选中的 ${ids.length} 个`;
  if (op === 'delete' && !window.confirm(`确认删除${scopeText}站点？其发现与资产记录会一并删除。`)) return;
  state.bulkBusy = true;
  try {
    const body = { ids, action: op, ...(extra || {}) };
    if (op === 'interval' && extra && extra.interval_minutes) state.lastInterval = extra.interval_minutes;
    if (state.targetsBulkAll) {
      body.all_matching = true;
      body.q = state.targetsQuery || '';
    }
    const r = await api('/api/targets/bulk', { method: 'POST', body: JSON.stringify(body) });
    const label = { scan: '已排入扫描队列', enable: '已恢复监测', disable: '已暂停监测',
                    delete: '已删除', interval: '已更新巡检周期' }[op] || '已完成';
    toast(`${label} · ${r.affected} 个站点`, 'ok');
    if (op !== 'scan') clearTargetSelection();
  } catch (err) {
    toast('批量操作失败: ' + err.message, 'err');
  }
  state.bulkBusy = false;
  renderTargets();
}

/* 批量新增站点: 粘贴域名清单或选一个 txt, 统一套用周期/深度/资产上限 */
function openBulkAddModal() {
  $('#modal').innerHTML = `
    <div class="modal-head">
      <h2>批量新增站点</h2>
      <button class="btn btn-ghost btn-icon btn-sm" data-act="close-modal">${icon('x', 14)}</button>
    </div>
    <div class="modal-body">
      <label class="field">站点清单
        <textarea id="bulk-urls" rows="8" placeholder="每行一个, 支持域名或完整 URL&#10;example.com&#10;https://a.example.com/app&#10;# 以 # 开头的行会被忽略"></textarea>
        <span class="field-hint">自动补 https://；<b>同一主机只建一条</b>，批内重复与已存在的都会跳过并在结果里列出来；单次最多 5000 个。</span>
      </label>
      <div>
        <input type="file" id="bulk-file" data-act="bulk-add-file" accept=".txt,.csv,text/plain" hidden>
        <button class="btn btn-sm" data-act="bulk-add-pick">${icon('folder', 13)}从 txt 文件读取</button>
        <span class="field-hint" id="bulk-file-name" style="margin-left:9px"></span>
      </div>
      <div class="form-row-3">
        ${intervalField('bulk-add-interval', 1440, '巡检周期')}
        <label class="field">页面递归深度
          <input type="number" id="bulk-add-depth" min="0" max="4" value="1">
        </label>
        <label class="field">资产上限
          <input type="number" id="bulk-add-assets" min="1" max="5000" value="60">
        </label>
      </div>
      <div style="display:flex;gap:18px;flex-wrap:wrap">
        <label class="switch"><input type="checkbox" id="bulk-add-enabled" checked><span class="track"></span>创建后立即开始监测</label>
        <label class="switch"><input type="checkbox" id="bulk-add-probe"><span class="track"></span>探测常见配置入口</label>
      </div>
      <div class="field-hint">请只对自己拥有或已获得书面授权的站点开启监测。</div>
      <div id="bulk-add-result"></div>
    </div>
    <div class="modal-foot">
      <button class="btn" data-act="close-modal">取消</button>
      <button class="btn btn-primary" data-act="bulk-add-save">导入并创建</button>
    </div>`;
  $('#modal-scrim').hidden = false;
  setTimeout(() => { const el = $('#bulk-urls'); if (el) el.focus(); }, 30);
}

function bulkAddSummary(r) {
  const label = { created: '新增', duplicate: '重复', skipped: '已存在', invalid: '无效', failed: '失败' };
  const parts = ['created', 'duplicate', 'skipped', 'invalid', 'failed']
    .filter((key) => key !== 'failed' || r.failed)
    .map((key) => {
      const tone = key === 'created' && r[key] ? ' tag-ok' : (key === 'failed' ? ' tag-err' : '');
      return `<span class="tag${tone}">${label[key]} ${r[key]}</span>`;
    })
    .join(' ');
  const detail = [
    ...(r.failed_detail || []).map((d) => ({ text: d.url, reason: `添加失败 — ${d.reason}` })),
    ...(r.duplicate_detail || []).map((d) => ({ text: d.line, reason: `与「${d.same_as}」同一主机，只保留一条` })),
    ...(r.skipped_detail || []).map((d) => ({ text: d.url, reason: d.reason })),
    ...(r.invalid_detail || []).map((d) => ({ text: d.line, reason: d.reason })),
  ];
  const total = (r.created || 0) + (r.duplicate || 0) + (r.skipped || 0) + (r.invalid || 0) + (r.failed || 0);
  return `
    <div class="list-row" style="align-items:flex-start;gap:10px;padding-top:4px">
      <span class="grow"><b>本次导入结果</b> <span class="muted">· 共处理 ${total} 条，失败/重复/已存在/无效最多各列 50 条${r.ignored ? `；另有 ${r.ignored} 行空行或注释已忽略` : ''}</span></span>
      <span class="nowrap">${parts}</span>
    </div>
    ${detail.length ? `<div class="mono muted" style="font-size:11.5px;max-height:170px;overflow:auto">
      ${detail.map((d) => `${esc(d.text)} — ${esc(d.reason)}`).join('<br>')}</div>` : ''}`;
}

async function runBulkAdd() {
  const text = $('#bulk-urls').value.trim();
  if (!text) { toast('请先粘贴或读取站点清单', 'err'); return; }
  const btn = $('[data-act="bulk-add-save"]');
  if (btn) btn.disabled = true;
  try {
    const r = await api('/api/targets/import', {
      method: 'POST',
      body: JSON.stringify({
        text,
        interval_minutes: readInterval('bulk-add-interval'),
        max_depth: Number($('#bulk-add-depth').value || 1),
        max_assets: Number($('#bulk-add-assets').value || 60),
        enabled: $('#bulk-add-enabled').checked,
        probe_common_config: $('#bulk-add-probe').checked,
      }),
    });
    $('#bulk-add-result').innerHTML = bulkAddSummary(r);
    const extra = [r.duplicate ? `重复 ${r.duplicate} 行` : '', r.skipped ? `已存在 ${r.skipped} 个` : '',
                   r.invalid ? `无效 ${r.invalid} 行` : '', r.failed ? `失败 ${r.failed} 个` : '']
      .filter(Boolean).join('，');
    toast(`已新增 ${r.created} 个站点${extra ? '，' + extra : ''}`,
          r.failed || !r.created ? 'err' : 'ok');
    const foot = $('.modal-foot');
    if (foot && !foot.dataset.done) {
      foot.dataset.done = '1';
      foot.innerHTML = `<button class="btn btn-primary" data-act="close-modal">完成</button>`;
    }
    refresh();
  } catch (err) {
    toast('导入失败: ' + err.message, 'err');
  } finally {
    const b = $('[data-act="bulk-add-save"]');
    if (b) b.disabled = false;
  }
}

async function readBulkFile(input) {
  const file = input.files && input.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const box = $('#bulk-urls');
    box.value = box.value.trim() ? box.value.trim() + '\n' + text.trim() : text.trim();
    const lines = text.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#')).length;
    $('#bulk-file-name').textContent = `${file.name} · ${lines} 行`;
    toast('已读入文件内容, 确认后点「导入并创建」', 'ok');
  } catch (err) {
    toast('读取文件失败: ' + err.message, 'err');
  } finally {
    input.value = '';
  }
}

function openIntervalModal() {
  $('#modal').innerHTML = `
    <div class="modal-head"><h2>批量修改巡检周期</h2>
      <button class="btn btn-ghost btn-icon btn-sm" data-act="close-modal">${icon('x', 14)}</button></div>
    <div class="modal-body">
      ${intervalField('bulk-interval', state.lastInterval || 1440, '巡检周期',
                      '常用：1 天、3 天、1 周；需要更密集的巡检可以切到小时。')}
      <div class="field-hint">将对已选的 ${state.selectedTargets.size} 个站点生效。</div>
    </div>
    <div class="modal-foot">
      <button class="btn" data-act="close-modal">取消</button>
      <button class="btn btn-primary" data-act="targets-bulk-save-interval">确定</button>
    </div>`;
  $('#modal-scrim').hidden = false;
}

function targetForm(t) {
  const isEdit = !!t;
  const data = t || { name: '', base_url: '', interval_minutes: 1440, scope: 'same-origin', max_depth: 2, max_assets: 400, include_sourcemaps: 1, probe_common_config: 1, notes: '' };
  return `
    <div class="modal-head">
      <h2>${isEdit ? '编辑站点' : '新增监测站点'}</h2>
      <button class="btn btn-ghost btn-icon btn-sm" data-act="close-modal">${icon('x', 14)}</button>
    </div>
    <div class="modal-body">
      <label class="field">站点名称
        <input type="text" id="f-name" value="${esc(data.name)}" placeholder="留空则使用域名">
      </label>
      <label class="field">入口地址
        <input type="text" id="f-url" value="${esc(data.base_url)}" placeholder="https://example.com/">
        <span class="field-hint">会从该页面出发, 递归发现脚本、按需加载 chunk 与 sourcemap。</span>
      </label>
      <div class="form-row">
        ${intervalField('f-interval', data.interval_minutes, '巡检周期',
                        '按天或周设置最常见；周期越短采集越频繁。')}
        <label class="field">采集范围
          <select id="f-scope">
            <option value="same-origin"${data.scope === 'same-origin' ? ' selected' : ''}>同源 (推荐)</option>
            <option value="same-host"${data.scope === 'same-host' ? ' selected' : ''}>同主机 (允许跨端口/协议)</option>
            <option value="any"${data.scope === 'any' ? ' selected' : ''}>任意域名</option>
          </select>
        </label>
      </div>
      <div class="form-row-3">
        <label class="field">页面递归深度
          <input type="number" id="f-depth" min="0" max="4" value="${esc(data.max_depth)}">
        </label>
        <label class="field">资产上限
          <input type="number" id="f-assets" min="1" max="5000" value="${esc(data.max_assets)}">
        </label>
        <label class="field">备注
          <input type="text" id="f-notes" value="${esc(data.notes || '')}">
        </label>
      </div>
      <div style="display:flex;gap:18px;flex-wrap:wrap">
        <label class="switch"><input type="checkbox" id="f-maps" ${data.include_sourcemaps ? 'checked' : ''}><span class="track"></span>抓取 sourcemap</label>
        <label class="switch"><input type="checkbox" id="f-probe" ${data.probe_common_config ? 'checked' : ''}><span class="track"></span>探测常见配置入口</label>
        ${isEdit ? `<label class="switch"><input type="checkbox" id="f-enabled" ${data.enabled ? 'checked' : ''}><span class="track"></span>启用监测</label>` : ''}
      </div>
      <div class="field-hint">请只对自己拥有或已获得书面授权的站点开启监测。</div>
    </div>
    <div class="modal-foot">
      <button class="btn" data-act="close-modal">取消</button>
      <button class="btn btn-primary" data-act="save-target" data-id="${isEdit ? t.id : ''}">${isEdit ? '保存' : '创建并扫描'}</button>
    </div>`;
}

function openModal(html) {
  $('#modal').innerHTML = html;
  $('#modal-scrim').hidden = false;
}

function openTargetModal(t) {
  openModal(targetForm(t));
  setTimeout(() => { const el = $('#f-name'); if (el) el.focus(); }, 30);
}

async function saveTarget(id) {
  const payload = {
    name: $('#f-name').value.trim(),
    base_url: $('#f-url').value.trim(),
    interval_minutes: readInterval('f-interval'),
    scope: $('#f-scope').value,
    max_depth: Number($('#f-depth').value || 2),
    max_assets: Number($('#f-assets').value || 400),
    notes: $('#f-notes').value,
    include_sourcemaps: $('#f-maps').checked,
    probe_common_config: $('#f-probe').checked,
  };
  if ($('#f-enabled')) payload.enabled = $('#f-enabled').checked;
  if (!payload.base_url) { toast('请填写入口地址', 'err'); return; }
  try {
    let target;
    if (id) {
      target = await api(`/api/targets/${id}`, { method: 'PATCH', body: JSON.stringify(payload) });
      toast('站点已更新', 'ok');
    } else {
      target = await api('/api/targets', { method: 'POST', body: JSON.stringify(payload) });
      toast('站点已创建，开始首次扫描', 'ok');
    }
    closeModal();
    refresh();
    if (!id) {
      await api(`/api/targets/${target.id}/scan?full=true`, { method: 'POST' }).catch(() => {});
      refresh();
    }
  } catch (err) {
    toast('保存失败: ' + err.message, 'err');
  }
}

/* ------------------------------------------------------------------ 发现 */

function findingsQuery() {
  const f = state.filters;
  const params = new URLSearchParams();
  params.set('limit', '50');
  params.set('offset', String(f.page * 50));
  params.set('sort', f.sort);
  if (f.showGated) params.set('include_gated', '1');
  if (f.status) params.set('status', f.status);
  if (f.severity.size) params.set('severity', Array.from(f.severity).join(','));
  if (f.target) params.set('target_id', f.target);
  if (f.rule) params.set('rule_id', f.rule);
  if (f.ai) params.set('ai_verdict', f.ai);
  if (f.q) params.set('q', f.q);
  return params;
}

async function renderFindings() {
  const q = parseHash().query;
  if (q.target && state.filters.target !== q.target) { state.filters.target = q.target; state.filters.page = 0; }
  if (q.rule && state.filters.rule !== q.rule) { state.filters.rule = q.rule; state.filters.page = 0; }
  if (q.severity) { state.filters.severity = new Set(q.severity.split(',')); }
  if (q.status !== undefined && q.status !== null && state.hash !== location.hash) state.filters.status = q.status;

  const [data, targetData, rules] = await Promise.all([
    api('/api/findings?' + findingsQuery().toString()),
    api('/api/targets?limit=0'),
    api('/api/rules'),
  ]);
  const targets = targetData.items || [];
  state.cache.targets = targets;
  state.cache.rules = rules.items;

  const f = state.filters;
  // 删完最后一页的发现后同样会越界, 回退到最后一页
  const lastPage = Math.max(0, Math.ceil((data.total || 0) / 50) - 1);
  if (f.page > lastPage) {
    f.page = lastPage;
    return renderFindings();
  }
  const statuses = [
    { key: 'new,open', label: '待处理' },
    { key: 'new', label: '待确认' },
    { key: 'open', label: '已确认' },
    { key: 'resolved', label: '已失效' },
    { key: 'false_positive', label: '误报' },
    { key: '', label: '全部' },
  ];
  const ruleOptions = rules.items
    .filter((r) => r.hits > 0)
    .sort((a, b) => b.hits - a.hits)
    .map((r) => `<option value="${esc(r.id)}"${f.rule === r.id ? ' selected' : ''}>${esc(r.name)} (${r.hits})</option>`)
    .join('');

  $('#view').innerHTML = `
    <section class="card">
      <div class="toolbar">
        <div class="seg">
          ${statuses.map((s) => `<button class="${f.status === s.key ? 'active' : ''}" data-act="set-status-filter" data-value="${esc(s.key)}">${s.label}</button>`).join('')}
        </div>
        <div class="picker">
          ${Object.keys(SEVERITY).map((k) => `<button data-act="toggle-sev" data-sev="${k}" class="${f.severity.has(k) ? 'on' : ''}">${SEVERITY[k].label}</button>`).join('')}
        </div>
        <select style="width:auto;min-width:150px" data-act="filter-target">
          <option value="">全部站点</option>
          ${targets.map((t) => `<option value="${t.id}"${String(f.target) === String(t.id) ? ' selected' : ''}>${esc(t.name)}</option>`).join('')}
        </select>
        <select style="width:auto;min-width:150px" data-act="filter-rule">
          <option value="">全部规则</option>${ruleOptions}
        </select>
        <select style="width:auto;min-width:132px" data-act="filter-ai">
          <option value="">AI 判定: 全部</option>
          <option value="real"${f.ai === 'real' ? ' selected' : ''}>AI: 真凭证</option>
          <option value="fake"${f.ai === 'fake' ? ' selected' : ''}>AI: 误报</option>
          <option value="public"${f.ai === 'public' ? ' selected' : ''}>AI: 公开密钥</option>
          <option value="uncertain"${f.ai === 'uncertain' ? ' selected' : ''}>AI: 待人工确认</option>
          <option value="none"${f.ai === 'none' ? ' selected' : ''}>AI: 未复核</option>
        </select>
        <div class="search" style="width:190px">
          ${icon('search')}<input type="text" id="f-q" placeholder="搜索命中值 / 文件" value="${esc(f.q)}">
        </div>
        <select style="width:auto" data-act="filter-sort">
          <option value="recent"${f.sort === 'recent' ? ' selected' : ''}>最近发现</option>
          <option value="severity"${f.sort === 'severity' ? ' selected' : ''}>按等级</option>
          <option value="target"${f.sort === 'target' ? ' selected' : ''}>按站点</option>
          <option value="oldest"${f.sort === 'oldest' ? ' selected' : ''}>最早发现</option>
        </select>
        <div class="spacer"></div>
        <button class="btn btn-sm" data-act="export">${icon('download', 13)}导出 CSV</button>
      </div>
      ${findingsBulkBar()}
      ${gatedBar(data.gated, f.showGated)}
      <div class="table-wrap">
        ${data.items.length ? `<table>
          <thead><tr>
            <th class="shrink"><input type="checkbox" class="check" data-act="select-all"></th>
            <th class="shrink">等级</th><th>规则</th><th>命中值</th><th>站点</th>
            <th>来源文件</th><th class="shrink">状态</th><th class="shrink">AI 复核</th><th class="shrink">首次发现</th>
            <th class="shrink sticky-r">操作</th>
          </tr></thead>
          <tbody>${data.items.map((r) => `
            <tr class="clickable" data-act="open-finding" data-id="${r.id}">
              <td class="shrink"><input type="checkbox" class="check" data-act="select-one" data-id="${r.id}"${state.selected.has(r.id) ? ' checked' : ''}></td>
              <td class="shrink">${sevChip(r.severity)}</td>
              <td><div class="cell-clip w-md" title="${esc(r.rule_name)}">${esc(r.rule_name)}${sourceTag(r)}</div></td>
              <td><span class="val-mask">${esc(r.match_masked)}</span></td>
              <td class="muted">
                <div class="cell-clip w-sm" title="${esc(r.target_name || '')}">${esc(r.target_name || '')}</div>
                ${r.reuse_sites > 1 ? `<span class="tag tag-warn" title="同一命中值出现在 ${r.reuse_sites} 个站点">复用 ${r.reuse_sites} 站</span>` : ''}
              </td>
              <td><div class="cell-clip w-lg mono" style="font-size:11.5px;color:var(--text-dim)" title="${esc(r.asset_url)}">${esc(r.asset_url)}</div></td>
              <td class="shrink">${statusTag(r.status)}</td>
              <td class="shrink">${verdictChip(r)}</td>
              <td class="shrink muted nowrap" style="font-size:11.5px">${fromNow(r.first_seen_at)}</td>
              <td class="shrink nowrap sticky-r">
                <button class="btn btn-icon btn-sm btn-danger" title="删除这条发现" data-act="del-finding" data-id="${r.id}">${icon('trash', 13)}</button>
              </td>
            </tr>`).join('')}</tbody></table>`
          : `<div class="empty">${icon('shield')}没有符合条件的发现</div>`}
      </div>
      <div class="pager">
        <span>共 ${data.total} 条，当前显示 ${data.offset + 1}-${data.offset + data.items.length}</span>
        <div class="spacer"></div>
        <button class="btn btn-sm" data-act="page" data-page="${f.page - 1}" ${f.page === 0 ? 'disabled' : ''}>上一页</button>
        <button class="btn btn-sm" data-act="page" data-page="${f.page + 1}" ${data.offset + data.items.length >= data.total ? 'disabled' : ''}>下一页</button>
      </div>
    </section>`;

  const qInput = $('#f-q');
  let timer = null;
  qInput.oninput = () => {
    clearTimeout(timer);
    timer = setTimeout(() => { state.filters.q = qInput.value.trim(); state.filters.page = 0; refresh(); }, 320);
  };

  // 支持 #/findings?finding=<id> 直接展开某条发现的详情
  if (q.finding && !state.openedFromLink) {
    state.openedFromLink = String(q.finding);
    openFinding(Number(q.finding));
  }
}

/* 发现批量操作条: 有选中项时才出现 */
function findingsBulkBar() {
  const count = state.selected.size;
  if (!count) {
    return `<div class="toolbar" style="padding-top:0">
      <span class="field-hint">勾选左侧复选框可批量改状态或删除</span>
    </div>`;
  }
  return `<div class="toolbar" style="background:#1b2432;border-bottom-color:#2b3a4e">
    <b>已选 ${count} 条发现</b>
    <div class="spacer"></div>
    <button class="btn btn-sm" data-act="bulk-status" data-status="open">${icon('check', 13)}确认有效</button>
    <button class="btn btn-sm" data-act="bulk-status" data-status="false_positive">标记误报</button>
    <button class="btn btn-sm" data-act="bulk-status" data-status="ignored">忽略</button>
    <button class="btn btn-sm" data-act="bulk-status" data-status="resolved">已修复</button>
    <button class="btn btn-sm btn-danger" data-act="bulk-del-findings">${icon('trash', 13)}删除</button>
    <button class="btn btn-sm btn-ghost" data-act="findings-clear">取消选择</button>
  </div>`;
}

async function bulkFindingStatus(status) {
  const ids = Array.from(state.selected);
  if (!ids.length) return;
  try {
    const r = await api('/api/findings/bulk', { method: 'POST', body: JSON.stringify({ ids, status }) });
    state.selected.clear();
    toast(`已标记 ${r.updated} 条为「${STATUS[status] || status}」`, 'ok');
    refresh();
  } catch (err) { toast('操作失败: ' + err.message, 'err'); }
}

async function bulkDeleteFindings() {
  const ids = Array.from(state.selected);
  if (!ids.length) return;
  if (!window.confirm(`确认删除选中的 ${ids.length} 条发现？删除后 JS 里若仍有该凭证，下一轮扫描会重新报出来。`)) return;
  try {
    const r = await api('/api/findings/bulk', {
      method: 'POST',
      body: JSON.stringify({ ids, action: 'delete' }),
    });
    state.selected.clear();
    toast(`已删除 ${r.deleted} 条发现`, 'ok');
    refresh();
  } catch (err) { toast('删除失败: ' + err.message, 'err'); }
}

async function setFindingStatus(id, status) {
  try {
    await api(`/api/findings/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) });
    toast('状态已更新为「' + (STATUS[status] || status) + '」', 'ok');
    closeDrawer();
    refresh();
  } catch (err) { toast('更新失败: ' + err.message, 'err'); }
}

async function openFinding(id) {
  let f;
  try { f = await api(`/api/findings/${id}`); }
  catch (err) { toast('加载失败: ' + err.message, 'err'); return; }
  const context = f.context || '';
  const masked = f.match_masked || '';
  const head = masked.split('...')[0] || '';
  const marked = head && context.includes(head)
    ? context.replace(head, `<mark>${esc(head)}</mark>`)
    : esc(context);
  $('#drawer').innerHTML = `
    <div class="drawer-head">
      <div>
        <h2>${esc(f.rule_name)}</h2>
        <div style="display:flex;gap:7px;align-items:center;flex-wrap:wrap">
          ${sevChip(f.severity)} ${statusTag(f.status)}
          <span class="tag mono">${esc(f.rule_id)}</span>
          ${f.verified && f.verified !== 'unverified' ? `<span class="tag">${esc(f.verified)}</span>` : ''}
        </div>
      </div>
      <button class="btn btn-ghost btn-icon btn-sm" data-act="close-drawer">${icon('x', 15)}</button>
    </div>
    <div class="drawer-body">
      <dl class="kv">
        <dt>命中值</dt><dd><span class="val-mask">${esc(f.match_masked)}</span> <span class="muted">(原文不入库，仅存掩码)</span></dd>
        <dt>所属站点</dt><dd>${esc(f.target_name || '')} <span class="muted mono" style="font-size:11.5px">${esc(f.target_url || '')}</span></dd>
        <dt>来源文件</dt><dd><a class="mono" style="font-size:11.5px" href="${esc(f.asset_url)}" target="_blank" rel="noreferrer">${esc(f.asset_url)}</a></dd>
        <dt>行号</dt><dd class="mono">${f.line_no || '—'}</dd>
        <dt>分类</dt><dd>${esc(f.category)}</dd>
        <dt>发现来源</dt><dd>${(f.found_by || 'builtin').split(',').filter(Boolean).map((x) => `<span class="tag">${esc(x)}</span>`).join(' ') || '—'}</dd>
        <dt>熵值</dt><dd class="mono">${f.entropy != null ? f.entropy : '—'}</dd>
        <dt>首次发现</dt><dd>${fmtTime(f.first_seen_at)} <span class="muted">(${fromNow(f.first_seen_at)})</span></dd>
        <dt>最近出现</dt><dd>${fmtTime(f.last_seen_at)} <span class="muted">· 累计 ${f.times_seen} 次</span></dd>
        <dt>指纹</dt><dd class="mono" style="font-size:11px;color:#6c7787">${esc(f.fingerprint)}</dd>
      </dl>
      <div class="section-title">命中上下文</div>
      <div class="codeblock">${marked || '（无上下文）'}</div>
      ${reuseSection(f)}
      ${aiSection(f)}
      <div class="section-title">备注</div>
      <textarea id="d-notes" rows="3" placeholder="记录复核结论、修复进展或负责人">${esc(f.notes || '')}</textarea>
      <div style="display:flex;gap:8px;margin-top:9px">
        <button class="btn btn-sm" data-act="save-notes" data-id="${f.id}">保存备注</button>
        <button class="btn btn-sm" data-act="copy" data-text="${esc(f.asset_url)}">${icon('copy', 13)}复制文件地址</button>
      </div>
    </div>
    <div class="drawer-foot">
      <button class="btn btn-sm" data-act="finding-status" data-id="${f.id}" data-status="open">${icon('check', 13)}确认有效</button>
      <button class="btn btn-sm" data-act="finding-status" data-id="${f.id}" data-status="false_positive">标记误报</button>
      <button class="btn btn-sm" data-act="finding-status" data-id="${f.id}" data-status="ignored">忽略</button>
      <button class="btn btn-sm" data-act="finding-status" data-id="${f.id}" data-status="resolved">已修复</button>
      <div class="spacer"></div>
      <button class="btn btn-sm btn-danger" data-act="del-finding" data-id="${f.id}">${icon('trash', 13)}删除</button>
    </div>`;
  $('#drawer').hidden = false;
  $('#scrim').hidden = false;
  state.openFindingId = id;
}

/* 同一命中值的其他出现位置: 一把密钥被多处复用, 往往比单条命中更值得追 */
function reuseSection(f) {
  const reuse = f.reuse || [];
  if (!reuse.length) return '';
  const sites = new Set(reuse.map((r) => r.target_name || r.target_id));
  return `<div class="section-title">同一凭证的其他出现位置 <span class="muted" style="font-weight:400">· ${reuse.length} 处 / ${sites.size} 个站点</span></div>
    <div style="display:flex;flex-direction:column;gap:6px">
      ${reuse.slice(0, 12).map((r) => `
        <div class="list-row" style="gap:8px;align-items:center">
          <span class="grow">
            <b>${esc(r.target_name || ('#' + r.target_id))}</b>
            <span class="muted mono" style="font-size:11.5px">${esc(r.asset_url)}</span>
          </span>
          ${statusTag(r.status)}
          <button class="btn btn-sm" data-act="open-finding" data-id="${r.id}">查看</button>
        </div>`).join('')}
      ${reuse.length > 12 ? `<div class="muted" style="font-size:11.5px">还有 ${reuse.length - 12} 处…</div>` : ''}
    </div>`;
}

function aiSection(f) {
  const hasReview = !!f.ai_verdict;
  const v = VERDICT[f.ai_verdict] || VERDICT.uncertain;
  const parts = [];
  if (hasReview) {
    parts.push(`<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
      <span class="chip ${v.cls}">${v.label}${f.ai_confidence ? ' · ' + Math.round(f.ai_confidence * 100) + '%' : ''}</span>
      <span class="muted" style="font-size:11.5px">${esc(f.ai_model || '')} · ${fmtTime(f.ai_checked_at)}</span>
    </div>`);
    if (f.ai_reason) parts.push(`<div style="font-size:12.5px;margin-bottom:6px">${esc(f.ai_reason)}</div>`);
    if (f.ai_impact) parts.push(`<div class="muted" style="font-size:12px">影响：${esc(f.ai_impact)}</div>`);
    if (f.ai_remediation) parts.push(`<div class="muted" style="font-size:12px">建议：${esc(f.ai_remediation)}</div>`);
  } else {
    parts.push('<div class="muted" style="font-size:12.5px">尚未复核。AI 会判断这是真凭证、占位符误报，还是公开设计中允许暴露的密钥。</div>');
  }
  parts.push(`<div style="display:flex;gap:8px;margin-top:9px;flex-wrap:wrap">
    <button class="btn btn-sm" data-act="triage" data-id="${f.id}">${icon('zap', 13)}${hasReview ? '重新复核' : 'AI 复核'}</button>
    <button class="btn btn-sm" data-act="draft-rule" data-id="${f.id}">${icon('plus', 13)}生成检测规则</button>
    ${f.origin === 'ai' ? '<span class="tag tag-run">AI 语义发现</span>' : ''}
  </div>`);
  return `<div class="section-title">AI 复核</div>${parts.join('')}`;
}

/* ------------------------------------------------------------------ 资产 */

async function renderAssets() {
  const q = parseHash().query;
  let page = state.assetsPage || 0;
  const per = state.assetsPerPage || 25;
  const params = new URLSearchParams({ limit: String(per), offset: String(page * per) });
  if (q.target) params.set('target_id', q.target);
  if (q.q) params.set('q', q.q);
  const changeParams = new URLSearchParams({ limit: '80' });
  if (q.target) changeParams.set('target_id', q.target);
  const [data, targetData, changes] = await Promise.all([
    api('/api/assets?' + params),
    api('/api/targets?limit=0'),
    apiList('/api/changes?' + changeParams),
  ]);
  const targets = targetData.items;
  const lastPage = Math.max(0, Math.ceil((data.total || 0) / per) - 1);
  if (page > lastPage) {
    state.assetsPage = lastPage;
    return renderAssets();
  }
  const view = state.assetsView || 'list';
  $('#view').innerHTML = `
    <section class="card">
      <div class="toolbar">
        <div class="seg">
          <button class="${view === 'list' ? 'active' : ''}" data-act="assets-view" data-value="list">资产清单</button>
          <button class="${view === 'changes' ? 'active' : ''}" data-act="assets-view" data-value="changes">最近变更</button>
        </div>
        <select style="width:auto;min-width:170px" data-act="asset-target">
          <option value="">全部站点</option>
          ${targets.map((t) => `<option value="${t.id}"${String(q.target) === String(t.id) ? ' selected' : ''}>${esc(t.name)}</option>`).join('')}
        </select>
        ${view === 'list' ? `
        <div class="search" style="width:240px">${icon('search')}
          <input type="text" id="a-q" placeholder="按地址过滤" value="${esc(q.q || '')}">
        </div>` : ''}
        <div class="spacer"></div>
        <span class="muted">${view === 'list' ? `共 ${data.total} 个资产` : `${changes.length} 次内容变更`}</span>
      </div>
      ${view === 'changes' ? changesTable(changes) : assetsTable(data, q)}
      ${view === 'list' && data.items.length ? listPager('assets', page, data.total, data.items.length, per) : ''}
    </section>`;
  const input = $('#a-q');
  if (input) {
    let timer = null;
    input.oninput = () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        state.assetsPage = 0;
        goto('assets', { ...(q.target ? { target: q.target } : {}), q: input.value.trim() });
      }, 340);
    };
  }
}

/* 资产清单 */
function assetsTable(data, q) {
  return `
      <div class="table-wrap">
        ${data.items.length ? `<table>
          <thead><tr>
            <th class="shrink">类型</th><th>地址</th><th class="shrink">站点</th>
            <th class="shrink">大小</th><th class="shrink">指纹</th>
            <th class="shrink">最近采集</th><th class="shrink">内容变更</th><th class="shrink">历史</th>
          </tr></thead>
          <tbody>${data.items.map((a) => `
            <tr>
              <td class="shrink"><span class="tag">${esc(assetKind(a.kind))}</span></td>
              <td><div class="url-cell" style="max-width:420px" title="${esc(a.url)}">${esc(a.url)}</div></td>
              <td class="shrink muted">${esc(a.target_name || '')}</td>
              <td class="shrink mono muted">${fmtBytes(a.size)}</td>
              <td class="shrink mono muted" style="font-size:11px">${esc((a.sha256 || '').slice(0, 8))}</td>
              <td class="shrink muted nowrap" style="font-size:11.5px">${fromNow(a.last_seen_at)}</td>
              <td class="shrink nowrap" style="font-size:11.5px">${a.last_changed_at
                ? `<span class="tag tag-warn">${fromNow(a.last_changed_at)}</span>`
                : '<span class="muted">未变更</span>'}</td>
              <td class="shrink nowrap">
                ${a.versions > 1
                  ? `<button class="btn btn-sm" data-act="asset-history" data-id="${a.id}">${a.versions} 版</button>`
                  : '<span class="muted" style="font-size:11.5px">—</span>'}
              </td>
            </tr>`).join('')}</tbody></table>`
          : `<div class="empty">${icon('filecode')}暂无资产，先添加站点并执行一次扫描</div>`}
      </div>`;
}

/* 跨站变更流: 谁变了、变了什么 */
function changesTable(changes) {
  if (!changes.length) {
    return `<div class="empty">${icon('filecode')}还没有内容变更记录。资产内容变化后，这里会列出新增与消失的字符串。</div>`;
  }
  return `<div class="table-wrap"><table>
    <thead><tr>
      <th class="shrink">时间</th><th class="shrink">站点</th><th>文件</th>
      <th class="shrink">变化</th><th>新增 / 消失的字符串</th>
    </tr></thead>
    <tbody>${changes.map((c) => `
      <tr>
        <td class="shrink muted nowrap" style="font-size:11.5px">${fromNow(c.created_at)}</td>
        <td class="shrink muted">${esc(c.target_name || ('#' + c.target_id))}</td>
        <td><div class="url-cell" style="max-width:330px" title="${esc(c.url)}">${esc(c.url)}</div></td>
        <td class="shrink nowrap">
          ${c.added_count ? `<span class="tag tag-ok">+${c.added_count}</span>` : ''}
          ${c.removed_count ? `<span class="tag tag-err">-${c.removed_count}</span>` : ''}
        </td>
        <td>
          <div class="diff-cell">
            ${diffLines(c)}
          </div>
        </td>
      </tr>`).join('')}</tbody>
  </table></div>`;
}

function diffLines(change) {
  const added = (change.added || []).slice(0, 12);
  const removed = (change.removed || []).slice(0, 6);
  const more = [];
  if ((change.added || []).length > added.length) more.push(`+${change.added.length - added.length}`);
  if ((change.removed || []).length > removed.length) more.push(`-${change.removed.length - removed.length}`);
  return [
    ...added.map((s) => `<div class="diff-add mono" title="${esc(s)}">+ ${esc(s)}</div>`),
    ...removed.map((s) => `<div class="diff-del mono" title="${esc(s)}">- ${esc(s)}</div>`),
    more.length ? `<div class="muted" style="font-size:11.5px">还有 ${more.join(' / ')} 条…</div>` : '',
  ].join('');
}

function assetKind(kind) {
  return { html: '页面', script: '脚本', inline: '内联', map: '映射', config: '配置',
           api: '接口' }[kind] || kind;
}

/* 单个资产的内容版本历史: 每版列出新增与消失的字符串 */
async function openAssetHistory(aid) {
  let info;
  try { info = await api(`/api/assets/${aid}/history`); }
  catch (err) { toast('加载失败: ' + err.message, 'err'); return; }
  const versions = info.versions || [];
  $('#modal').innerHTML = `
    <div class="modal-head">
      <h2>内容变更历史</h2>
      <button class="btn btn-ghost btn-icon btn-sm" data-act="close-modal">${icon('x', 14)}</button>
    </div>
    <div class="modal-body">
      <div class="field-hint">
        ${esc(info.asset.target_name || '')} · <span class="mono">${esc(info.asset.url)}</span>
      </div>
      <div class="field-hint">
        只保存字符串签名，命中的密钥与高熵串都已掩码，不落 JS 原文；每个资产保留最近 12 版。
      </div>
      ${versions.length ? versions.map((v, index) => `
        <div style="border-top:1px solid var(--line-soft);padding-top:10px;display:flex;flex-direction:column;gap:6px">
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <b>${fmtTime(v.created_at)}</b>
            <span class="muted" style="font-size:11.5px">${fromNow(v.created_at)}</span>
            ${index === 0 ? '<span class="tag tag-ok">当前版本</span>' : ''}
            <span class="muted mono" style="font-size:11px">${esc((v.sha256 || '').slice(0, 8))}</span>
            <span class="muted" style="font-size:11.5px">${fmtBytes(v.size)} · ${v.lines} 行 · ${v.findings} 处命中</span>
            ${v.added_count ? `<span class="tag tag-ok">+${v.added_count}</span>` : ''}
            ${v.removed_count ? `<span class="tag tag-err">-${v.removed_count}</span>` : ''}
          </div>
          ${v.added_count || v.removed_count
            ? `<div class="diff-cell">${diffLines(v)}</div>`
            : '<div class="muted" style="font-size:11.5px">这是首次采集的基线版本</div>'}
        </div>`).join('')
        : '<div class="muted">还没有版本记录，下次扫描内容变化时会生成。</div>'}
    </div>
    <div class="modal-foot">
      <button class="btn" data-act="close-modal">关闭</button>
    </div>`;
  $('#modal-scrim').hidden = false;
}

function fmtBytes(n) {
  if (!n) return '0 B';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(2) + ' MB';
}

/* ------------------------------------------------------------------ 规则 */

/* 规则质量: 用真实命中 + AI 复核结果算出"谁在制造误报", 并给出可执行建议 */
function ruleQualityCard(q) {
  const s = (q && q.summary) || {};
  const ranked = (q && q.ranked) || [];
  const worst = ranked.filter((item) => item.tone === 'err' || item.tone === 'warn').slice(0, 6);
  const ai = s.ai_today || {};
  const head = s.judged
    ? `已复核 ${s.judged} 条命中, 其中 ${s.fake} 条被判误报 (${Math.round((s.fp_rate || 0) * 100)}%)`
    : '还没有 AI 复核结果, 打开 AI 复核后这里会给出每条规则的误报率';
  return `<section class="card" style="margin-bottom:12px">
    <div class="card-head"><h2>规则质量</h2><span class="sub">按误报率排序 · 样本 ≥ ${s.min_samples || 3} 条才计入</span></div>
    <div class="card-body" style="display:flex;flex-direction:column;gap:10px">
      <div class="field-hint">
        ${esc(head)}${ai.calls != null ? ` · 今日模型调用 ${ai.calls} 次 (缓存命中 ${ai.cached || 0})` : ''}
      </div>
      ${worst.length ? `<div class="table-wrap"><table>
        <thead><tr><th>规则</th><th class="shrink">命中</th><th class="shrink">站点</th>
          <th class="shrink">已复核</th><th class="shrink">误报率</th><th class="shrink">建议</th>
          <th class="shrink">操作</th></tr></thead>
        <tbody>${worst.map((item) => `
          <tr>
            <td><div class="cell-clip w-md" title="${esc(item.rule_id)}">${esc(item.rule_name)}</div></td>
            <td class="shrink mono muted">${item.hits}</td>
            <td class="shrink mono muted">${item.sites}</td>
            <td class="shrink mono muted">${item.judged}</td>
            <td class="shrink"><span class="tag ${item.tone === 'err' ? 'tag-err' : 'tag-warn'}">${Math.round(item.fp_rate * 100)}%</span></td>
            <td class="shrink muted" style="font-size:11.5px">${esc(item.advice)}</td>
            <td class="shrink nowrap">
              <button class="btn btn-sm" data-act="rule-downgrade" data-id="${esc(item.rule_id)}" title="降一级, 减少噪声">降级</button>
              <button class="btn btn-sm" data-act="rule-toggle" data-id="${esc(item.rule_id)}" title="关闭这条规则的后续命中">关闭</button>
            </td>
          </tr>`).join('')}</tbody>
      </table></div>` : '<div class="muted" style="font-size:12px">暂无高误报规则 —— 要么样本还不够, 要么规则表现不错。</div>'}
    </div>
  </section>`;
}

/* 在线编辑自定义规则: 正则 + 样例当场验证 */
function ruleEditor(rule) {
  const draft = rule || { name: '', pattern: '', severity: 'high', category: 'imported',
                          description: '', keywords: [], entropy_min: 0 };
  return `
    <div class="modal-head">
      <h2>${rule ? '编辑自定义规则' : '新建检测规则'}</h2>
      <button class="btn btn-ghost btn-icon btn-sm" data-act="close-modal">${icon('x', 14)}</button>
    </div>
    <div class="modal-body">
      <div class="form-row">
        <label class="field">规则名
          <input type="text" id="nr-name" value="${esc(draft.name)}" placeholder="例如 Acme 内部令牌">
        </label>
        <label class="field">等级
          <select id="nr-sev">
            ${Object.keys(SEVERITY).map((k) => `<option value="${k}"${draft.severity === k ? ' selected' : ''}>${SEVERITY[k].label}</option>`).join('')}
          </select>
        </label>
      </div>
      <label class="field">正则表达式
        <textarea id="nr-pattern" rows="2" placeholder="acme_[A-Za-z0-9]{20,}">${esc(draft.pattern)}</textarea>
        <span class="field-hint">和真实扫描用同一套过滤（占位符、代码路径、熵值、白名单）。id 会自动加 <code>custom:</code> 前缀。</span>
      </label>
      <div class="form-row">
        <label class="field">关键词 (逗号分隔, 可选)
          <input type="text" id="nr-keywords" value="${esc((draft.keywords || []).join(','))}" placeholder="acme_,token">
        </label>
        <label class="field">熵值下限 (可选)
          <input type="number" id="nr-entropy" step="0.1" min="0" value="${esc(draft.entropy_min || 0)}">
        </label>
      </div>
      <label class="field">说明
        <input type="text" id="nr-desc" value="${esc(draft.description || '')}" placeholder="命中什么、为什么危险">
      </label>
      <label class="field">样例文本（拿一段真实片段验证）
        <textarea id="nr-sample" rows="4" placeholder='var k = "acme_a8F3kQ2zLp91XbS7";'></textarea>
      </label>
      <div id="nr-result"></div>
    </div>
    <div class="modal-foot">
      <button class="btn" data-act="close-modal">取消</button>
      <button class="btn" data-act="test-rule">测试规则</button>
      <button class="btn btn-primary" data-act="save-rule" data-id="${esc(draft.id || '')}">保存并启用</button>
    </div>`;
}

function readRuleDraft() {
  return {
    id: $('[data-act="save-rule"]').dataset.id || '',
    name: $('#nr-name').value.trim(),
    pattern: $('#nr-pattern').value,
    severity: $('#nr-sev').value,
    category: 'imported',
    description: $('#nr-desc').value.trim(),
    keywords: $('#nr-keywords').value.split(',').map((s) => s.trim()).filter(Boolean),
    entropy_min: Number($('#nr-entropy').value || 0),
  };
}

async function testRuleDraft() {
  const draft = readRuleDraft();
  const sample = $('#nr-sample').value;
  if (!draft.pattern.trim()) { toast('先填写正则表达式', 'err'); return; }
  if (!sample.trim()) { toast('粘贴一段样例文本才能验证', 'err'); return; }
  const box = $('#nr-result');
  box.innerHTML = '<div class="field-hint">正在验证…</div>';
  try {
    const r = await api('/api/rules/test', { method: 'POST', body: JSON.stringify({ ...draft, sample }) });
    const rejected = Object.entries(r.rejected || {});
    box.innerHTML = `
      <div class="list-row" style="gap:8px;flex-wrap:wrap">
        <span class="grow"><b>正则匹配 ${r.raw_count} 处, 通过过滤 ${r.count} 处</b></span>
        ${r.count ? '<span class="tag tag-ok">可用</span>' : '<span class="tag tag-err">样例无命中</span>'}
      </div>
      ${rejected.length ? `<div class="field-hint">被挡掉: ${rejected.map(([k, v]) => `${esc(k)} ${v}`).join(' · ')}</div>` : ''}
      ${r.hint ? `<div class="field-hint">${esc(r.hint)}</div>` : ''}
      ${(r.matches || []).slice(0, 6).map((m) => `
        <div class="list-row" style="gap:8px">
          <span class="grow mono" style="font-size:11.5px">${esc(m.context)}</span>
          <span class="tag">行 ${m.line_no}</span><span class="tag">熵 ${m.entropy}</span>
        </div>`).join('')}`;
  } catch (err) {
    box.innerHTML = `<div class="field-hint" style="color:#ef8b8b">${esc(err.message)}</div>`;
  }
}

async function saveRuleDraft() {
  const draft = readRuleDraft();
  if (!draft.pattern.trim()) { toast('先填写正则表达式', 'err'); return; }
  if (!draft.name) { toast('给规则起个名字', 'err'); return; }
  try {
    const r = await api('/api/rules/custom', { method: 'POST', body: JSON.stringify(draft) });
    toast(`规则 ${r.saved} 已保存并启用`, 'ok');
    closeModal();
    renderRules();
  } catch (err) { toast('保存失败: ' + err.message, 'err'); }
}

async function downgradeRule(ruleId) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const rule = (state.cache.rules || []).find((r) => r.id === ruleId);
  if (!rule) return;
  const next = order[Math.min(order.indexOf(rule.severity) + 1, order.length - 1)];
  if (next === rule.severity) { toast('已经是最低等级了', 'err'); return; }
  try {
    await api(`/api/rules/${encodeURIComponent(ruleId)}`, { method: 'PATCH', body: JSON.stringify({ severity: next }) });
    toast(`「${rule.name}」已降为 ${SEVERITY[next].label}`, 'ok');
    renderRules();
  } catch (err) { toast('操作失败: ' + err.message, 'err'); }
}

async function renderRules() {
  const [data, quality] = await Promise.all([api('/api/rules'), api('/api/rules/quality')]);
  state.cache.rules = data.items;
  state.cache.ruleQuality = quality;
  const grouped = {};
  data.items.forEach((r) => { (grouped[r.category] = grouped[r.category] || []).push(r); });
  const cats = Object.keys(grouped).sort();
  const enabledCount = data.items.filter((r) => r.enabled).length;
  $('#view').innerHTML = `
    <section class="card" style="margin-bottom:12px">
      <div class="toolbar">
        <span class="muted">共 ${data.items.length} 条规则，启用 ${enabledCount} 条</span>
        <div class="spacer"></div>
        <button class="btn btn-sm" data-act="new-rule">${icon('plus', 13)}新建规则</button>
        <div class="spacer"></div>
        <div class="search" style="width:220px">${icon('search')}<input type="text" id="r-q" placeholder="搜索规则名 / ID"></div>
      </div>
    </section>
    ${ruleQualityCard(quality)}

    <div class="grid cols-2b" style="margin-bottom:12px">
      <section class="card">
        <div class="card-head"><h2>导入外部规则</h2><span class="sub">gitleaks TOML 格式</span></div>
        <div class="card-body" style="display:flex;flex-direction:column;gap:10px">
          <textarea id="import-toml" rows="6" placeholder='[[rules]]
id = "acme-internal-token"
description = "Acme 内部令牌"
regex = '''acme_[a-z0-9]{32}'''
keywords = ["acme_"]'></textarea>
          <div style="display:flex;gap:8px;align-items:center">
            <button class="btn btn-primary btn-sm" data-act="import-rules">${icon('plus', 13)}导入规则</button>
            <span class="field-hint">也支持粘贴 gitleaks 官方 rules 片段；导入后规则 id 会加 <code>gl:</code> 前缀。</span>
          </div>
        </div>
      </section>
      <section class="card">
        <div class="card-head"><h2>规则引擎说明</h2></div>
        <div class="card-body" style="display:flex;flex-direction:column;gap:8px;font-size:12.5px">
          <div class="list-row"><span class="grow">关键词预过滤 <span class="muted">先定位关键词再跑正则，压缩代码上开销更低</span></span></div>
          <div class="list-row"><span class="grow">香农熵阈值 <span class="muted">过滤掉低随机度的占位串</span></span></div>
          <div class="list-row"><span class="grow">占位符与代码路径识别 <span class="muted">YOUR_KEY、process.env、静态资源路径不报</span></span></div>
          <div class="list-row"><span class="grow">重叠消歧 <span class="muted">同一段文本命中多条规则时保留最有价值的一条</span></span></div>
          <div class="list-row"><span class="grow">字符串拼接还原 <span class="muted">识别 <code>"a" + "b"</code> 形式规避写法</span></span></div>
        </div>
      </section>
    </div>

    ${cats.map((cat) => `
      <section class="card" style="margin-bottom:12px">
        <div class="card-head"><h2>${esc(catLabel(cat))}</h2><span class="sub">${grouped[cat].length} 条</span></div>
        <div class="table-wrap"><table>
          <thead><tr><th class="shrink">启用</th><th>规则</th><th class="shrink">等级</th>
            <th class="shrink">命中</th><th class="shrink">来源</th><th class="shrink"></th></tr></thead>
          <tbody>${grouped[cat].map((r) => `
            <tr data-rule-row="${esc(r.id)}" data-text="${esc((r.name + ' ' + r.id + ' ' + (r.description || '')).toLowerCase())}">
              <td class="shrink">
                <label class="switch"><input type="checkbox" data-act="rule-toggle" data-id="${esc(r.id)}" ${r.enabled ? 'checked' : ''}><span class="track"></span></label>
              </td>
              <td>
                <div style="display:flex;flex-direction:column;gap:2px">
                  <span>${esc(r.name)}</span>
                  <span class="muted mono" style="font-size:11px">${esc(r.id)}</span>
                  ${r.description ? `<span class="muted" style="font-size:11.5px">${esc(r.description)}</span>` : ''}
                </div>
              </td>
              <td class="shrink">
                <select data-act="rule-sev" data-id="${esc(r.id)}" style="width:auto">
                  ${Object.keys(SEVERITY).map((k) => `<option value="${k}"${r.severity === k ? ' selected' : ''}>${SEVERITY[k].label}</option>`).join('')}
                </select>
              </td>
              <td class="shrink mono muted">${r.hits}</td>
              <td class="shrink">${r.builtin ? '<span class="tag">内置</span>' : '<span class="tag tag-ok">导入</span>'}</td>
              <td class="shrink nowrap">${r.builtin ? '' : `
                <button class="btn btn-icon btn-sm" data-act="edit-rule" data-id="${esc(r.id)}" title="编辑这条自定义规则">${icon('sliders', 13)}</button>
                <button class="btn btn-icon btn-sm btn-danger" data-act="del-rule" data-id="${esc(r.id)}" title="删除导入规则">${icon('trash', 13)}</button>`}</td>
            </tr>`).join('')}</tbody>
        </table></div>
      </section>`).join('')}`;

  const input = $('#r-q');
  input.oninput = () => {
    const term = input.value.trim().toLowerCase();
    $$('[data-rule-row]').forEach((row) => {
      row.classList.toggle('hidden', term !== '' && !row.dataset.text.includes(term));
    });
  };
}

const CATEGORY_LABELS = {
  cloud: '云厂商与对象存储', 'cn-cloud': '国内云厂商', scm: '代码托管与 CI',
  payment: '支付与结算', 'cn-payment': '国内支付 (微信/支付宝)', email: '邮件服务',
  sms: '短信服务', im: 'IM 与协作工具', social: '社交平台', saas: '第三方 SaaS',
  'cn-service': '国内地图/语音/风控', 'private-key': '私钥与证书',
  credential: '通用凭据', database: '数据库连接串', exposure: '源码与信息暴露',
  generic: '通用高熵检测', pii: '个人信息 (默认关闭)', imported: '导入规则',
};

function catLabel(cat) {
  return CATEGORY_LABELS[cat] || cat;
}

/* ------------------------------------------------------------------ 设置 */

/* 飞书告警排障: 最近一次推送结果 + 尚未推送的、达到等级的发现数 */
function alertStatusLine(status, minLabel) {
  if (!status) return '';
  const last = status.last_event;
  const pending = status.pending_alertable || 0;
  const bad = last && (last.level === 'warn' || last.level === 'error');
  const lastText = last
    ? `<span class="tag ${bad ? 'tag-err' : 'tag-ok'}">${bad ? '异常' : '正常'}</span> ${esc(last.message)}`
    : '<span class="tag">还没有推送记录</span>';
  const pendingText = pending
    ? `<span class="tag tag-warn">有 ${pending} 条达到等级的发现尚未推送</span>`
    : '<span class="tag tag-ok">没有待推送的发现</span>';
  return `<div style="border-top:1px solid var(--line-soft);padding-top:11px;display:flex;flex-direction:column;gap:6px;font-size:12px">
    <div>最近推送：${lastText}${last ? ` <span class="muted">(${esc(fmtTime(last.ts))})</span>` : ''}</div>
    <div class="muted" style="font-size:11.5px">${pendingText}
      低于「${esc(minLabel)}」等级的发现不会推送；告警开关关闭时也不推送。</div>
  </div>`;
}

/* 模型选择: 一个输入框 + 右侧箭头弹出的候选列表（拉取结果缓存在内存里, 页面重绘后依然可用） */
function modelCombo(current) {
  const models = state.cache.modelList || [];
  const items = models.map((m) => `<button type="button" class="combo-item${m === current ? ' active' : ''}" data-act="ai-model-choose" data-value="${esc(m)}">${esc(m)}</button>`).join('');
  return `<div class="combo" id="ai-model-combo">
    <input type="text" id="ai-model" data-act="ai-model-open" placeholder="例如 glm-5.2" value="${esc(current)}" autocomplete="off" spellcheck="false">
    <button type="button" class="combo-btn" data-act="ai-model-toggle" title="${models.length ? '从拉取到的模型里选择' : '先点「拉取模型列表」'}">${icon('chevron', 13)}</button>
    <div class="combo-list" id="ai-model-pop" hidden>${items || '<div class="combo-empty">还没有拉取模型列表</div>'}</div>
  </div>`;
}

function modelHint() {
  const models = state.cache.modelList || [];
  if (!models.length) return '点「拉取模型列表」可列出端点上的模型，再点输入框右侧箭头直接选。';
  return `已拉取 ${models.length} 个模型：点输入框右侧箭头可切换，也可以直接手填。`;
}

function toggleModelPop(force) {
  const pop = $('#ai-model-pop');
  if (!pop) return;
  const models = state.cache.modelList || [];
  if (!models.length) { toast('先点「拉取模型列表」', 'err'); return; }
  const show = force === undefined ? pop.hidden : force;
  pop.hidden = !show;
  const combo = $('#ai-model-combo');
  if (combo) combo.classList.toggle('open', show);
}

function closeModelPop() {
  const pop = $('#ai-model-pop');
  if (pop && !pop.hidden) { pop.hidden = true; }
  const combo = $('#ai-model-combo');
  if (combo) combo.classList.remove('open');
}

async function renderSettings() {
  const s = await api('/api/settings');
  const scan = s.scan, alert = s.alert, ai = s.ai;
  const [allow, aiStatus] = await Promise.all([api('/api/allowlist'), api('/api/ai/status')]);
  const tools = s.integrations.external_tools || {};
  const disc = s.discovery || {};
  const katana = ((s.analyzer_specs || {}).discovery || {}).katana || null;
  const analyzer_specs = s.analyzer_specs || {};
  const analyzer_cfg = s.analyzers || {};
  const gate = s.ai_gate || {};
  state.cache.gateThreshold = gate.fp_threshold ?? 0.6;
  const sched = s.scheduler || {};
  const scanner_specs = s.target_scanners || {};
  const scanner_cfg = s.target_scanner_config || {};
  $('#view').innerHTML = `
    <div class="grid cols-2b">
      <section class="card">
        <div class="card-head"><h2>采集参数</h2><span class="sub">影响所有站点的默认行为</span></div>
        <div class="card-body" style="display:flex;flex-direction:column;gap:13px">
          <div class="form-row">
            <label class="field">站点并行数
              <input type="number" id="s-parallel" min="1" max="512" value="${esc(sched.max_parallel_targets ?? 3)}">
            </label>
            <label class="field">调度 tick (秒)
              <input type="number" id="s-tick" min="1" max="120" value="${esc(sched.tick_seconds ?? 5)}">
            </label>
          </div>
          <div class="field-hint">
            站点并行数要按 <span class="mono">站点数 × 单站耗时 ÷ 巡检周期</span> 估：
            例如 1000 个站点、每站 30 秒、每小时一轮 → 需要约 9 个并行。改完重启生效。
          </div>
          <div class="form-row">
            <label class="field">全局并发请求数<input type="number" id="s-conc" min="1" max="32" value="${esc(scan.max_concurrency)}"></label>
            <label class="field">单站请求间隔 (毫秒)<input type="number" id="s-delay" min="0" max="5000" value="${esc(scan.per_host_delay_ms)}"></label>
          </div>
          <div class="form-row-3">
            <label class="field">请求超时 (秒)<input type="number" id="s-timeout" min="3" max="120" value="${esc(scan.timeout_seconds)}"></label>
            <label class="field">失败重试次数<input type="number" id="s-retries" min="0" max="3" value="${esc(scan.max_retries ?? 1)}"></label>
            <label class="field">单资产大小上限 (MB)<input type="number" id="s-maxbytes" min="0" step="0.5" value="${esc(bytesToMb(scan.max_asset_bytes))}"></label>
          </div>
          <div class="form-row">
            <label class="field">单站资产上限<input type="number" id="s-maxassets" min="1" max="5000" value="${esc(scan.max_assets_per_scan)}"></label>
            <label class="field">页面递归深度<input type="number" id="s-depth" min="0" max="4" value="${esc(scan.max_depth)}"></label>
          </div>
          <div class="field-hint">
            重试只作用于「连接没建立起来」和「连接被中途掐断」，站点自己响应慢不重试。
            单资产大小上限填 <span class="mono">0</span> 表示不限制，整份文件都会下载并扫描。
          </div>
          <label class="field">User-Agent<input type="text" id="s-ua" value="${esc(scan.user_agent)}"></label>
          <label class="field">代理地址 (可选)<input type="text" id="s-proxy" placeholder="http://127.0.0.1:8080" value="${esc(scan.proxy || '')}"></label>
          <div class="form-row">
            <label class="field">额外请求头 (每行 <span class="mono">K: V</span>)
              <input type="text" id="s-headers" placeholder="${scan.credential_headers && scan.credential_headers.length ? '已配置: ' + esc(scan.credential_headers.join(', ')) + '（留空不改动）' : '留空 = 匿名采集'}">
            </label>
            <label class="field">Cookie
              <input type="text" id="s-cookies" placeholder="${scan.has_cookies ? '已配置（留空不改动）' : '留空 = 匿名采集'}">
            </label>
          </div>
          <div class="field-hint">
            当前模式：<b>${esc(scan.credential_mode || '匿名采集')}</b>。带凭据采集只用于自有或已授权目标，
            它能覆盖"登录后才下发"的 JS；凭据明文存于本机数据库。
            <button class="btn btn-sm" data-act="clear-credentials" style="margin-left:6px">清除凭据</button>
          </div>
          <div style="display:flex;flex-direction:column;gap:9px">
            <label class="switch"><input type="checkbox" id="s-maps" ${scan.follow_sourcemaps ? 'checked' : ''}><span class="track"></span>抓取并扫描 sourcemap</label>
            <label class="switch"><input type="checkbox" id="s-probe" ${scan.probe_common_config ? 'checked' : ''}><span class="track"></span>探测常见配置入口</label>
            <label class="switch"><input type="checkbox" id="s-cross" ${scan.allow_cross_origin_js ? 'checked' : ''}><span class="track"></span>允许采集跨域脚本</label>
            <label class="switch"><input type="checkbox" id="s-tls" ${scan.verify_tls ? 'checked' : ''}><span class="track"></span>校验 TLS 证书</label>
            <label class="switch"><input type="checkbox" id="s-raw" ${scan.store_raw_secrets ? 'checked' : ''}><span class="track"></span>入库保存明文命中值 (默认关闭)</label>
            <label class="switch"><input type="checkbox" id="s-api" ${scan.scan_api_endpoints ? 'checked' : ''}><span class="track"></span>扫描接口响应 (只 GET 同源读接口)</label>
            <label class="switch"><input type="checkbox" id="s-headless" ${scan.headless_render ? 'checked' : ''}><span class="track"></span>无头浏览器渲染页面 (需 Chrome，明显更慢)</label>
          </div>
          <div class="form-row">
            <label class="field">单站接口上限 (条)
              <input type="number" id="s-apimax" min="0" max="200" value="${esc(scan.max_api_endpoints || 20)}">
              <span class="field-hint">只收 JS 里以 GET 语义出现的同源地址；带变量的模板地址一律跳过，不猜参数。</span>
            </label>
            <label class="field">无头渲染页数 (个)
              <input type="number" id="s-renderpages" min="1" max="10" value="${esc(scan.max_render_pages || 1)}">
              <span class="field-hint">渲染会执行页面 JS，能拿到运行时才出现的脚本与接口；走匿名请求，不带采集凭据。</span>
            </label>
            <label class="field">渲染等待 (毫秒)
              <input type="number" id="s-renderwait" min="500" max="30000" step="500" value="${esc(scan.render_wait_ms || 4000)}">
            </label>
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn btn-primary btn-sm" data-act="save-scan">保存采集参数</button>
            <span class="field-hint" style="align-self:center">开启明文入库会提高数据泄露风险，仅在必要时使用。</span>
          </div>
          <div style="border-top:1px solid var(--line-soft);padding-top:11px;display:flex;flex-direction:column;gap:11px">
            <div class="form-row">
              <label class="field">采集后端
                <select id="s-discovery">
                  <option value="builtin"${(disc.backend || 'builtin') === 'builtin' ? ' selected' : ''}>内置展开 (引用 + chunk 映射 + sourcemap)</option>
                  <option value="katana"${disc.backend === 'katana' ? ' selected' : ''}>内置 + Katana 补充种子</option>
                </select>
              </label>
              <label class="field">Katana 抓取深度
                <input type="number" id="s-kdepth" min="1" max="5" value="${esc((disc.katana && disc.katana.depth) || 2)}">
              </label>
            </div>
            <label class="switch"><input type="checkbox" id="s-kheadless" ${disc.katana && disc.katana.headless ? 'checked' : ''}><span class="track"></span>Katana 用无头浏览器渲染 (需 Chrome, 明显更慢)</label>
            <div class="field-hint">
              ${katana && katana.available
                ? `Katana 已就绪。实测本机样例站单轮从 7.4 秒升到 25.6 秒，且静态模式仍发现不了 webpack 按需 chunk 与 sourcemap，因此它只作额外种子来源，内置展开始终保留。`
                : '未检测到 Katana，安装后此处自动可用。'}
            </div>
          </div>
        </div>
      </section>

      <section class="card">
        <div class="card-head"><h2>飞书告警</h2><span class="sub">${alert.enabled ? '已启用' : '未启用'}</span></div>
        <div class="card-body" style="display:flex;flex-direction:column;gap:13px">
          <label class="switch"><input type="checkbox" id="a-enabled" ${alert.enabled ? 'checked' : ''}><span class="track"></span>发现新泄露时推送飞书</label>
          <label class="field">接入方式
            <select id="a-channel">
              <option value="webhook"${alert.channel === 'webhook' ? ' selected' : ''}>自定义机器人 Webhook (最简单)</option>
              <option value="app"${alert.channel === 'app' ? ' selected' : ''}>企业自建应用 (可指定群/人)</option>
            </select>
          </label>
          <div id="chan-webhook" class="${alert.channel === 'webhook' ? '' : 'hidden'}">
            <label class="field">Webhook 地址
              <input type="text" id="a-webhook" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..." value="${esc(alert.webhook_url)}">
            </label>
          </div>
          <div id="chan-app" class="${alert.channel === 'app' ? '' : 'hidden'}" style="display:flex;flex-direction:column;gap:13px">
            <div class="form-row">
              <label class="field">App ID<input type="text" id="a-appid" placeholder="cli_xxxxxxxx" value="${esc(alert.app_id)}"></label>
              <label class="field">App Secret<input type="password" id="a-secret" placeholder="${alert.has_app_secret ? '已保存，留空不修改' : '请输入'}"></label>
            </div>
            <label class="field">接收方 ID
              <input type="text" id="a-chat" placeholder="oc_ 开头的群 ID 或 ou_ 用户 ID" value="${esc(alert.chat_id)}">
              <span class="field-hint">机器人需已被拉入目标群，并具备 im:message 权限。</span>
            </label>
          </div>
          <div class="form-row-3">
            <label class="field">最低推送等级
              <select id="a-mins">
                ${Object.keys(SEVERITY).map((k) => `<option value="${k}"${alert.min_severity === k ? ' selected' : ''}>${SEVERITY[k].label}</option>`).join('')}
              </select>
            </label>
            <label class="field">汇总阈值 (条)
              <input type="number" id="a-digest" min="1" max="100" value="${esc(alert.digest_threshold)}">
            </label>
            <label class="field">单轮上限 (条)
              <input type="number" id="a-max" min="1" max="200" value="${esc(alert.max_alerts_per_run)}">
            </label>
          </div>
          <label class="field">@ 成员 (逗号分隔)
            <input type="text" id="a-at" placeholder="ou_xxx,ou_yyy" value="${esc((alert.at_user_ids || []).join(','))}">
          </label>
          <label class="field">通用 Webhook (逗号分隔, JSON POST)
            <input type="text" id="a-extra" value="${esc((alert.extra_webhooks || []).join(','))}">
          </label>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <button class="btn btn-primary btn-sm" data-act="save-alert">保存告警设置</button>
            <button class="btn btn-sm" data-act="test-alert">${icon('send', 13)}发送测试消息</button>
            <span class="field-hint">单轮新发现超过汇总阈值时合并为一条汇总卡片；AI 复核判定为误报的不会推送，卡片上会标注 AI 结论。</span>
          </div>
          ${alertStatusLine(s.alert_status, (SEVERITY[alert.min_severity] || {}).label || alert.min_severity)}
        </div>
      </section>
    </div>

    <div class="grid cols-2b" style="margin-top:12px">
      <section class="card">
        <div class="card-head">
          <h2>AI 复核</h2>
          <span class="sub">${ai.enabled ? `已启用 · ${esc(ai.model || '未选模型')}` : '未启用'}</span>
        </div>
        <div class="card-body" style="display:flex;flex-direction:column;gap:13px">
          <label class="switch"><input type="checkbox" id="ai-enabled" ${ai.enabled ? 'checked' : ''}><span class="track"></span>启用 AI 复核与语义补漏</label>

          <div class="form-row">
            <label class="field">接入方预设
              <select id="ai-preset">
                <option value="">— 选择预设 —</option>
                ${Object.keys(ai.presets).map((key) => `<option value="${esc(key)}"${ai.preset === key ? ' selected' : ''}>${esc(ai.presets[key].label)}</option>`).join('')}
              </select>
            </label>
            <label class="field">协议
              <select id="ai-kind">
                <option value="openai"${ai.kind === 'openai' ? ' selected' : ''}>OpenAI 兼容 (GLM / Qwen / vLLM / Ollama)</option>
                <option value="anthropic"${ai.kind === 'anthropic' ? ' selected' : ''}>Anthropic</option>
              </select>
            </label>
          </div>

          <label class="field">接口地址 (OpenAI 兼容 base_url)
            <input type="text" id="ai-base" placeholder="http://glm.corp.example.com/v1" value="${esc(ai.base_url)}">
            <span class="field-hint">官方文档给的地址直接粘即可（带不带 <span class="mono">/v1</span> 都能识别，完整 endpoint 也行）；内网无鉴权时 API Key 留空。</span>
          </label>

          <div class="form-row">
            <div class="field-plain">
              <span>模型</span>
              ${modelCombo(ai.model)}
              <span class="field-hint" id="ai-model-hint">${modelHint()}</span>
            </div>
            <label class="field">API Key
              <input type="password" id="ai-key" placeholder="${ai.has_api_key ? '已保存，留空不修改' : '无鉴权可留空'}">
            </label>
          </div>

          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
            <button class="btn btn-sm" data-act="ai-apply-preset">填入预设</button>
            <button class="btn btn-sm" data-act="ai-fetch-models">${icon('refresh', 13)}拉取模型列表</button>
            <button class="btn btn-sm" data-act="ai-test">${icon('zap', 13)}测试连接</button>
            <button class="btn btn-primary btn-sm" data-act="save-ai">保存 AI 设置</button>
          </div>
          <div class="field-hint" id="ai-test-result"></div>

          <div style="display:flex;flex-direction:column;gap:9px;border-top:1px solid var(--line-soft);padding-top:12px">
            <label class="switch"><input type="checkbox" id="ai-verify" ${ai.verify_new_findings ? 'checked' : ''}><span class="track"></span>扫描后自动复核新发现</label>
            <label class="switch"><input type="checkbox" id="ai-auto-fp" ${ai.auto_mark_false_positive ? 'checked' : ''}><span class="track"></span>高置信度误报自动标记为「误报」</label>
            <label class="switch"><input type="checkbox" id="ai-semantic" ${ai.semantic_scan ? 'checked' : ''}><span class="track"></span>开启语义补漏 (会把资产内容发给模型)</label>
            <label class="switch"><input type="checkbox" id="ai-raw" ${ai.send_raw ? 'checked' : ''}><span class="track"></span>复核时发送明文命中值 (默认只发掩码)</label>
          </div>

          <div class="form-row-3">
            <label class="field">误报自动标记阈值
              <input type="number" id="ai-fpconf" min="0.5" max="1" step="0.05" value="${esc(ai.auto_fp_confidence)}">
            </label>
            <label class="field">单轮复核上限
              <input type="number" id="ai-perscan" min="0" max="200" value="${esc(ai.max_calls_per_scan)}">
            </label>
            <label class="field">每日调用上限
              <input type="number" id="ai-perday" min="0" max="100000" value="${esc(ai.max_calls_per_day)}">
            </label>
          </div>
          <div class="form-row-3">
            <label class="field">语义审计资产数
              <input type="number" id="ai-maxassets" min="1" max="30" value="${esc(ai.semantic_max_assets)}">
            </label>
            <label class="field">单资产最大字符
              <input type="number" id="ai-maxchars" min="2000" max="60000" step="1000" value="${esc(ai.semantic_max_chars)}">
            </label>
            <label class="field">请求超时 (秒)
              <input type="number" id="ai-timeout" min="10" max="300" value="${esc(ai.timeout)}">
            </label>
          </div>

          <div style="border-top:1px solid var(--line-soft);padding-top:11px;display:flex;flex-direction:column;gap:10px">
            <label class="switch"><input type="checkbox" id="gate-enabled" ${gate.enabled !== false ? 'checked' : ''}><span class="track"></span>高误报来源先由 AI 研判，确认后再展示</label>
            <label class="switch"><input type="checkbox" id="gate-hide-fake" ${gate.hide_ai_fake !== false ? 'checked' : ''}><span class="track"></span>AI 已判定为误报的也不再展示（关掉可看到全部）</label>
            <div class="form-row">
              <label class="field">误报率阈值 (%)
                <input type="number" id="gate-threshold" min="10" max="100" step="5" value="${Math.round((gate.fp_threshold ?? 0.6) * 100)}">
              </label>
              <label class="field">最小判定样本数
                <input type="number" id="gate-samples" min="1" max="50" value="${gate.min_samples ?? 3}">
              </label>
            </div>
            <div class="field-hint" id="gate-hint">
              ${gateBarText(gate.summary)}
            </div>
          </div>

          <div style="border-top:1px solid var(--line-soft);padding-top:11px;display:flex;flex-direction:column;gap:7px;font-size:12.5px">
            <div class="list-row">
              <span class="grow">今日用量</span>
              <span class="mono muted">调用 ${aiStatus.usage.calls} · 失败 ${aiStatus.usage.fails} · 缓存命中 ${aiStatus.usage.cached} · 剩余额度 ${aiStatus.budget_left}</span>
            </div>
            <div class="list-row">
              <span class="grow">复核结果分布</span>
              <span class="muted">${['real', 'fake', 'public', 'uncertain'].map((k) => `${VERDICT[k].label} ${aiStatus.by_verdict[k] || 0}`).join(' · ')}</span>
            </div>
            <div class="list-row">
              <span class="grow">响应缓存条目</span>
              <span class="mono muted">${aiStatus.cache_entries}</span>
            </div>
            <div class="muted" style="font-size:11.5px;line-height:1.7">
              复核默认只发送掩码值与上下文，明文不出本机；语义补漏会把资产内容发给模型，
              且会先把规则已命中的密钥替换掉。两者都受每日调用上限与内容缓存约束。
            </div>
          </div>
        </div>
      </section>

      <div style="display:flex;flex-direction:column;gap:12px">
      <section class="card">
        <div class="card-head"><h2>误报白名单</h2><span class="sub">命中值的正则，匹配则不再上报</span></div>
        <div class="card-body" style="display:flex;flex-direction:column;gap:11px">
          <div style="display:flex;gap:8px">
            <input type="text" id="w-pattern" placeholder="例如 ^AIzaSy[A-Za-z0-9_-]{33}$ 或 fe-preview">
            <button class="btn btn-sm btn-primary" data-act="add-allowlist">${icon('plus', 13)}添加</button>
          </div>
          ${allow.length ? `<ul class="list-plain">${allow.map((a) => `
            <li class="list-row">
              <span class="grow mono" style="font-size:11.5px">${esc(a.pattern)}</span>
              <span class="muted">${esc(a.reason || '')}</span>
              <button class="btn btn-icon btn-sm btn-danger" data-act="del-allowlist" data-id="${a.id}">${icon('trash', 13)}</button>
            </li>`).join('')}</ul>`
            : '<div class="muted" style="font-size:12.5px">暂无白名单规则。</div>'}
        </div>
      </section>

      <section class="card">
        <div class="card-head"><h2>运行环境</h2></div>
        <div class="card-body" style="display:flex;flex-direction:column;gap:9px;font-size:12.5px">
          <div class="list-row"><span class="grow">服务版本</span><span class="mono muted">${esc(s.server.version)}</span></div>
          <div class="list-row"><span class="grow">监听地址</span><span class="mono muted">${esc(s.server.host)}:${esc(s.server.port)}</span></div>
          <div class="list-row"><span class="grow">数据目录</span><span class="mono muted">${esc(s.server.data_dir)}</span></div>
          <div class="list-row"><span class="grow">规则版本</span><span class="mono muted">rev ${esc(s.rules_revision)}</span></div>
          <div class="list-row"><span class="grow">gitleaks</span><span class="tag ${tools.gitleaks ? 'tag-ok' : ''}">${tools.gitleaks ? '已检测到' : '未安装'}</span></div>
          <div class="list-row"><span class="grow">trufflehog</span><span class="tag ${tools.trufflehog ? 'tag-ok' : ''}">${tools.trufflehog ? '已检测到' : '未安装'}</span></div>
          <div class="muted" style="font-size:11.5px;line-height:1.7">
            本系统面向授权范围内的资产安全巡检。采集只使用公开可访问的页面与脚本，
            不进行漏洞利用；请确保你对被监测站点拥有授权。
          </div>
        </div>
      </section>
      </div>
    </div>`;

  const analyzerEntries = Object.entries(analyzer_specs.analyzer || {})
    .filter(([key]) => key !== 'builtin')
    .map(([key, meta]) => {
      const name = key.replace(/^cli:/, '');
      const conf = ((analyzer_cfg.cli_analyzers || {})[name]) || {};
      const enabled = conf.enabled !== false;
      return `<div class="list-row">
        <label class="switch"><input type="checkbox" data-act="analyzer-toggle" data-name="${esc(name)}" ${enabled ? 'checked' : ''}><span class="track"></span></label>
        <span class="grow">
          <b>${esc(meta.label || name)}</b>
          <span class="tag ${meta.available ? 'tag-ok' : 'tag-err'}" style="margin-left:6px">${meta.available ? '命令可用' : '命令不可用'}</span>
          <div class="muted mono" style="font-size:11px;margin-top:2px">${esc(meta.command || '')}</div>
        </span>
        <label class="field" style="width:110px">资产上限
          <input type="number" data-analyzer-max="${esc(name)}" min="1" max="2000" value="${esc(conf.max_assets || 80)}">
        </label>
        <label class="field" style="width:120px">大小上限 (MB)
          <input type="number" data-analyzer-bytes="${esc(name)}" min="0" step="0.5" value="${esc(bytesToMb(conf.max_bytes))}">
        </label>
      </div>`;
    }).join('');

  $('#view').insertAdjacentHTML('beforeend', `
    <div class="grid" style="margin-top:12px">
      <section class="card">
        <div class="card-head"><h2>外部分析器（并联发现）</h2>
          <span class="sub">与规则引擎同时运行，命中并入同一套发现体系</span></div>
        <div class="card-body" style="display:flex;flex-direction:column;gap:11px">
          <label class="switch"><input type="checkbox" id="an-run" ${analyzer_cfg.run_in_scan !== false ? 'checked' : ''}><span class="track"></span>扫描时并联运行外部分析器</label>
          ${analyzerEntries || '<div class="muted" style="font-size:12.5px">还没有登记外部分析器。用命令行登记后会自动出现在这里：<br><span class="mono">python3.10 tools/benchmark.py add-analyzer --name jshawk --command "jshawk scan --json {file}"</span></div>'}
          <div class="field-hint">
            并联只跑在"新增或内容变化"的资产上，稳态开销接近零；同一条凭证被多个分析器发现时只保留一条，
            并在发现列表里标注来源归属（<span class="mono">builtin + cli:xxx</span>），不会被重复催办。
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <button class="btn btn-primary btn-sm" data-act="save-analyzers">保存并联设置</button>
            <span class="field-hint">外部分析器失败会在事件里记一笔，不会影响规则扫描本身。</span>
          </div>
        </div>
      </section>
    </div>`);

  const scannerEntries = Object.entries(scanner_specs).map(([name, meta]) => {
    const conf = scanner_cfg[name] || {};
    return `<div class="list-row" style="align-items:flex-start">
      <label class="switch" style="margin-top:3px"><input type="checkbox" data-act="scanner-toggle" data-name="${esc(name)}" ${meta.enabled ? 'checked' : ''}><span class="track"></span></label>
      <span class="grow">
        <b>${esc(meta.label || name)}</b>
        <span class="tag ${meta.available ? 'tag-ok' : 'tag-err'}" style="margin-left:6px">${meta.available ? '可用' : '未配置/不可用'}</span>
        <span class="tag${conf.use_ai ? ' tag-run' : ''}" style="margin-left:4px">${conf.use_ai ? '用它的模型判定' : '判定交给本系统 AI'}</span>
        <div class="muted" style="font-size:11.5px;margin-top:3px">工具目录：<span class="mono">${esc(conf.module_dir || '未填写')}</span></div>
      </span>
      <label class="field" style="width:130px">运行方式
        <select data-scanner-mode="${esc(name)}">
          <option value="run"${(conf.mode || 'run') === 'run' ? ' selected' : ''}>扫描时调起</option>
          <option value="import"${conf.mode === 'import' ? ' selected' : ''}>只导入已有结果</option>
        </select>
      </label>
      <label class="field" style="width:110px">超时 (秒)
        <input type="number" min="30" max="3600" data-scanner-timeout="${esc(name)}" value="${esc(conf.timeout || 600)}">
      </label>
    </div>`;
  }).join('');

  $('#view').insertAdjacentHTML('beforeend', `
    <div class="grid" style="margin-top:12px">
      <section class="card">
        <div class="card-head"><h2>整站扫描器</h2>
          <span class="sub">自带抓取的工具，由本系统按站点调起后并入发现</span></div>
        <div class="card-body" style="display:flex;flex-direction:column;gap:11px">
          ${scannerEntries || '<div class="muted" style="font-size:12.5px">还没有登记整站扫描器。</div>'}
          <div class="field-hint">
            与上面的「逐资产并联」不同：这类工具自己爬、自己分析，接入方式是「按站点调起一轮 → 读它的结果 → 并入同一套发现」。
            同一目标下重复命中的凭证只保留一条并记录来源，增量比对、AI 复核、飞书告警、界面全部复用。
            建议把它的 AI 关掉（判定交给本系统 AI）：省一份模型费用，判定口径也统一。
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <button class="btn btn-primary btn-sm" data-act="save-scanners">保存整站扫描器设置</button>
            <span class="field-hint">外部工具超时或报错只在事件里记一笔，不影响主扫描。</span>
          </div>
        </div>
      </section>
    </div>`);

  const chan = $('#a-channel');
  chan.onchange = () => {
    $('#chan-webhook').classList.toggle('hidden', chan.value !== 'webhook');
    $('#chan-app').classList.toggle('hidden', chan.value !== 'app');
  };
}

async function saveScanSettings() {
  const headerText = $('#s-headers').value.trim();
  const cookieText = $('#s-cookies').value.trim();
  const extraHeaders = {};
  headerText.split('\n').map((line) => line.trim()).filter(Boolean).forEach((line) => {
    const idx = line.indexOf(':');
    if (idx > 0) extraHeaders[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  });
  const payload = {
    scan: {
      max_concurrency: Number($('#s-conc').value),
      per_host_delay_ms: Number($('#s-delay').value),
      timeout_seconds: Number($('#s-timeout').value),
      max_retries: Number($('#s-retries').value || 0),
      max_asset_bytes: Math.round(Number($('#s-maxbytes').value || 0) * 1024 * 1024),
      max_assets_per_scan: Number($('#s-maxassets').value),
      max_depth: Number($('#s-depth').value),
      user_agent: $('#s-ua').value,
      proxy: $('#s-proxy').value.trim(),
      follow_sourcemaps: $('#s-maps').checked,
      probe_common_config: $('#s-probe').checked,
      allow_cross_origin_js: $('#s-cross').checked,
      verify_tls: $('#s-tls').checked,
      store_raw_secrets: $('#s-raw').checked,
      scan_api_endpoints: $('#s-api').checked,
      max_api_endpoints: Number($('#s-apimax').value || 20),
      headless_render: $('#s-headless').checked,
      max_render_pages: Number($('#s-renderpages').value || 1),
      render_wait_ms: Number($('#s-renderwait').value || 4000),
    },
    discovery: {
      backend: $('#s-discovery').value,
      katana: { depth: Number($('#s-kdepth').value || 2), headless: $('#s-kheadless').checked },
    },
    scheduler: {
      max_parallel_targets: Number($('#s-parallel').value || 3),
      tick_seconds: Number($('#s-tick').value || 5),
    },
  };
  // 留空表示"不改动", 避免把已保存的凭据误清掉
  if (Object.keys(extraHeaders).length) payload.scan.extra_headers = extraHeaders;
  if (cookieText) payload.scan.cookies = cookieText;
  try {
    await api('/api/settings', { method: 'PUT', body: JSON.stringify(payload) });
    toast('采集参数已保存', 'ok');
  } catch (err) { toast('保存失败: ' + err.message, 'err'); }
}

async function saveAlertSettings() {
  const split = (v) => v.split(',').map((x) => x.trim()).filter(Boolean);
  const payload = {
    alert: {
      enabled: $('#a-enabled').checked,
      channel: $('#a-channel').value,
      webhook_url: $('#a-webhook').value.trim(),
      app_id: $('#a-appid').value.trim(),
      chat_id: $('#a-chat').value.trim(),
      min_severity: $('#a-mins').value,
      digest_threshold: Number($('#a-digest').value),
      max_alerts_per_run: Number($('#a-max').value),
      at_user_ids: split($('#a-at').value),
      extra_webhooks: split($('#a-extra').value),
    },
  };
  const secret = $('#a-secret').value.trim();
  if (secret) payload.alert.app_secret = secret;
  try {
    await api('/api/settings', { method: 'PUT', body: JSON.stringify(payload) });
    toast('告警设置已保存', 'ok');
    refresh();
  } catch (err) { toast('保存失败: ' + err.message, 'err'); }
}

function readAIFields() {
  const payload = {
    enabled: $('#ai-enabled').checked,
    preset: $('#ai-preset').value,
    kind: $('#ai-kind').value,
    base_url: $('#ai-base').value.trim(),
    model: $('#ai-model').value.trim(),
    verify_new_findings: $('#ai-verify').checked,
    auto_mark_false_positive: $('#ai-auto-fp').checked,
    semantic_scan: $('#ai-semantic').checked,
    send_raw: $('#ai-raw').checked,
    auto_fp_confidence: Number($('#ai-fpconf').value || 0.85),
    max_calls_per_scan: Number($('#ai-perscan').value || 20),
    max_calls_per_day: Number($('#ai-perday').value || 500),
    semantic_max_assets: Number($('#ai-maxassets').value || 5),
    semantic_max_chars: Number($('#ai-maxchars').value || 12000),
    timeout: Number($('#ai-timeout').value || 60),
  };
  payload.ai_gate = {
    enabled: $('#gate-enabled').checked,
    hide_ai_fake: $('#gate-hide-fake').checked,
    fp_threshold: Math.max(0.05, Math.min(1, Number($('#gate-threshold').value || 60) / 100)),
    min_samples: Math.max(1, Number($('#gate-samples').value || 3)),
  };
  const key = $('#ai-key').value.trim();
  if (key) payload.api_key = key;
  return payload;
}

async function saveAISettings() {
  if (!$('#ai-base').value.trim()) { toast('请填写接口地址', 'err'); return; }
  if ($('#ai-enabled').checked && !$('#ai-model').value.trim()) {
    toast('启用前请填写模型名称，可先点「拉取模型列表」', 'err');
    return;
  }
  try {
    const fields = readAIFields();
    const gateCfg = fields.ai_gate;
    delete fields.ai_gate;      // 门控走独立字段, 不混进 ai 配置
    await api('/api/settings', { method: 'PUT', body: JSON.stringify({ ai: fields, ai_gate: gateCfg }) });
    toast('AI 设置已保存', 'ok');
    refresh();
  } catch (err) { toast('保存失败: ' + err.message, 'err'); }
}

async function saveScannerSettings() {
  const target = {};
  $$('[data-act="scanner-toggle"]').forEach((box) => {
    target[box.dataset.name] = { ...(target[box.dataset.name] || {}), enabled: box.checked };
  });
  $$('[data-scanner-mode]').forEach((select) => {
    const name = select.dataset.scannerMode;
    target[name] = { ...(target[name] || {}), mode: select.value };
  });
  $$('[data-scanner-timeout]').forEach((input) => {
    const name = input.dataset.scannerTimeout;
    target[name] = { ...(target[name] || {}), timeout: Math.max(30, Number(input.value || 600)) };
  });
  try {
    await api('/api/settings', { method: 'PUT', body: JSON.stringify({
      analyzers: { target_scanners: target },
    }) });
    toast('整站扫描器设置已保存', 'ok');
    refresh();
  } catch (err) { toast('保存失败: ' + err.message, 'err'); }
}

async function saveAnalyzerSettings() {
  const cli = {};
  $$('[data-act="analyzer-toggle"]').forEach((box) => {
    const name = box.dataset.name;
    cli[name] = { ...(cli[name] || {}), enabled: box.checked };
  });
  $$('[data-analyzer-max]').forEach((input) => {
    const name = input.dataset.analyzerMax;
    cli[name] = { ...(cli[name] || {}), max_assets: Number(input.value || 80) };
  });
  $$('[data-analyzer-bytes]').forEach((input) => {
    const name = input.dataset.analyzerBytes;
    cli[name] = { ...(cli[name] || {}), max_bytes: Math.round(Number(input.value || 0) * 1024 * 1024) };
  });
  try {
    await api('/api/settings', { method: 'PUT', body: JSON.stringify({
      analyzers: { run_in_scan: $('#an-run').checked, cli_analyzers: cli },
    }) });
    toast('并联设置已保存', 'ok');
    refresh();
  } catch (err) { toast('保存失败: ' + err.message, 'err'); }
}

/* ------------------------------------------------------------------ 路由 */

function renderNav() {
  const { path } = parseHash();
  const counts = (state.live && state.live.counts) || {};
  $('#nav').innerHTML = NAV.map((item) => {
    let badge = '';
    if (item.path === 'findings' && counts.new) badge = `<span class="count hot">${counts.new}</span>`;
    if (item.path === 'targets' && counts.targets) badge = `<span class="count">${counts.targets}</span>`;
    return `<a href="#/${item.path}" class="${path === item.path ? 'active' : ''}">${icon(item.icon)}<span>${item.label}</span>${badge}</a>`;
  }).join('');
}

function renderActions(path) {
  const actions = {
    overview: `<button class="btn btn-sm" data-act="refresh">${icon('refresh', 13)}刷新</button>`,
    targets: `<button class="btn btn-primary btn-sm" data-act="add-target">${icon('plus', 13)}新增站点</button>`,
    findings: `<button class="btn btn-sm" data-act="nav" data-to="settings">告警设置${icon('chevron', 12)}</button>`,
    assets: `<button class="btn btn-sm" data-act="nav" data-to="targets">站点管理${icon('chevron', 12)}</button>`,
    rules: `<button class="btn btn-sm" data-act="refresh">${icon('refresh', 13)}刷新</button>`,
    settings: `<button class="btn btn-sm" data-act="refresh">${icon('refresh', 13)}刷新</button>`,
  };
  $('#page-actions').innerHTML = actions[path] || '';
}

async function render() {
  const { path, query } = parseHash();
  hideTip();  // 重渲染会把旧的悬停目标换掉, 先收起说明气泡
  // 离开发现页时收起详情抽屉; 发现页内部的刷新保持打开
  if (path !== 'findings' || (!query.finding && !state.openFindingId)) closeDrawer();
  const [title, sub] = TITLES[path] || TITLES.overview;
  $('#page-title').textContent = title;
  $('#page-sub').textContent = sub;
  renderNav();
  renderActions(path);
  const view = $('#view');
  // 已经有内容时不要先清空: 扫描期间页面会被 SSE 频繁重绘, 每次清空再填会让人
  // 觉得"一直加载中"。新数据到了直接替换; 失败则保留旧内容并提示。
  const hadContent = view.dataset.page === path && view.innerText.trim() !== '';
  if (!hadContent) view.innerHTML = '<div class="skeleton">加载中…</div>';
  try {
    if (path === 'overview') await renderOverview();
    else if (path === 'targets') await renderTargets();
    else if (path === 'findings') await renderFindings();
    else if (path === 'assets') await renderAssets();
    else if (path === 'rules') await renderRules();
    else if (path === 'settings') await renderSettings();
    else await renderOverview();
    view.dataset.page = path;
  } catch (err) {
    if (hadContent) toast('刷新失败: ' + err.message, 'err');
    else view.innerHTML = `<div class="empty">加载失败：${esc(err.message)}<br>
      <button class="btn btn-sm" style="margin-top:10px" data-act="reload-page">重试</button></div>`;
  }
}

async function refresh() {
  state.hash = location.hash;
  state.overview = await api('/api/overview').catch(() => state.overview);
  renderNav();
  updateStatusLines();
  await render();
}

/* ------------------------------------------------------------------ 状态栏 */

function updateStatusLines() {
  const live = state.live || {};
  const sched = live.scheduler || {};
  const dot = sched.running ? 'dot-run' : 'dot-ok';
  const text = sched.running
    ? `正在扫描 ${sched.running} 个站点`
    : `调度器运行中 · 已完成 ${sched.completed || 0} 轮`;
  $('#sched-status').innerHTML = `<span class="dot ${dot}"></span><span>${esc(text)}</span>`;
  const alertOn = state.overview && state.overview.scheduler && state.overview.scheduler.alert_enabled;
  $('#alert-status').textContent = alertOn ? '飞书告警已启用' : '飞书告警未启用';
}

function initStream() {
  const source = new EventSource('/api/stream');
  source.onmessage = (event) => {
    let data;
    try { data = JSON.parse(event.data); } catch (e) { return; }
    const prev = state.live;
    state.live = data;
    updateStatusLines();
    renderNav();
    if (prev && prev.counts && data.counts && data.counts.new > prev.counts.new) {
      toast(`新增 ${data.counts.new - prev.counts.new} 条发现`, 'err');
      state.overview = null;
      const { path } = parseHash();
      if (path === 'overview' || path === 'findings') render();
    }
    if (prev && prev.scheduler && data.scheduler
        && data.scheduler.completed !== prev.scheduler.completed) {
      state.overview = null;
      // 只重绘概览: 设置/规则是表单页, 后台每完成一轮就整页重绘会把用户填了一半的内容
      // 和刚拉取的模型列表一起清掉（表现为"下拉选择失效"）
      if (parseHash().path === 'overview') render();
    }
  };
  source.onerror = () => { /* 浏览器会自动重连 */ };
}

/* ------------------------------------------------------------------ 动作 */

function closeDrawer() {
  $('#drawer').hidden = true;
  $('#scrim').hidden = true;
  state.openFindingId = null;
}

function closeModal() {
  $('#modal-scrim').hidden = true;
  $('#modal').innerHTML = '';
}

async function handleAction(el, evt) {
  const act = el.dataset.act;
  if (!act) return;
  const event = evt || window.event;
  const stop = (e) => { if (e) { e.preventDefault(); e.stopPropagation(); } };

  if (act === 'nav') { stop(event); goto(el.dataset.to, el.dataset.query ? Object.fromEntries(new URLSearchParams(el.dataset.query)) : undefined); return; }
  if (act === 'close-drawer') return closeDrawer();
  if (act === 'close-modal') return closeModal();
  if (act === 'refresh') return refresh();
  if (act === 'reload-page') return render();
  if (act === 'export') { window.location.href = '/api/findings/export.csv?status=' + encodeURIComponent(state.filters.status || 'new,open'); return; }

  if (act === 'add-target') return openTargetModal(null);
  if (act === 'bulk-add-target') return openBulkAddModal();
  if (act === 'bulk-add-pick') return $('#bulk-file').click();
  if (act === 'bulk-add-save') return runBulkAdd();
  if (act === 'ai-model-toggle') return toggleModelPop();
  if (act === 'ai-model-open') {
    if ((state.cache.modelList || []).length) toggleModelPop();
    return;
  }
  if (act === 'ai-model-choose') {
    $('#ai-model').value = el.dataset.value;
    $$('#ai-model-pop .combo-item').forEach((item) => item.classList.toggle('active', item === el));
    closeModelPop();
    return;
  }
  if (act === 'save-target') return saveTarget(el.dataset.id || null);
  if (act === 'edit-target') {
    let t = (state.cache.targets || []).find((x) => String(x.id) === el.dataset.id);
    if (!t) {
      // 缓存里没有（比如刚翻过页）就回源查一次, 别让按钮点了没反应
      try {
        const data = await api('/api/targets?limit=0');
        t = (data.items || []).find((x) => String(x.id) === el.dataset.id);
      } catch (err) { /* 下面统一提示 */ }
    }
    if (!t) { toast('没找到该站点，刷新页面后再试', 'err'); return; }
    return openTargetModal(t);
  }
  if (act === 'scan') {
    el.disabled = true;
    try {
      const r = await api(`/api/targets/${el.dataset.id}/scan?full=true`, { method: 'POST' });
      toast(r.queued ? '已加入扫描队列' : (r.reason || '未加入队列'), r.queued ? 'ok' : 'err');
    } catch (err) { toast('触发失败: ' + err.message, 'err'); }
    setTimeout(refresh, 900);
    return;
  }
  if (act === 'scan-all') {
    const targets = (await api('/api/targets?limit=0')).items;
    let n = 0;
    for (const t of targets.filter((x) => x.enabled)) {
      try { const r = await api(`/api/targets/${t.id}/scan?full=false`, { method: 'POST' }); if (r.queued) n += 1; } catch (e) { /* ignore */ }
    }
    toast(`已排队 ${n} 个站点`, 'ok');
    setTimeout(refresh, 900);
    return;
  }
  if (act === 'all-sites-state') {
    // 一键停/启全部站点: 不带筛选词, 由后端解析成全部 id（上千站点也不塞进请求体）
    const action = el.dataset.value === 'disable' ? 'disable' : 'enable';
    const pausing = action === 'disable';
    let total = 0;
    try { total = (await api('/api/targets?limit=0')).total; } catch (err) { /* 拿不到就照常问一次 */ }
    if (!total) { toast('还没有监测站点', 'err'); return; }
    const tip = pausing
      ? '暂停后这些站点不再按周期自动巡检，发现也不会更新。'
      : '恢复后会按各自的周期继续巡检；之前手动暂停过的站点也会一并打开。';
    if (!window.confirm(`确认${pausing ? '暂停' : '恢复'}全部 ${total} 个站点？${tip}`)) return;
    try {
      const r = await api('/api/targets/bulk', {
        method: 'POST',
        body: JSON.stringify({ ids: [], action, all_matching: true }),
      });
      toast(r.affected
        ? `${pausing ? '已暂停' : '已恢复'} ${r.affected} 个站点`
        : `全部 ${total} 个站点本来就已经是${pausing ? '暂停' : '监测'}状态`, r.affected ? 'ok' : 'err');
    } catch (err) {
      toast('操作失败: ' + err.message, 'err');
    }
    refresh();
    return;
  }
  if (act === 'toggle-target') {
    const enabled = el.dataset.enabled === '1';
    try {
      await api(`/api/targets/${el.dataset.id}`, { method: 'PATCH', body: JSON.stringify({ enabled: !enabled }) });
      toast(enabled ? '已暂停监测' : '已恢复监测', 'ok');
      refresh();
    } catch (err) { toast('操作失败: ' + err.message, 'err'); }
    return;
  }
  if (act === 'del-target') {
    if (!window.confirm(`确认删除站点「${el.dataset.name}」？该站点下的发现与资产记录会一并删除。`)) return;
    try {
      await api(`/api/targets/${el.dataset.id}`, { method: 'DELETE' });
      toast('站点已删除', 'ok');
      refresh();
    } catch (err) { toast('删除失败: ' + err.message, 'err'); }
    return;
  }

  if (act === 'open-finding') {
    if (event && event.target && event.target.closest && event.target.closest('[data-act="select-one"]')) return;
    stop(event);
    return openFinding(Number(el.dataset.id));
  }
  if (act === 'del-finding') {
    const id = Number(el.dataset.id);
    if (!window.confirm('确认删除这条发现？删除后 JS 里若仍有该凭证，下一轮扫描会重新报出来；想长期压下它，用「忽略」或「标记误报」更合适。')) return;
    try {
      await api(`/api/findings/${id}`, { method: 'DELETE' });
      state.selected.delete(id);
      if (state.openFindingId === id) closeDrawer();
      toast('已删除该条发现', 'ok');
      refresh();
    } catch (err) { toast('删除失败: ' + err.message, 'err'); }
    return;
  }
  if (act === 'bulk-status') return bulkFindingStatus(el.dataset.status);
  if (act === 'bulk-del-findings') return bulkDeleteFindings();
  if (act === 'findings-clear') { state.selected.clear(); return renderFindings(); }
  if (act === 'assets-view') { state.assetsView = el.dataset.value; return renderAssets(); }
  if (act === 'asset-history') { stop(event); return openAssetHistory(Number(el.dataset.id)); }
  if (act === 'new-rule') { openModal(ruleEditor(null)); return; }
  if (act === 'edit-rule') {
    stop(event);
    const rule = (state.cache.rules || []).find((r) => r.id === el.dataset.id);
    return openModal(ruleEditor(rule));
  }
  if (act === 'test-rule') return testRuleDraft();
  if (act === 'save-rule') return saveRuleDraft();
  if (act === 'rule-downgrade') { stop(event); return downgradeRule(el.dataset.id); }
  if (act === 'finding-status') { stop(event); return setFindingStatus(Number(el.dataset.id), el.dataset.status); }
  if (act === 'save-notes') {
    const notes = $('#d-notes').value;
    try {
      await api(`/api/findings/${el.dataset.id}`, { method: 'PATCH', body: JSON.stringify({ notes }) });
      toast('备注已保存', 'ok');
    } catch (err) { toast('保存失败: ' + err.message, 'err'); }
    return;
  }
  if (act === 'triage') {
    stop(event);
    el.disabled = true;
    const original = el.innerHTML;
    el.textContent = '复核中…';
    try {
      const r = await api(`/api/findings/${el.dataset.id}/triage`, { method: 'POST' });
      toast(`AI 判定：${(VERDICT[r.verdict] || VERDICT.uncertain).label}`, r.verdict === 'real' ? 'err' : 'ok');
      await openFinding(Number(el.dataset.id));
      refresh();
    } catch (err) {
      toast('复核失败: ' + err.message, 'err');
      el.disabled = false;
      el.innerHTML = original;
    }
    return;
  }
  if (act === 'draft-rule') {
    stop(event);
    el.disabled = true;
    el.textContent = '生成中…';
    try {
      const r = await api(`/api/findings/${el.dataset.id}/draft-rule?save=true`, { method: 'POST' });
      if (r.saved) toast(`已生成并启用规则 ${r.rule.id}`, 'ok');
      else toast('未能生成可用规则: ' + (r.reason || ''), 'err');
    } catch (err) {
      toast('生成失败: ' + err.message, 'err');
    }
    el.disabled = false;
    el.textContent = '生成检测规则';
    return;
  }
  if (act === 'copy') {
    try { await navigator.clipboard.writeText(el.dataset.text); toast('已复制', 'ok'); }
    catch (e) { toast('复制失败，请手动选择', 'err'); }
    return;
  }
  if (act === 'select-one') {
    const id = Number(el.dataset.id);
    if (el.checked) state.selected.add(id); else state.selected.delete(id);
    return renderFindings();
  }
  if (act === 'select-all') {
    const rows = $$('[data-act="open-finding"]').map((r) => Number(r.dataset.id));
    if (el.checked) rows.forEach((id) => state.selected.add(id)); else state.selected.clear();
    return renderFindings();
  }
  if (act === 'page') { state.filters.page = Math.max(0, Number(el.dataset.page)); return renderFindings(); }
  if (act === 'list-page') {
    const block = el.dataset.block;
    const wanted = Math.max(0, Number(el.dataset.page));
    if (block === 'sites') {
      state.targetsPage = wanted;
      clearTargetSelection();             // 翻页时清空选择, 避免误删看不到的行
      return renderTargets();
    }
    if (block === 'assets') { state.assetsPage = wanted; return renderAssets(); }
    state.overviewPage = { recent: 0, targets: 0, ...(state.overviewPage || {}) };
    state.overviewPage[block === 'health' ? 'targets' : block] = wanted;
    return renderOverview();
  }
  if (act === 'target-select') {
    const id = Number(el.dataset.id);
    if (el.checked) state.selectedTargets.add(id); else state.selectedTargets.delete(id);
    // 逐个改动即退出"全部匹配"模式, 否则条上的数字和实际作用范围会对不上
    state.targetsBulkAll = false;
    return renderTargets();
  }
  if (act === 'target-select-all') {
    if (el.checked) {
      // 只全选当前页（与多数后台一致, 避免一次误操作影响上千站点）
      $$('[data-act="target-select"]').forEach((box) => state.selectedTargets.add(Number(box.dataset.id)));
    } else {
      clearTargetSelection();
    }
    return renderTargets();
  }
  if (act === 'targets-select-all-matching') { state.targetsBulkAll = true; return renderTargets(); }
  if (act === 'targets-select-page') { state.targetsBulkAll = false; return renderTargets(); }
  if (act === 'targets-clear') { clearTargetSelection(); return renderTargets(); }
  if (act === 'targets-bulk') {
    const op = el.dataset.op;
    if (op === 'interval') return openIntervalModal();
    return runBulk(op);
  }
  if (act === 'targets-bulk-save-interval') {
    const minutes = readInterval('bulk-interval');
    closeModal();
    return runBulk('interval', { interval_minutes: minutes });
  }
  if (act === 'toggle-gated') {
    state.filters.showGated = !state.filters.showGated;
    state.filters.page = 0;
    return renderFindings();
  }
  if (act === 'set-status-filter') { state.filters.status = el.dataset.value; state.filters.page = 0; state.selected.clear(); return renderFindings(); }
  if (act === 'toggle-sev') {
    const sev = el.dataset.sev;
    if (state.filters.severity.has(sev)) state.filters.severity.delete(sev); else state.filters.severity.add(sev);
    state.filters.page = 0;
    return renderFindings();
  }

  if (act === 'rule-toggle') {
    try {
      await api(`/api/rules/${encodeURIComponent(el.dataset.id)}`, { method: 'PATCH', body: JSON.stringify({ enabled: el.checked }) });
      toast(el.checked ? '规则已启用' : '规则已关闭', 'ok');
    } catch (err) { toast('操作失败: ' + err.message, 'err'); el.checked = !el.checked; }
    return;
  }
  if (act === 'del-rule') {
    if (!window.confirm('确认删除这条导入规则？')) return;
    try {
      await api(`/api/rules/custom/${encodeURIComponent(el.dataset.id)}`, { method: 'DELETE' });
      toast('规则已删除', 'ok');
      renderRules();
    } catch (err) { toast('删除失败: ' + err.message, 'err'); }
    return;
  }
  if (act === 'import-rules') {
    const toml = $('#import-toml').value.trim();
    if (!toml) { toast('请先粘贴 gitleaks TOML 内容', 'err'); return; }
    try {
      const r = await api('/api/rules/import', { method: 'POST', body: JSON.stringify({ toml }) });
      toast(`已导入 ${r.imported} 条规则`, 'ok');
      renderRules();
    } catch (err) { toast('导入失败: ' + err.message, 'err'); }
    return;
  }

  if (act === 'save-scan') return saveScanSettings();
  if (act === 'clear-credentials') {
    try {
      await api('/api/settings', { method: 'PUT', body: JSON.stringify({
        scan: { extra_headers: {}, cookies: '' },
      }) });
      toast('已清除采集凭据，回到匿名采集', 'ok');
      refresh();
    } catch (err) { toast('清除失败: ' + err.message, 'err'); }
    return;
  }
  if (act === 'save-alert') return saveAlertSettings();
  if (act === 'ai-apply-preset') {
    const key = $('#ai-preset').value;
    const map = (state.cache.aiPresets || {})[key];
    if (!map) { toast('请先选择一个预设', 'err'); return; }
    $('#ai-base').value = map.base_url;
    $('#ai-kind').value = map.kind;
    if (map.model) $('#ai-model').value = map.model;
    toast(`已填入 ${map.label}，保存后生效`, 'ok');
    return;
  }
  if (act === 'ai-fetch-models') {
    el.disabled = true;
    $('#ai-test-result').textContent = '正在拉取模型列表…';
    try {
      const r = await api('/api/ai/models', { method: 'POST', body: JSON.stringify({ ai: readAIFields() }) });
      state.cache.modelList = r.models;
      // 只重绘这一小块, 而不是整页 render()（那会把正在填的表单清掉）
      const combo = $('#ai-model-combo');
      const hint = $('#ai-model-hint');
      if (combo) combo.outerHTML = modelCombo($('#ai-model') ? $('#ai-model').value.trim() : '');
      if (hint) hint.textContent = modelHint();
      if (!r.models.length) {
        $('#ai-test-result').textContent = '端点没有返回模型列表，请手动填写模型名称。';
      } else {
        if (!$('#ai-model').value) $('#ai-model').value = r.models[0];
        $('#ai-test-result').textContent = `发现 ${r.models.length} 个模型：${r.models.slice(0, 6).join('、')}${r.models.length > 6 ? ' …' : ''}（点模型框右侧箭头可选择）`;
      }
    } catch (err) {
      $('#ai-test-result').textContent = '拉取失败：' + err.message;
    }
    el.disabled = false;
    return;
  }
  if (act === 'ai-test') {
    el.disabled = true;
    $('#ai-test-result').textContent = '正在测试连接…';
    try {
      const r = await api('/api/ai/test', { method: 'POST', body: JSON.stringify({ ai: readAIFields() }) });
      $('#ai-test-result').textContent = r.ok
        ? `连接正常 · ${r.model} · ${r.latency_ms} ms · 返回: ${(r.message || '').slice(0, 80)}`
        : `连接失败: ${r.message}`;
      toast(r.ok ? 'AI 连接正常' : 'AI 连接失败', r.ok ? 'ok' : 'err');
    } catch (err) {
      $('#ai-test-result').textContent = '测试失败：' + err.message;
      toast('测试失败: ' + err.message, 'err');
    }
    el.disabled = false;
    return;
  }
  if (act === 'save-ai') return saveAISettings();
  if (act === 'save-analyzers') return saveAnalyzerSettings();
  if (act === 'save-scanners') return saveScannerSettings();
  if (act === 'test-alert') {
    el.disabled = true;
    toast('正在发送测试消息…');
    try {
      const r = await api('/api/settings/alert/test', { method: 'POST' });
      toast(r.ok ? '测试消息已发送，请查看飞书' : ('发送失败: ' + r.message), r.ok ? 'ok' : 'err');
    } catch (err) { toast('发送失败: ' + err.message, 'err'); }
    el.disabled = false;
    return;
  }
  if (act === 'add-allowlist') {
    const pattern = $('#w-pattern').value.trim();
    if (!pattern) return;
    try {
      await api('/api/allowlist', { method: 'POST', body: JSON.stringify({ pattern }) });
      toast('已加入白名单', 'ok');
      renderSettings();
    } catch (err) { toast('添加失败: ' + err.message, 'err'); }
    return;
  }
  if (act === 'del-allowlist') {
    try {
      await api(`/api/allowlist/${el.dataset.id}`, { method: 'DELETE' });
      toast('已移出白名单', 'ok');
      renderSettings();
    } catch (err) { toast('删除失败: ' + err.message, 'err'); }
    return;
  }
}

/* ------------------------------------------------------------------ 绑定 */

document.addEventListener('click', (event) => {
  if (!event.target.closest('#ai-model-combo')) closeModelPop();
  const el = event.target.closest('[data-act]');
  if (el) { handleAction(el, event); return; }
  if (event.target.id === 'scrim' || event.target.id === 'modal-scrim') { closeDrawer(); closeModal(); }
});

// 手动输入模型名时就收起候选列表, 免得干扰
document.addEventListener('input', (event) => {
  if (event.target.id === 'ai-model') closeModelPop();
});

document.addEventListener('change', (event) => {
  const el = event.target.closest('[data-act]');
  if (!el) return;
  const act = el.dataset.act;
  if (act === 'filter-target') { state.filters.target = el.value; state.filters.page = 0; renderFindings(); }
  else if (act === 'filter-rule') { state.filters.rule = el.value; state.filters.page = 0; renderFindings(); }
  else if (act === 'filter-sort') { state.filters.sort = el.value; renderFindings(); }
  else if (act === 'filter-ai') { state.filters.ai = el.value; state.filters.page = 0; renderFindings(); }
  else if (act === 'toggle-gated') { /* 由点击分支处理 */ }
  else if (act === 'asset-target') { goto('assets', el.value ? { target: el.value } : undefined); }
  else if (act === 'bulk-add-file') { readBulkFile(el); }
  else if (act === 'rule-sev') {
    api(`/api/rules/${encodeURIComponent(el.dataset.id)}`, { method: 'PATCH', body: JSON.stringify({ severity: el.value }) })
      .then(() => toast('等级已更新', 'ok'))
      .catch((err) => toast('更新失败: ' + err.message, 'err'));
  } else if (act === 'rule-toggle') { handleAction(el, event); }
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') { closeDrawer(); closeModal(); closeModelPop(); }
});

window.addEventListener('hashchange', () => { state.selected.clear(); state.openedFromLink = null; render(); });

setInterval(() => {
  const { path } = parseHash();
  if (path === 'overview' || path === 'targets') { state.overview = null; render(); }
}, 15000);

api('/api/settings').then((s) => {
  $('#build-info').textContent = `v${s.server.version} · 规则 rev ${s.rules_revision}`;
  state.cache.aiPresets = (s.ai && s.ai.presets) || {};
}).catch(() => {});

refresh();
initStream();
