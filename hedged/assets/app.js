// Private Encrypted ARC Review Portal — Zero external dependencies, Web Crypto AES-256-GCM
const SESSION_KEY = 'hedged_arc_passphrase_v1';
const CHECKLIST_KEY = 'hedged_arc_checklist_v1';

const pageEl = document.body;
const PAGE_TYPE = pageEl.dataset.page || 'portal';
const REVIEWER_ID = pageEl.dataset.reviewerId || '';
const BASE_PATH = pageEl.dataset.basePath || '.';

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function decryptBundle(encObj, passphrase) {
  const te = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    te.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: b64ToBytes(encObj.salt),
      iterations: encObj.iter,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(encObj.iv) },
    aesKey,
    b64ToBytes(encObj.ct)
  );
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function inlineMd(text) {
  let out = escapeHtml(text);
  out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  out = out.replace(/(?<!\*)\*([^*]+)\*(?!\*)/g, '<em>$1</em>');
  return out;
}

function renderMarkdown(md) {
  if (!md) return '';
  const lines = String(md).replace(/\r\n/g, '\n').split('\n');
  let html = '';
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed === '---') {
      i++;
      continue;
    }
    // Headings
    const hm = trimmed.match(/^(#{1,4})\s+(.+)$/);
    if (hm) {
      const lvl = Math.min(hm[1].length + 1, 5);
      html += `<h${lvl}>${inlineMd(hm[2])}</h${lvl}>`;
      i++;
      continue;
    }
    // Blockquote
    if (trimmed.startsWith('>')) {
      const qLines = [];
      while (i < lines.length && lines[i].trim().startsWith('>')) {
        qLines.push(lines[i].trim().replace(/^>\s?/, ''));
        i++;
      }
      html += `<blockquote>${qLines.map(inlineMd).join('<br>')}</blockquote>`;
      continue;
    }
    // Table
    if (trimmed.startsWith('|') && i + 1 < lines.length && lines[i + 1].trim().startsWith('|') && lines[i + 1].includes('---')) {
      const headers = trimmed.replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        rows.push(lines[i].trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim()));
        i++;
      }
      html += `<div style="overflow-x:auto"><table><thead><tr>${headers.map((h) => `<th>${inlineMd(h)}</th>`).join('')}</tr></thead><tbody>`;
      for (const r of rows) {
        html += `<tr>${r.map((c) => `<td>${inlineMd(c)}</td>`).join('')}</tr>`;
      }
      html += '</tbody></table></div>';
      continue;
    }
    // Unordered list
    if (/^[-*]\s+/.test(trimmed)) {
      html += '<ul>';
      while (i < lines.length && /^[-*]\s+/.test(lines[i].trim())) {
        html += `<li>${inlineMd(lines[i].trim().replace(/^[-*]\s+/, ''))}</li>`;
        i++;
      }
      html += '</ul>';
      continue;
    }
    // Ordered list
    if (/^\d+\.\s+/.test(trimmed)) {
      html += '<ol>';
      while (i < lines.length && /^\d+\.\s+/.test(lines[i].trim())) {
        html += `<li>${inlineMd(lines[i].trim().replace(/^\d+\.\s+/, ''))}</li>`;
        i++;
      }
      html += '</ol>';
      continue;
    }
    // Paragraph
    const pLines = [];
    while (
      i < lines.length &&
      lines[i].trim() &&
      !lines[i].trim().startsWith('#') &&
      !lines[i].trim().startsWith('>') &&
      !lines[i].trim().startsWith('|') &&
      lines[i].trim() !== '---' &&
      !/^[-*]\s+/.test(lines[i].trim()) &&
      !/^\d+\.\s+/.test(lines[i].trim())
    ) {
      pLines.push(lines[i].trim());
      i++;
    }
    html += `<p>${inlineMd(pLines.join(' '))}</p>`;
  }
  return html;
}

function getChecklistState() {
  try {
    return JSON.parse(localStorage.getItem(CHECKLIST_KEY) || '{}');
  } catch {
    return {};
  }
}

function setChecklistItem(id, checked) {
  const st = getChecklistState();
  st[id] = Boolean(checked);
  localStorage.setItem(CHECKLIST_KEY, JSON.stringify(st));
}

function renderStars(val) {
  const full = Math.floor(val);
  const half = val - full >= 0.5 ? 1 : 0;
  const empty = 5 - full - half;
  return '★'.repeat(full) + (half ? '⯪' : '') + '☆'.repeat(empty);
}

function heatColor(val, mode) {
  if (val == null) return { bg: '#eee', fg: '#555' };
  if (mode === 'engagement') {
    if (val >= 9) return { bg: '#2f5d44', fg: '#ffffff' };
    if (val >= 8) return { bg: '#4e7d62', fg: '#ffffff' };
    if (val >= 7) return { bg: '#cde0d3', fg: '#1d2b24' };
    return { bg: '#f5e1c8', fg: '#5c3412' };
  } else {
    if (val <= 1) return { bg: '#d6e8dc', fg: '#1d442d' };
    if (val <= 2) return { bg: '#e9f2ec', fg: '#2b4f3a' };
    if (val <= 3) return { bg: '#faf0d7', fg: '#6b4d12' };
    if (val <= 4) return { bg: '#f8dfc2', fg: '#7c3f14' };
    return { bg: '#f3c6c2', fg: '#7a1f19' };
  }
}

function buildSidebar(data, activeId) {
  const state = getChecklistState();
  const totalCheckable = data.triage.p0.length + data.triage.p1.length + data.kdp_checklist.length;
  const doneCount = [
    ...data.triage.p0,
    ...data.triage.p1,
    ...data.kdp_checklist,
  ].filter((x) => state[x.id]).length;

  const portalHref = `${BASE_PATH}/index.html`;
  const links = data.reviewers
    .map((r) => {
      const href = `${BASE_PATH}/reviewers/${r.id}.html`;
      const isActive = activeId === r.id ? 'active' : '';
      return `
        <li>
          <a class="nav-link ${isActive}" href="${href}">
            <span class="nav-avatar" style="background:${r.accent}">${escapeHtml(r.initials)}</span>
            <span class="nav-meta">
              <span class="nav-name">${escapeHtml(r.name)}</span>
              <span class="nav-role">${escapeHtml(r.category_label)} · ${escapeHtml(r.model_family)}</span>
            </span>
            <span class="nav-star">${r.star_rating.toFixed(1)}★</span>
          </a>
        </li>`;
    })
    .join('');

  return `
    <div class="mobile-bar">
      <strong style="font-family:var(--serif);font-size:1.1rem">${escapeHtml(data.meta.title)} · ARC Portal</strong>
      <button id="mobile-menu-btn" type="button">Menu</button>
    </div>
    <aside class="sidebar" id="sidebar">
      <div class="brand">
        <div class="brand-kicker">Private Editorial Portal</div>
        <div class="brand-title">${escapeHtml(data.meta.title)}</div>
        <div class="brand-sub">by ${escapeHtml(data.meta.author)} · ${data.meta.word_count.toLocaleString()} words</div>
      </div>

      <div>
        <div class="nav-section-label">Consolidated Synthesis</div>
        <ul class="nav-list">
          <li>
            <a class="nav-link ${activeId === 'portal' ? 'active' : ''}" href="${portalHref}">
              <span class="nav-avatar" style="background:#b86b2b">★</span>
              <span class="nav-meta">
                <span class="nav-name">Editorial &amp; Launch Portal</span>
                <span class="nav-role">Neon Consolidated Dossier</span>
              </span>
            </a>
          </li>
          ${
            activeId === 'portal'
              ? `
          <li><a class="nav-link" href="#reviewers" style="padding-left:2.4rem;font-size:0.82rem">7 Reviewer Panel</a></li>
          <li><a class="nav-link" href="#triage" style="padding-left:2.4rem;font-size:0.82rem">P0 / P1 / P2 Fix Triage</a></li>
          <li><a class="nav-link" href="#heatmap" style="padding-left:2.4rem;font-size:0.82rem">6-Sitting Pacing Heatmap</a></li>
          <li><a class="nav-link" href="#consensus" style="padding-left:2.4rem;font-size:0.82rem">Consensus &amp; Model Bias</a></li>
          <li><a class="nav-link" href="#launch" style="padding-left:2.4rem;font-size:0.82rem">Marketing &amp; KDP Kit</a></li>`
              : ''
          }
        </ul>
      </div>

      <div>
        <div class="nav-section-label">7 Blind ARC Reviewers</div>
        <ul class="nav-list">${links}</ul>
      </div>

      <div class="sidebar-footer">
        <div class="progress-pill" id="sidebar-progress">
          Editorial Checklist: <strong>${doneCount} / ${totalCheckable}</strong> done
        </div>
        <button class="btn-ghost-dark" id="lock-btn" type="button">Lock Portal</button>
      </div>
    </aside>`;
}

function updateProgressBadge(data) {
  const el = document.getElementById('sidebar-progress');
  if (!el) return;
  const state = getChecklistState();
  const items = [...data.triage.p0, ...data.triage.p1, ...data.kdp_checklist];
  const done = items.filter((x) => state[x.id]).length;
  el.innerHTML = `Editorial Checklist: <strong>${done} / ${items.length}</strong> done`;
}

function buildHeatmapSvg(reviewers) {
  const engMeans = [];
  const dnfMeans = [];
  for (let s = 0; s < 6; s++) {
    const eVals = reviewers.map((r) => r.sittings[s]?.engagement).filter((v) => v != null);
    const dVals = reviewers.map((r) => r.sittings[s]?.dnf).filter((v) => v != null);
    engMeans.push(eVals.reduce((a, b) => a + b, 0) / eVals.length);
    dnfMeans.push(dVals.reduce((a, b) => a + b, 0) / dVals.length);
  }
  const W = 620, H = 140, padX = 48, padY = 20;
  const xFor = (i) => padX + (i * (W - padX * 2)) / 5;
  const yFor = (v) => H - padY - ((v - 1) / 9) * (H - padY * 2);
  const engPts = engMeans.map((v, i) => `${xFor(i).toFixed(1)},${yFor(v).toFixed(1)}`).join(' ');
  const dnfPts = dnfMeans.map((v, i) => `${xFor(i).toFixed(1)},${yFor(v).toFixed(1)}`).join(' ');

  return `
    <div class="sparkline-box">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;font-size:0.8rem;color:var(--ink-soft)">
        <strong>Panel Mean Trajectory (Sittings 1–6)</strong>
        <span><span style="color:#3f5e4d;font-weight:700">● Engagement</span> &nbsp; <span style="color:#9e3a33;font-weight:700">● DNF-Risk</span></span>
      </div>
      <svg viewBox="0 0 ${W} ${H}" style="width:100%;max-width:680px;height:auto;display:block">
        ${[2, 5, 8].map((v) => `<line x1="${padX}" y1="${yFor(v)}" x2="${W - padX}" y2="${yFor(v)}" stroke="#e4dccb" stroke-dasharray="3 3" /><text x="10" y="${yFor(v) + 4}" font-size="10" fill="#6e7d75">${v}</text>`).join('')}
        <polyline fill="none" stroke="#3f5e4d" stroke-width="2.6" points="${engPts}" />
        <polyline fill="none" stroke="#9e3a33" stroke-width="2.2" stroke-dasharray="5 3" points="${dnfPts}" />
        ${engMeans.map((v, i) => `<circle cx="${xFor(i)}" cy="${yFor(v)}" r="4.5" fill="#3f5e4d" /><text x="${xFor(i)}" y="${yFor(v) - 8}" text-anchor="middle" font-size="10.5" font-weight="700" fill="#1d2b24">${v.toFixed(2)}</text>`).join('')}
        ${dnfMeans.map((v, i) => `<circle cx="${xFor(i)}" cy="${yFor(v)}" r="4" fill="#9e3a33" /><text x="${xFor(i)}" y="${yFor(v) + 14}" text-anchor="middle" font-size="10" font-weight="600" fill="#9e3a33">${v.toFixed(2)}</text>`).join('')}
        ${['S1 (1–5)', 'S2 (6–10)', 'S3 (11–15)', 'S4 (16–20)', 'S5 (21–25)', 'S6 (26–30)'].map((lbl, i) => `<text x="${xFor(i)}" y="${H - 3}" text-anchor="middle" font-size="10" fill="#4c5d54">${lbl}</text>`).join('')}
      </svg>
    </div>`;
}

function renderPortalPage(data) {
  const m = data.meta;
  const allTriage = [...data.triage.p0, ...data.triage.p1, ...data.triage.p2];
  const state = getChecklistState();

  const reviewerCards = data.reviewers
    .map((r) => {
      const catClass = r.category === 'core_icp' ? 'badge-icp' : 'badge-skeptic';
      return `
        <a class="reviewer-card" href="${BASE_PATH}/reviewers/${r.id}.html">
          <div class="rc-top">
            <div class="rc-avatar" style="background:${r.accent}">${escapeHtml(r.initials)}</div>
            <div>
              <div class="rc-name">${escapeHtml(r.name)}</div>
              <div class="rc-role">${escapeHtml(r.short_role)}</div>
            </div>
          </div>
          <div class="rc-badges">
            <span class="badge ${catClass}">${escapeHtml(r.category_label)}</span>
            <span class="badge badge-star">${r.star_rating.toFixed(1)} / 5.0 ★</span>
            <span class="badge badge-model">${escapeHtml(r.model_family)}</span>
            ${r.reads_pdf_extract ? '<span class="badge badge-pdf">KDP PDF Audit</span>' : ''}
          </div>
          <p class="rc-headline">“${escapeHtml(r.headline)}”</p>
          <div class="rc-footer">
            <span>DNF: ${escapeHtml(r.dnf_verdict.slice(0, 34))}${r.dnf_verdict.length > 34 ? '…' : ''}</span>
            <span>Open Persona →</span>
          </div>
        </a>`;
    })
    .join('');

  const kdpItemsHtml = data.kdp_checklist
    .map((item) => {
      const isChecked = Boolean(state[item.id]);
      return `
        <label class="kdp-item ${isChecked ? 'checked' : ''}" data-kdp-id="${item.id}">
          <input type="checkbox" class="triage-check kdp-box" data-id="${item.id}" ${isChecked ? 'checked' : ''} />
          <span>${inlineMd(item.text)}</span>
        </label>`;
    })
    .join('');

  const root = document.getElementById('app');
  root.innerHTML = `
    <div class="app-shell">
      ${buildSidebar(data, 'portal')}
      <main class="main-content">
        <header class="hero">
          <span class="kicker">Private Pre-Publication Editorial Portal · Encrypted</span>
          <h1><em>${escapeHtml(m.title)}</em> — Consolidated ARC Review Dossier</h1>
          <p class="hero-lead">
            100% blind 6-sitting Advance Reader Copy simulation across <strong>7 reader personas</strong> (5 Core ICPs + 2 Stress-Test Skeptics) and <strong>7 independent AI model families</strong>, collated and verified against the ${m.word_count.toLocaleString()}-word manuscript and ${m.pdf_pages}-page KDP paperback preview.
          </p>

          <div class="kpi-grid">
            <div class="kpi-card">
              <div class="kpi-label">Core ICP Mean (5)</div>
              <div class="kpi-value">${m.icp_mean.toFixed(2)}★</div>
              <div class="kpi-sub">Target audience range: 3.0–4.5★</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Overall Panel Mean (7)</div>
              <div class="kpi-value">${m.overall_mean.toFixed(2)}★</div>
              <div class="kpi-sub">Includes 2 strict skeptics (${m.skeptic_mean.toFixed(2)}★)</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">P0 Must-Fix Items</div>
              <div class="kpi-value">${data.triage.p0.length}</div>
              <div class="kpi-sub">All verified verbatim in manuscript</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Projected Post-Polish</div>
              <div class="kpi-value" style="color:var(--sage);font-size:1.55rem">${escapeHtml(m.projected_lift)}</div>
              <div class="kpi-sub">Zero structural rewrites required</div>
            </div>
          </div>

          <div class="verdict-banner">
            <strong>98% Launch-Readiness Verdict:</strong> ${escapeHtml(m.verdict)}
            <div style="margin-top:0.35rem;font-size:0.9rem;color:var(--ink-soft)">Clearing the ${data.triage.p0.length} verified P0 continuity/copyedit items and top P1 pacing splits requires zero structural rewrites and is projected to lift Core ICP ratings to <strong>${escapeHtml(m.projected_lift)}</strong>.</div>
          </div>
        </header>

        <section class="section-block" id="reviewers">
          <div class="section-header">
            <h2>Explore the 7 Blind ARC Reviewers</h2>
            <span class="section-sub">Click any persona card to inspect their full ICP portfolio, editorial diagnostic, public review, and 6-sitting reading journal</span>
          </div>
          <div class="reviewer-grid">${reviewerCards}</div>
        </section>

        <section class="section-block" id="triage">
          <div class="section-header">
            <h2>Last-2% Pre-Pub Fix Triage (Interactive Checklist)</h2>
            <span class="section-sub">Your checkmarks are saved locally in this browser as you edit</span>
          </div>
          <div class="controls-bar">
            <div class="pill-group" id="triage-filters">
              <button class="filter-pill active" data-filter="ALL" type="button">All (${allTriage.length})</button>
              <button class="filter-pill" data-filter="P0" type="button">P0 Must-Fix (${data.triage.p0.length})</button>
              <button class="filter-pill" data-filter="P1" type="button">P1 High-ROI (${data.triage.p1.length})</button>
              <button class="filter-pill" data-filter="P2" type="button">P2 Keep As-Is (${data.triage.p2.length})</button>
              <button class="filter-pill" data-filter="OPEN" type="button">Unchecked Only</button>
            </div>
            <input class="search-input" id="triage-search" type="search" placeholder="Search chapter, quote, or issue…" />
          </div>
          <div class="triage-list" id="triage-list"></div>
        </section>

        <section class="section-block" id="heatmap">
          <div class="section-header">
            <h2>Sitting-by-Sitting Pacing &amp; Emotional Heatmap</h2>
            <div class="pill-group" id="heatmap-toggle">
              <button class="filter-pill active" data-mode="engagement" type="button">Engagement (1–10)</button>
              <button class="filter-pill" data-mode="dnf" type="button">DNF-Risk (1–10)</button>
            </div>
          </div>
          <div class="heatmap-wrap">
            <div id="heatmap-table-container"></div>
            ${buildHeatmapSvg(data.reviewers)}
          </div>
        </section>

        <section class="section-block" id="consensus">
          <div class="section-header">
            <h2>Consensus Matrix &amp; Model-Bias Audit</h2>
            <span class="section-sub">Signals corroborated across ≥3 independent personas &amp; ≥2 model families</span>
          </div>
          <div class="prose-card md-body">${renderMarkdown(data.sections.consensus_md)}</div>
        </section>

        <section class="section-block" id="launch">
          <div class="section-header">
            <h2>Marketing, Positioning &amp; KDP Pre-Upload Kit</h2>
            <span class="section-sub">Interactive KDP print checklist + validated audience positioning</span>
          </div>
          <div class="kdp-list">${kdpItemsHtml}</div>
          <div class="prose-card md-body">${renderMarkdown(data.sections.marketing_md)}</div>
        </section>
      </main>
    </div>`;

  // Wire triage rendering & filtering
  let currentFilter = 'ALL';
  let currentSearch = '';
  const triageListEl = document.getElementById('triage-list');

  function renderTriage() {
    const st = getChecklistState();
    const q = currentSearch.trim().toLowerCase();
    const filtered = allTriage.filter((item) => {
      if (currentFilter === 'OPEN' && st[item.id]) return false;
      if (['P0', 'P1', 'P2'].includes(currentFilter) && item.priority !== currentFilter) return false;
      if (q) {
        const blob = `${item.id} ${item.location} ${item.evidence} ${item.recommendation} ${item.flagged_by}`.toLowerCase();
        if (!blob.includes(q)) return false;
      }
      return true;
    });

    if (!filtered.length) {
      triageListEl.innerHTML = `<div class="prose-card" style="text-align:center;color:var(--ink-muted)">No triage items match this filter.</div>`;
      return;
    }

    triageListEl.innerHTML = filtered
      .map((item) => {
        const isChecked = Boolean(st[item.id]);
        return `
          <div class="triage-item ${isChecked ? 'checked' : ''}">
            <input type="checkbox" class="triage-check triage-box" data-id="${escapeHtml(item.id)}" ${isChecked ? 'checked' : ''} />
            <div>
              <div class="triage-head">
                <span class="prio-tag prio-${item.priority}">${escapeHtml(item.id)}</span>
                <span class="triage-title">${inlineMd(item.location)}</span>
                <span class="triage-consensus">${inlineMd(item.flagged_by)}</span>
              </div>
              <div class="triage-evidence">${inlineMd(item.evidence)}</div>
              <div class="triage-rec"><strong>Recommended Edit:</strong> ${inlineMd(item.recommendation)}</div>
            </div>
          </div>`;
      })
      .join('');

    triageListEl.querySelectorAll('.triage-box').forEach((cb) => {
      cb.addEventListener('change', (e) => {
        setChecklistItem(e.target.dataset.id, e.target.checked);
        e.target.closest('.triage-item').classList.toggle('checked', e.target.checked);
        updateProgressBadge(data);
        if (currentFilter === 'OPEN') renderTriage();
      });
    });
  }

  renderTriage();

  document.querySelectorAll('#triage-filters .filter-pill').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#triage-filters .filter-pill').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      renderTriage();
    });
  });

  document.getElementById('triage-search').addEventListener('input', (e) => {
    currentSearch = e.target.value;
    renderTriage();
  });

  document.querySelectorAll('.kdp-box').forEach((cb) => {
    cb.addEventListener('change', (e) => {
      setChecklistItem(e.target.dataset.id, e.target.checked);
      e.target.closest('.kdp-item').classList.toggle('checked', e.target.checked);
      updateProgressBadge(data);
    });
  });

  // Heatmap renderer
  function renderHeatmap(mode) {
    const container = document.getElementById('heatmap-table-container');
    const means = [0, 1, 2, 3, 4, 5].map((idx) => {
      const vals = data.reviewers.map((r) => r.sittings[idx]?.[mode]).filter((v) => v != null);
      return vals.reduce((a, b) => a + b, 0) / vals.length;
    });

    const rows = data.reviewers
      .map((r) => {
        const cells = [0, 1, 2, 3, 4, 5]
          .map((idx) => {
            const val = r.sittings[idx]?.[mode];
            const c = heatColor(val, mode);
            return `<td><div class="hm-cell" style="background:${c.bg};color:${c.fg}">${val != null ? `${val}/10` : '—'}</div></td>`;
          })
          .join('');
        return `<tr><td class="hm-name"><a href="${BASE_PATH}/reviewers/${r.id}.html">${escapeHtml(r.name)}</a> <span style="color:var(--ink-muted);font-weight:400;font-size:0.78rem">(${escapeHtml(r.model_family)})</span></td>${cells}</tr>`;
      })
      .join('');

    container.innerHTML = `
      <table class="heatmap-table">
        <thead>
          <tr>
            <th>Reviewer (Model)</th>
            <th>S1<br>Ch 1–5</th>
            <th>S2<br>Ch 6–10</th>
            <th>S3<br>Ch 11–15</th>
            <th>S4<br>Ch 16–20</th>
            <th>S5<br>Ch 21–25</th>
            <th>S6<br>Ch 26–30</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
          <tr class="hm-mean-row">
            <td>Panel Mean (${mode === 'engagement' ? 'Engagement' : 'DNF-Risk'})</td>
            ${means.map((v) => `<td style="text-align:center">${v.toFixed(2)}</td>`).join('')}
          </tr>
        </tbody>
      </table>`;
  }

  renderHeatmap('engagement');
  document.querySelectorAll('#heatmap-toggle .filter-pill').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#heatmap-toggle .filter-pill').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      renderHeatmap(btn.dataset.mode);
    });
  });

  wireGlobalShellHandlers();
}

function renderReviewerPage(data, reviewerId) {
  const idx = data.reviewers.findIndex((r) => r.id === reviewerId);
  const rev = data.reviewers[idx];
  if (!rev) {
    document.getElementById('app').innerHTML = '<div style="padding:2rem">Reviewer not found.</div>';
    return;
  }

  const prev = idx > 0 ? data.reviewers[idx - 1] : null;
  const next = idx < data.reviewers.length - 1 ? data.reviewers[idx + 1] : null;
  const catClass = rev.category === 'core_icp' ? 'badge-icp' : 'badge-skeptic';

  const scorecardHtml = rev.scorecard.length
    ? `<div class="scorecard-grid">${rev.scorecard
        .map(
          (s) => `
        <div class="score-row">
          <div class="score-top">
            <span>${escapeHtml(s.dimension)}</span>
            <span style="color:var(--sage)">${escapeHtml(s.raw)}</span>
          </div>
          <div class="score-track"><div class="score-fill" style="width:${Math.min(100, s.score * 10)}%;background:${rev.accent}"></div></div>
          <div class="score-note">${inlineMd(s.note)}</div>
        </div>`
        )
        .join('')}</div>`
    : '';

  const sittingsHtml = rev.sittings
    .map(
      (s, sIdx) => `
      <details class="sitting-card" ${sIdx === 0 ? 'open' : ''}>
        <summary>
          <span>Sitting ${s.num} — ${escapeHtml(s.label)}</span>
          <span style="display:flex;gap:0.45rem;font-size:0.78rem">
            <span class="badge badge-icp">Engagement: ${s.engagement ?? '?'}/10</span>
            <span class="badge badge-skeptic">DNF-Risk: ${s.dnf ?? '?'}/10</span>
          </span>
        </summary>
        <div class="sitting-body md-body">${renderMarkdown(s.markdown)}</div>
      </details>`
    )
    .join('');

  document.title = `${rev.name} — Hedged ARC Portal`;
  document.getElementById('app').innerHTML = `
    <div class="app-shell">
      ${buildSidebar(data, rev.id)}
      <main class="main-content">
        <div style="margin-bottom:1rem;font-size:0.85rem">
          <a href="${BASE_PATH}/index.html">← Back to Consolidated Editorial Portal</a>
        </div>

        <header class="hero">
          <div style="display:flex;align-items:center;gap:1rem;margin-bottom:0.85rem;flex-wrap:wrap">
            <div class="rc-avatar" style="width:60px;height:60px;font-size:1.45rem;background:${rev.accent}">${escapeHtml(rev.initials)}</div>
            <div>
              <h1 style="margin:0 0 0.25rem;font-size:2rem">${escapeHtml(rev.name)}</h1>
              <div style="color:var(--ink-soft);font-size:0.95rem">${escapeHtml(rev.role)}</div>
            </div>
          </div>
          <div class="rc-badges" style="margin-bottom:0.85rem">
            <span class="badge ${catClass}">${escapeHtml(rev.category_label)}</span>
            <span class="badge badge-star">${rev.star_display} ${renderStars(rev.star_rating)}</span>
            <span class="badge badge-model">Model: ${escapeHtml(rev.model_family)} (${escapeHtml(rev.model_id)})</span>
            ${rev.reads_pdf_extract ? '<span class="badge badge-pdf">Audited KDP 5.5×8.5 PDF</span>' : ''}
          </div>
          <p class="hero-lead"><strong>DNF-Risk Verdict:</strong> ${escapeHtml(rev.dnf_verdict)}</p>
        </header>

        <nav class="tab-bar" id="reviewer-tabs">
          <button class="tab-btn active" data-tab="part-a" type="button">Part A: Editorial Stress-Test</button>
          <button class="tab-btn" data-tab="part-b" type="button">Part B: Public ARC Review</button>
          <button class="tab-btn" data-tab="persona" type="button">Persona Portfolio &amp; ICP</button>
          <button class="tab-btn" data-tab="journal" type="button">6-Sitting Reading Journal (${rev.sittings.length})</button>
        </nav>

        <section class="tab-panel" id="tab-part-a">
          ${scorecardHtml}
          <div class="prose-card md-body">${renderMarkdown(rev.part_a_md)}</div>
        </section>

        <section class="tab-panel" id="tab-part-b" hidden>
          <div class="goodreads-card">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;margin-bottom:0.75rem">
              <div class="gr-stars">${renderStars(rev.star_rating)} <span style="font-size:1rem;color:var(--ink);font-weight:700">${rev.star_display}</span></div>
              <div class="rc-badges">${rev.tags.map((t) => `<span class="badge badge-icp">${escapeHtml(t)}</span>`).join('')}</div>
            </div>
            <div class="md-body">${renderMarkdown(rev.part_b_md)}</div>
          </div>
        </section>

        <section class="tab-panel" id="tab-persona" hidden>
          <div class="prose-card md-body">${renderMarkdown(rev.persona_md)}</div>
        </section>

        <section class="tab-panel" id="tab-journal" hidden>
          <div style="display:flex;justify-content:flex-end;gap:0.5rem;margin-bottom:0.85rem">
            <button class="filter-pill" id="expand-all-sittings" type="button">Expand All 6 Sittings</button>
            <button class="filter-pill" id="collapse-all-sittings" type="button">Collapse All</button>
          </div>
          ${sittingsHtml}
        </section>

        <nav class="pager">
          ${prev ? `<a href="${BASE_PATH}/reviewers/${prev.id}.html">← ${escapeHtml(prev.name)} (${prev.star_rating.toFixed(1)}★)</a>` : `<a href="${BASE_PATH}/index.html">← Consolidated Portal</a>`}
          ${next ? `<a href="${BASE_PATH}/reviewers/${next.id}.html">${escapeHtml(next.name)} (${next.star_rating.toFixed(1)}★) →</a>` : `<a href="${BASE_PATH}/index.html">Consolidated Portal →</a>`}
        </nav>
      </main>
    </div>`;

  // Wire tabs
  document.querySelectorAll('#reviewer-tabs .tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#reviewer-tabs .tab-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const target = btn.dataset.tab;
      document.querySelectorAll('.tab-panel').forEach((p) => {
        p.hidden = p.id !== `tab-${target}`;
      });
    });
  });

  document.getElementById('expand-all-sittings')?.addEventListener('click', () => {
    document.querySelectorAll('.sitting-card').forEach((d) => (d.open = true));
  });
  document.getElementById('collapse-all-sittings')?.addEventListener('click', () => {
    document.querySelectorAll('.sitting-card').forEach((d) => (d.open = false));
  });

  wireGlobalShellHandlers();
}

function wireGlobalShellHandlers() {
  document.getElementById('lock-btn')?.addEventListener('click', () => {
    sessionStorage.removeItem(SESSION_KEY);
    location.reload();
  });
  document.getElementById('mobile-menu-btn')?.addEventListener('click', () => {
    document.getElementById('sidebar')?.classList.toggle('open');
  });
}

function renderLockScreen(encObj) {
  const root = document.getElementById('app');
  root.innerHTML = `
    <div class="lock-screen">
      <div class="lock-card">
        <div class="lock-emblem">H</div>
        <h1>Private Editorial Portal</h1>
        <p>This pre-publication review workspace is encrypted client-side. Enter your passphrase to unlock.</p>
        <form class="lock-form" id="unlock-form">
          <div class="input-wrap">
            <input class="lock-input" id="pass-input" type="password" autocomplete="current-password" placeholder="Enter passphrase" required autofocus />
            <button class="toggle-vis" id="toggle-vis" type="button">Show</button>
          </div>
          <div class="lock-error" id="lock-error">Incorrect passphrase. Please try again.</div>
          <button class="btn-primary" id="unlock-btn" type="submit">Unlock Portal</button>
        </form>
        <div class="lock-footnote">
          AES-256-GCM · PBKDF2-SHA256 · Unindexed &amp; Private
        </div>
      </div>
    </div>`;

  const passInput = document.getElementById('pass-input');
  const toggleBtn = document.getElementById('toggle-vis');
  const errEl = document.getElementById('lock-error');
  const submitBtn = document.getElementById('unlock-btn');

  toggleBtn.addEventListener('click', () => {
    const isPw = passInput.type === 'password';
    passInput.type = isPw ? 'text' : 'password';
    toggleBtn.textContent = isPw ? 'Hide' : 'Show';
  });

  document.getElementById('unlock-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    errEl.classList.remove('visible');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Decrypting…';
    try {
      const pass = passInput.value.trim();
      const data = await decryptBundle(encObj, pass);
      sessionStorage.setItem(SESSION_KEY, pass);
      mountPortal(data);
    } catch {
      errEl.classList.add('visible');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Unlock Portal';
      passInput.select();
    }
  });
}

function mountPortal(data) {
  if (PAGE_TYPE === 'reviewer') {
    renderReviewerPage(data, REVIEWER_ID);
  } else {
    renderPortalPage(data);
  }
}

async function boot() {
  try {
    const res = await fetch(`${BASE_PATH}/data/portal.enc.json`, { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const encObj = await res.json();
    const saved = sessionStorage.getItem(SESSION_KEY);
    if (saved) {
      try {
        const data = await decryptBundle(encObj, saved);
        mountPortal(data);
        return;
      } catch {
        sessionStorage.removeItem(SESSION_KEY);
      }
    }
    renderLockScreen(encObj);
  } catch (err) {
    document.getElementById('app').innerHTML = `<div class="lock-screen"><div class="lock-card"><h1>Unable to Load Portal</h1><p>${escapeHtml(err.message)}</p></div></div>`;
  }
}

boot();
