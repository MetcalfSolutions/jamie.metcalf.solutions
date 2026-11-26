// Private Encrypted 3-Track (21-Read) Consensus ARC Portal — Web Crypto AES-256-GCM
const SESSION_KEY = 'hedged_arc_passphrase_v1';
const CHECKLIST_KEY = 'hedged_arc_checklist_v2';

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
  const baseKey = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64ToBytes(encObj.salt), iterations: encObj.iter, hash: 'SHA-256' },
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
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed === '---') { i++; continue; }
    const hm = trimmed.match(/^(#{1,4})\s+(.+)$/);
    if (hm) {
      const lvl = Math.min(hm[1].length + 1, 5);
      html += `<h${lvl}>${inlineMd(hm[2])}</h${lvl}>`;
      i++; continue;
    }
    if (trimmed.startsWith('>')) {
      const q = [];
      while (i < lines.length && lines[i].trim().startsWith('>')) { q.push(lines[i].trim().replace(/^>\s?/, '')); i++; }
      html += `<blockquote>${q.map(inlineMd).join('<br>')}</blockquote>`;
      continue;
    }
    if (trimmed.startsWith('|') && i + 1 < lines.length && lines[i + 1].trim().startsWith('|') && lines[i + 1].includes('---')) {
      const headers = trimmed.replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        rows.push(lines[i].trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim()));
        i++;
      }
      html += `<div style="overflow-x:auto"><table><thead><tr>${headers.map((h) => `<th>${inlineMd(h)}</th>`).join('')}</tr></thead><tbody>`;
      for (const r of rows) html += `<tr>${r.map((c) => `<td>${inlineMd(c)}</td>`).join('')}</tr>`;
      html += '</tbody></table></div>';
      continue;
    }
    if (/^[-*]\s+/.test(trimmed)) {
      html += '<ul>';
      while (i < lines.length && /^[-*]\s+/.test(lines[i].trim())) { html += `<li>${inlineMd(lines[i].trim().replace(/^[-*]\s+/, ''))}</li>`; i++; }
      html += '</ul>';
      continue;
    }
    if (/^\d+\.\s+/.test(trimmed)) {
      html += '<ol>';
      while (i < lines.length && /^\d+\.\s+/.test(lines[i].trim())) { html += `<li>${inlineMd(lines[i].trim().replace(/^\d+\.\s+/, ''))}</li>`; i++; }
      html += '</ol>';
      continue;
    }
    const p = [];
    while (i < lines.length && lines[i].trim() && !lines[i].trim().startsWith('#') && !lines[i].trim().startsWith('>') && !lines[i].trim().startsWith('|') && lines[i].trim() !== '---' && !/^[-*]\s+/.test(lines[i].trim()) && !/^\d+\.\s+/.test(lines[i].trim())) {
      p.push(lines[i].trim()); i++;
    }
    html += `<p>${inlineMd(p.join(' '))}</p>`;
  }
  return html;
}

function getChecklistState() {
  try { return JSON.parse(localStorage.getItem(CHECKLIST_KEY) || '{}'); } catch { return {}; }
}

function setChecklistItem(id, checked) {
  const st = getChecklistState();
  st[id] = Boolean(checked);
  localStorage.setItem(CHECKLIST_KEY, JSON.stringify(st));
}

function renderStars(val) {
  const full = Math.floor(val);
  const half = val - full >= 0.35 ? 1 : 0;
  const empty = Math.max(0, 5 - full - half);
  return '★'.repeat(full) + (half ? '⯪' : '') + '☆'.repeat(empty);
}

function heatColor(val, mode) {
  if (val == null) return { bg: '#eee', fg: '#555' };
  if (mode === 'engagement') {
    if (val >= 8.5) return { bg: '#2f5d44', fg: '#ffffff' };
    if (val >= 7.8) return { bg: '#4e7d62', fg: '#ffffff' };
    if (val >= 7.0) return { bg: '#cde0d3', fg: '#1d2b24' };
    return { bg: '#f5e1c8', fg: '#5c3412' };
  }
  if (val <= 1.5) return { bg: '#d6e8dc', fg: '#1d442d' };
  if (val <= 2.3) return { bg: '#e9f2ec', fg: '#2b4f3a' };
  if (val <= 3.2) return { bg: '#faf0d7', fg: '#6b4d12' };
  if (val <= 4.2) return { bg: '#f8dfc2', fg: '#7c3f14' };
  return { bg: '#f3c6c2', fg: '#7a1f19' };
}

function agreeBadgeClass(agree) {
  if (String(agree).startsWith('3/3')) return 'agree-3';
  if (String(agree).startsWith('2/3')) return 'agree-2';
  return 'agree-1';
}

function allCheckableItems(data) {
  return [...data.triage.objective, ...data.triage.editorial.filter((x) => x.tier !== '1/3'), ...data.kdp_checklist];
}

function updateProgressBadge(data) {
  const el = document.getElementById('sidebar-progress');
  if (!el) return;
  const state = getChecklistState();
  const items = allCheckableItems(data);
  const done = items.filter((x) => state[x.id]).length;
  el.innerHTML = `Editorial Checklist: <strong>${done} / ${items.length}</strong> done`;
}

function buildSidebar(data, activeId) {
  const state = getChecklistState();
  const items = allCheckableItems(data);
  const doneCount = items.filter((x) => state[x.id]).length;
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
              <span class="nav-role">${escapeHtml(r.category_label)} · ${escapeHtml(r.agreement_label)}</span>
            </span>
            <span class="nav-star">${r.star_mean.toFixed(2)}★</span>
          </a>
        </li>`;
    })
    .join('');

  return `
    <div class="mobile-bar">
      <strong style="font-family:var(--serif);font-size:1.1rem">${escapeHtml(data.meta.title)} · 3-Track Portal</strong>
      <button id="mobile-menu-btn" type="button">Menu</button>
    </div>
    <aside class="sidebar" id="sidebar">
      <div class="brand">
        <div class="brand-kicker">Private 3-Track Portal</div>
        <div class="brand-title">${escapeHtml(data.meta.title)}</div>
        <div class="brand-sub">by ${escapeHtml(data.meta.author)} · 21 Blind Reads</div>
      </div>

      <div>
        <div class="nav-section-label">Consolidated Consensus</div>
        <ul class="nav-list">
          <li>
            <a class="nav-link ${activeId === 'portal' ? 'active' : ''}" href="${portalHref}">
              <span class="nav-avatar" style="background:#b86b2b">★</span>
              <span class="nav-meta">
                <span class="nav-name">3-Track Consensus Portal</span>
                <span class="nav-role">Neon 21-Read Dossier</span>
              </span>
            </a>
          </li>
          ${
            activeId === 'portal'
              ? `
          <li><a class="nav-link" href="#reviewers" style="padding-left:2.4rem;font-size:0.82rem">7 Reviewer Panel</a></li>
          <li><a class="nav-link" href="#objective" style="padding-left:2.4rem;font-size:0.82rem">Verified Objective P0s</a></li>
          <li><a class="nav-link" href="#editorial" style="padding-left:2.4rem;font-size:0.82rem">3/3 → 2/3 → 1/3 Opinions</a></li>
          <li><a class="nav-link" href="#heatmap" style="padding-left:2.4rem;font-size:0.82rem">21-Read Pacing Heatmap</a></li>
          <li><a class="nav-link" href="#launch" style="padding-left:2.4rem;font-size:0.82rem">Marketing &amp; KDP Kit</a></li>`
              : ''
          }
        </ul>
      </div>

      <div>
        <div class="nav-section-label">7 ARC Personas (3-Model Mean)</div>
        <ul class="nav-list">${links}</ul>
      </div>

      <div class="sidebar-footer">
        <div class="progress-pill" id="sidebar-progress">
          Editorial Checklist: <strong>${doneCount} / ${items.length}</strong> done
        </div>
        <button class="btn-ghost-dark" id="lock-btn" type="button">Lock Portal</button>
      </div>
    </aside>`;
}

function buildHeatmapSvg(reviewers, trackKey) {
  const engMeans = [];
  const dnfMeans = [];
  for (let s = 0; s < 6; s++) {
    const eVals = reviewers.map((r) => (trackKey === 'ALL' ? r.consolidated_sittings[s]?.engagement : r.tracks[trackKey]?.sittings[s]?.engagement)).filter((v) => v != null);
    const dVals = reviewers.map((r) => (trackKey === 'ALL' ? r.consolidated_sittings[s]?.dnf : r.tracks[trackKey]?.sittings[s]?.dnf)).filter((v) => v != null);
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
  const state = getChecklistState();

  const reviewerCards = data.reviewers
    .map((r) => {
      const catClass = r.category === 'core_icp' ? 'badge-icp' : 'badge-skeptic';
      const ta = r.tracks['track-a-diverse'].star_rating.toFixed(1);
      const tb = r.tracks['track-b-hydrogen'].star_rating.toFixed(1);
      const tc = r.tracks['track-c-deepseek-flash'].star_rating.toFixed(1);
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
            <span class="badge badge-star">${r.star_mean.toFixed(2)} / 5.0 ★</span>
            <span class="badge badge-model">${escapeHtml(r.agreement_label)} (±${r.star_spread.toFixed(1)})</span>
            ${r.reads_pdf_extract ? '<span class="badge badge-pdf">KDP PDF</span>' : ''}
          </div>
          <div class="track-score-row">
            <span class="track-mini">A: ${ta}★</span>
            <span class="track-mini">Hydrogen: ${tb}★</span>
            <span class="track-mini">DS-Flash: ${tc}★</span>
          </div>
          <p class="rc-headline">“${escapeHtml(r.headline)}”</p>
          <div class="rc-footer">
            <span>3-Way Consensus + All 3 Models</span>
            <span>Open Persona →</span>
          </div>
        </a>`;
    })
    .join('');

  const kdpItemsHtml = data.kdp_checklist
    .map((item) => {
      const isChecked = Boolean(state[item.id]);
      return `
        <label class="kdp-item ${isChecked ? 'checked' : ''}">
          <input type="checkbox" class="triage-check kdp-box" data-id="${item.id}" ${isChecked ? 'checked' : ''} />
          <span>${inlineMd(item.text)}</span>
        </label>`;
    })
    .join('');

  const edConsensus = data.triage.editorial.filter((x) => x.tier !== '1/3');
  const edOutliers = data.triage.editorial.filter((x) => x.tier === '1/3');

  document.getElementById('app').innerHTML = `
    <div class="app-shell">
      ${buildSidebar(data, 'portal')}
      <main class="main-content">
        <header class="hero">
          <span class="kicker">Private 3-Track Consensus Portal · 21 Blind Reads · Encrypted</span>
          <h1><em>${escapeHtml(m.title)}</em> — 3-Model Consensus Dossier</h1>
          <p class="hero-lead">
            Every one of the 7 blind reader personas read the full ${m.word_count.toLocaleString()}-word manuscript across <strong>3 independent AI model tracks (21 reads / 126 sittings)</strong>. Objective manuscript defects are machine-verified and pinned at the top; subjective editorial opinions are strictly ranked <strong>3/3 Unanimous → 2/3 Majority → 1/3 Outliers</strong>.
          </p>

          <div class="kpi-grid">
            <div class="kpi-card">
              <div class="kpi-label">Core ICP Mean (15 Reads)</div>
              <div class="kpi-value">${m.icp_mean.toFixed(2)}★</div>
              <div class="kpi-sub">5 target personas × 3 tracks</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Overall Mean (21 Reads)</div>
              <div class="kpi-value">${m.overall_mean.toFixed(2)}★</div>
              <div class="kpi-sub">Skeptics (6 reads): ${m.skeptic_mean.toFixed(2)}★</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Inter-Model Agreement</div>
              <div class="kpi-value" style="color:var(--sage)">6 / 7 Tight</div>
              <div class="kpi-sub">Within 0.5★ across 3 models</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Projected Post-Polish</div>
              <div class="kpi-value" style="color:var(--sage);font-size:1.45rem">${escapeHtml(m.projected_lift)}</div>
              <div class="kpi-sub">Zero structural rewrites needed</div>
            </div>
          </div>

          <div class="track-strip">
            <div class="track-chip"><span>Track A · Diverse 7-Model Fleet</span><strong>${m.track_means['track-a-diverse'].toFixed(2)}★</strong></div>
            <div class="track-chip"><span>Track B · AGY Gemini Hydrogen (Med)</span><strong>${m.track_means['track-b-hydrogen'].toFixed(2)}★</strong></div>
            <div class="track-chip"><span>Track C · OpenCode DeepSeek V4.1 Flash</span><strong>${m.track_means['track-c-deepseek-flash'].toFixed(2)}★</strong></div>
          </div>

          <div class="verdict-banner">
            <strong>98% Launch-Readiness Verdict:</strong> ${escapeHtml(m.verdict)}.
            <div style="margin-top:0.35rem;font-size:0.9rem;color:var(--ink-soft)">6 of 7 personas agreed within 0.5★ across 3 completely different models. Fixing the ${data.triage.objective.length} machine-verified objective defects and top 3/3 unanimous pacing adjustments lifts Core ICP ratings to <strong>${escapeHtml(m.projected_lift)}</strong>.</div>
          </div>
        </header>

        <section class="section-block" id="reviewers">
          <div class="section-header">
            <h2>7 ARC Reviewer Personas (Consolidated 3-Model Scores)</h2>
            <span class="section-sub">Click any persona to inspect their 3-way consensus summary and switch between all 3 model reads</span>
          </div>
          <div class="reviewer-grid">${reviewerCards}</div>
        </section>

        <section class="section-block" id="objective">
          <div class="section-header">
            <h2>Tier 1 — Machine-Verified Objective Defects (Pinned Top)</h2>
            <span class="section-sub">Verified verbatim in the manuscript/PDF regardless of 1/3–3/3 count · Checkmarks save locally</span>
          </div>
          <div class="triage-list" id="objective-list"></div>
        </section>

        <section class="section-block" id="editorial">
          <div class="section-header">
            <h2>Tier 2 — Consensus-Ranked Editorial Opinions (3/3 → 2/3 → 1/3)</h2>
            <span class="section-sub">Unanimous 3/3 signals surfaced first; single-model outliers tucked below</span>
          </div>
          <div class="controls-bar">
            <div class="pill-group" id="ed-filters">
              <button class="filter-pill active" data-filter="ALL" type="button">All Consensus (${edConsensus.length})</button>
              <button class="filter-pill" data-filter="3/3" type="button">3/3 Unanimous (${edConsensus.filter((x) => x.tier === '3/3').length})</button>
              <button class="filter-pill" data-filter="2/3" type="button">2/3 Majority (${edConsensus.filter((x) => x.tier === '2/3').length})</button>
              <button class="filter-pill" data-filter="OPEN" type="button">Unchecked Only</button>
            </div>
            <input class="search-input" id="ed-search" type="search" placeholder="Search chapter or topic…" />
          </div>
          <div class="triage-list" id="editorial-list"></div>
          ${
            edOutliers.length
              ? `
          <details class="outlier-drawer">
            <summary>
              <span>1/3 Single-Model Outliers &amp; Author-Preference Notes (${edOutliers.length})</span>
              <span>Expand ▾</span>
            </summary>
            <div class="outlier-drawer-body">
              ${edOutliers
                .map(
                  (item) => `
                <div class="triage-item" style="grid-template-columns:1fr">
                  <div>
                    <div class="triage-head">
                      <span class="agree-pill agree-1">1/3 Outlier</span>
                      <span class="triage-title">${inlineMd(item.location)}</span>
                    </div>
                    <div class="triage-evidence">${inlineMd(item.evidence)}</div>
                    <div class="triage-rec">${inlineMd(item.recommendation)}</div>
                  </div>
                </div>`
                )
                .join('')}
            </div>
          </details>`
              : ''
          }
        </section>

        <section class="section-block" id="heatmap">
          <div class="section-header">
            <h2>21-Read Sitting-by-Sitting Pacing &amp; Emotional Heatmap</h2>
            <div style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center">
              <div class="pill-group" id="hm-track-toggle">
                <button class="filter-pill active" data-track="ALL" type="button">21-Read Mean</button>
                <button class="filter-pill" data-track="track-a-diverse" type="button">Track A</button>
                <button class="filter-pill" data-track="track-b-hydrogen" type="button">Hydrogen</button>
                <button class="filter-pill" data-track="track-c-deepseek-flash" type="button">DS-Flash</button>
              </div>
              <div class="pill-group" id="heatmap-toggle">
                <button class="filter-pill active" data-mode="engagement" type="button">Engagement</button>
                <button class="filter-pill" data-mode="dnf" type="button">DNF-Risk</button>
              </div>
            </div>
          </div>
          <div class="heatmap-wrap" id="heatmap-wrap"></div>
        </section>

        <section class="section-block" id="launch">
          <div class="section-header">
            <h2>Marketing, Positioning &amp; KDP Pre-Upload Kit</h2>
            <span class="section-sub">Interactive KDP checklist + validated pitch &amp; comps</span>
          </div>
          <div class="kdp-list">${kdpItemsHtml}</div>
          <div class="prose-card md-body">${renderMarkdown(data.sections.marketing_md)}</div>
        </section>
      </main>
    </div>`;

  // Render Tier 1 Objective Defects
  function renderObjective() {
    const st = getChecklistState();
    const el = document.getElementById('objective-list');
    el.innerHTML = data.triage.objective
      .map((item) => {
        const isChecked = Boolean(st[item.id]);
        return `
          <div class="triage-item ${isChecked ? 'checked' : ''}">
            <input type="checkbox" class="triage-check obj-box" data-id="${escapeHtml(item.id)}" ${isChecked ? 'checked' : ''} />
            <div>
              <div class="triage-head">
                <span class="agree-pill agree-obj">${escapeHtml(item.id)} · Verified</span>
                <span class="agree-pill ${agreeBadgeClass(item.consensus)}">${escapeHtml(item.consensus)}</span>
                <span class="triage-title">${inlineMd(item.location)}</span>
              </div>
              <div class="triage-evidence">${inlineMd(item.evidence)}</div>
              <div class="triage-rec"><strong>Recommended Edit:</strong> ${inlineMd(item.recommendation)}</div>
            </div>
          </div>`;
      })
      .join('');
    el.querySelectorAll('.obj-box').forEach((cb) => {
      cb.addEventListener('change', (e) => {
        setChecklistItem(e.target.dataset.id, e.target.checked);
        e.target.closest('.triage-item').classList.toggle('checked', e.target.checked);
        updateProgressBadge(data);
      });
    });
  }
  renderObjective();

  // Render Tier 2 Editorial Consensus
  let edFilter = 'ALL';
  let edSearch = '';
  function renderEditorial() {
    const st = getChecklistState();
    const q = edSearch.trim().toLowerCase();
    const list = edConsensus.filter((item) => {
      if (edFilter === 'OPEN' && st[item.id]) return false;
      if (['3/3', '2/3'].includes(edFilter) && item.tier !== edFilter) return false;
      if (q && !`${item.id} ${item.location} ${item.evidence} ${item.recommendation}`.toLowerCase().includes(q)) return false;
      return true;
    });
    const el = document.getElementById('editorial-list');
    if (!list.length) {
      el.innerHTML = `<div class="prose-card" style="text-align:center;color:var(--ink-muted)">No consensus items match this filter.</div>`;
      return;
    }
    el.innerHTML = list
      .map((item) => {
        const isChecked = Boolean(st[item.id]);
        return `
          <div class="triage-item ${isChecked ? 'checked' : ''}">
            <input type="checkbox" class="triage-check ed-box" data-id="${escapeHtml(item.id)}" ${isChecked ? 'checked' : ''} />
            <div>
              <div class="triage-head">
                <span class="agree-pill ${agreeBadgeClass(item.tier)}">${escapeHtml(item.consensus)}</span>
                <span class="triage-title">${inlineMd(item.location)}</span>
              </div>
              <div class="triage-evidence">${inlineMd(item.evidence)}</div>
              <div class="triage-rec">${inlineMd(item.recommendation)}</div>
            </div>
          </div>`;
      })
      .join('');
    el.querySelectorAll('.ed-box').forEach((cb) => {
      cb.addEventListener('change', (e) => {
        setChecklistItem(e.target.dataset.id, e.target.checked);
        e.target.closest('.triage-item').classList.toggle('checked', e.target.checked);
        updateProgressBadge(data);
        if (edFilter === 'OPEN') renderEditorial();
      });
    });
  }
  renderEditorial();

  document.querySelectorAll('#ed-filters .filter-pill').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#ed-filters .filter-pill').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      edFilter = btn.dataset.filter;
      renderEditorial();
    });
  });
  document.getElementById('ed-search').addEventListener('input', (e) => { edSearch = e.target.value; renderEditorial(); });

  document.querySelectorAll('.kdp-box').forEach((cb) => {
    cb.addEventListener('change', (e) => {
      setChecklistItem(e.target.dataset.id, e.target.checked);
      e.target.closest('.kdp-item').classList.toggle('checked', e.target.checked);
      updateProgressBadge(data);
    });
  });

  // Heatmap renderer with Track Switcher
  let hmMode = 'engagement';
  let hmTrack = 'ALL';
  function renderHeatmap() {
    const wrap = document.getElementById('heatmap-wrap');
    const means = [0, 1, 2, 3, 4, 5].map((idx) => {
      const vals = data.reviewers
        .map((r) => (hmTrack === 'ALL' ? r.consolidated_sittings[idx]?.[hmMode] : r.tracks[hmTrack]?.sittings[idx]?.[hmMode]))
        .filter((v) => v != null);
      return vals.reduce((a, b) => a + b, 0) / vals.length;
    });
    const rows = data.reviewers
      .map((r) => {
        const cells = [0, 1, 2, 3, 4, 5]
          .map((idx) => {
            const val = hmTrack === 'ALL' ? r.consolidated_sittings[idx]?.[hmMode] : r.tracks[hmTrack]?.sittings[idx]?.[hmMode];
            const c = heatColor(val, hmMode);
            return `<td><div class="hm-cell" style="background:${c.bg};color:${c.fg}">${val != null ? `${Number(val).toFixed(hmTrack === 'ALL' ? 1 : 0)}/10` : '—'}</div></td>`;
          })
          .join('');
        return `<tr><td class="hm-name"><a href="${BASE_PATH}/reviewers/${r.id}.html">${escapeHtml(r.name)}</a></td>${cells}</tr>`;
      })
      .join('');
    wrap.innerHTML = `
      <table class="heatmap-table">
        <thead><tr><th>Reviewer</th><th>S1<br>Ch 1–5</th><th>S2<br>Ch 6–10</th><th>S3<br>Ch 11–15</th><th>S4<br>Ch 16–20</th><th>S5<br>Ch 21–25</th><th>S6<br>Ch 26–30</th></tr></thead>
        <tbody>
          ${rows}
          <tr class="hm-mean-row"><td>Panel Mean (${hmMode === 'engagement' ? 'Engagement' : 'DNF-Risk'})</td>${means.map((v) => `<td style="text-align:center">${v.toFixed(2)}</td>`).join('')}</tr>
        </tbody>
      </table>
      ${buildHeatmapSvg(data.reviewers, hmTrack)}`;
  }
  renderHeatmap();

  document.querySelectorAll('#heatmap-toggle .filter-pill').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#heatmap-toggle .filter-pill').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      hmMode = btn.dataset.mode;
      renderHeatmap();
    });
  });
  document.querySelectorAll('#hm-track-toggle .filter-pill').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#hm-track-toggle .filter-pill').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      hmTrack = btn.dataset.track;
      renderHeatmap();
    });
  });

  wireGlobalShellHandlers();
}

function renderReviewerPage(data, reviewerId) {
  const idx = data.reviewers.findIndex((r) => r.id === reviewerId);
  const rev = data.reviewers[idx];
  if (!rev) { document.getElementById('app').innerHTML = '<div style="padding:2rem">Reviewer not found.</div>'; return; }

  const prev = idx > 0 ? data.reviewers[idx - 1] : null;
  const next = idx < data.reviewers.length - 1 ? data.reviewers[idx + 1] : null;
  const catClass = rev.category === 'core_icp' ? 'badge-icp' : 'badge-skeptic';
  const c3 = rev.consensus_3way;

  const ta = rev.tracks['track-a-diverse'];
  const tb = rev.tracks['track-b-hydrogen'];
  const tc = rev.tracks['track-c-deepseek-flash'];

  const f3 = c3.findings.filter((x) => x.agreement === '3/3');
  const f2 = c3.findings.filter((x) => x.agreement === '2/3');
  const f1 = c3.findings.filter((x) => x.agreement === '1/3');

  function renderFindingCard(f) {
    return `
      <div class="triage-item" style="grid-template-columns:1fr">
        <div>
          <div class="triage-head">
            <span class="agree-pill ${agreeBadgeClass(f.agreement)}">${escapeHtml(f.agreement)}</span>
            ${f.kind === 'objective' ? '<span class="agree-pill agree-obj">Objective</span>' : '<span class="badge badge-model">Editorial</span>'}
            <span class="triage-title">${escapeHtml(f.location)} — ${escapeHtml(f.title)}</span>
          </div>
          <div class="triage-evidence">${inlineMd(f.evidence)}</div>
          <div class="triage-rec"><strong>Recommendation:</strong> ${inlineMd(f.recommendation)}</div>
        </div>
      </div>`;
  }

  const consensusHtml = `
    <div class="verdict-banner" style="margin-top:0">
      <strong>3-Model Persona Synthesis:</strong> ${inlineMd(c3.executive_summary)}
    </div>

    <div class="section-header" style="margin-top:1.25rem">
      <h3>Consensus Strengths</h3>
      <span class="section-sub">What all 3 models agreed this reader loved</span>
    </div>
    <div class="triage-list" style="margin-bottom:1.75rem">
      ${c3.strengths
        .map(
          (s) => `
        <div class="triage-item" style="grid-template-columns:1fr">
          <div>
            <div class="triage-head">
              <span class="agree-pill ${agreeBadgeClass(s.agreement)}">${escapeHtml(s.agreement)}</span>
              <span class="triage-title">${escapeHtml(s.title)}</span>
            </div>
            <div class="triage-evidence">${inlineMd(s.evidence)}</div>
            <div style="font-size:0.88rem;color:var(--ink)">${inlineMd(s.summary)}</div>
          </div>
        </div>`
        )
        .join('')}
    </div>

    <div class="section-header">
      <h3>3/3 Unanimous Findings (${f3.length})</h3>
      <span class="section-sub">Flagged independently by all 3 AI models</span>
    </div>
    <div class="triage-list" style="margin-bottom:1.75rem">
      ${f3.length ? f3.map(renderFindingCard).join('') : '<div class="prose-card" style="color:var(--ink-muted)">No unanimous findings.</div>'}
    </div>

    <div class="section-header">
      <h3>2/3 Majority Findings (${f2.length})</h3>
      <span class="section-sub">Corroborated by 2 of 3 models</span>
    </div>
    <div class="triage-list" style="margin-bottom:1.25rem">
      ${f2.length ? f2.map(renderFindingCard).join('') : '<div class="prose-card" style="color:var(--ink-muted)">No majority findings.</div>'}
    </div>

    <details class="outlier-drawer">
      <summary>
        <span>1/3 Single-Model Outliers (${f1.length}) — Click to expand minority catches</span>
        <span>Expand ▾</span>
      </summary>
      <div class="outlier-drawer-body">${f1.map(renderFindingCard).join('')}</div>
    </details>`;

  document.title = `${rev.name} (${rev.star_mean.toFixed(2)}★) — Hedged 3-Track Portal`;
  document.getElementById('app').innerHTML = `
    <div class="app-shell">
      ${buildSidebar(data, rev.id)}
      <main class="main-content">
        <div style="margin-bottom:1rem;font-size:0.85rem">
          <a href="${BASE_PATH}/index.html">← Back to 3-Track Consensus Portal</a>
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
            <span class="badge badge-star">Consolidated: ${rev.star_mean.toFixed(2)} / 5.0 ${renderStars(rev.star_mean)}</span>
            <span class="badge badge-model">Agreement: ${escapeHtml(rev.agreement_label)} (±${rev.star_spread.toFixed(1)}★)</span>
            ${rev.reads_pdf_extract ? '<span class="badge badge-pdf">Audited KDP 5.5×8.5 PDF</span>' : ''}
          </div>
          <div class="track-strip" style="margin-bottom:0">
            <div class="track-chip"><span>Track A · ${escapeHtml(ta.model_family)}</span><strong>${ta.star_rating.toFixed(1)}★</strong></div>
            <div class="track-chip"><span>Track B · Gemini Hydrogen (Med)</span><strong>${tb.star_rating.toFixed(1)}★</strong></div>
            <div class="track-chip"><span>Track C · DeepSeek V4.1 Flash</span><strong>${tc.star_rating.toFixed(1)}★</strong></div>
          </div>
        </header>

        <nav class="tab-bar" id="reviewer-tabs">
          <button class="tab-btn active" data-tab="consensus" type="button">3-Model Consensus</button>
          <button class="tab-btn" data-tab="part-a" type="button">Part A: Editorial Stress-Test</button>
          <button class="tab-btn" data-tab="part-b" type="button">Part B: Public ARC Review</button>
          <button class="tab-btn" data-tab="journal" type="button">6-Sitting Reading Journal</button>
          <button class="tab-btn" data-tab="persona" type="button">Persona Portfolio &amp; ICP</button>
        </nav>

        <section class="tab-panel" id="tab-consensus">${consensusHtml}</section>
        <section class="tab-panel" id="tab-part-a" hidden></section>
        <section class="tab-panel" id="tab-part-b" hidden></section>
        <section class="tab-panel" id="tab-journal" hidden></section>
        <section class="tab-panel" id="tab-persona" hidden>
          <div class="prose-card md-body">${renderMarkdown(rev.persona_md)}</div>
        </section>

        <nav class="pager">
          ${prev ? `<a href="${BASE_PATH}/reviewers/${prev.id}.html">← ${escapeHtml(prev.name)} (${prev.star_mean.toFixed(2)}★)</a>` : `<a href="${BASE_PATH}/index.html">← 3-Track Consensus Portal</a>`}
          ${next ? `<a href="${BASE_PATH}/reviewers/${next.id}.html">${escapeHtml(next.name)} (${next.star_mean.toFixed(2)}★) →</a>` : `<a href="${BASE_PATH}/index.html">3-Track Consensus Portal →</a>`}
        </nav>
      </main>
    </div>`;

  let selectedTrack = 'track-b-hydrogen';
  function switcherHtml() {
    return `
      <div class="model-switcher">
        <button class="model-switch-btn ${selectedTrack === 'track-a-diverse' ? 'active' : ''}" data-tr="track-a-diverse" type="button">Track A · ${escapeHtml(ta.model_family)} (${ta.star_rating.toFixed(1)}★)</button>
        <button class="model-switch-btn ${selectedTrack === 'track-b-hydrogen' ? 'active' : ''}" data-tr="track-b-hydrogen" type="button">Track B · Hydrogen (${tb.star_rating.toFixed(1)}★)</button>
        <button class="model-switch-btn ${selectedTrack === 'track-c-deepseek-flash' ? 'active' : ''}" data-tr="track-c-deepseek-flash" type="button">Track C · DeepSeek Flash (${tc.star_rating.toFixed(1)}★)</button>
      </div>`;
  }

  function renderTrackPanels() {
    const tr = rev.tracks[selectedTrack];
    const scHtml = tr.scorecard.length
      ? `<div class="scorecard-grid">${tr.scorecard
          .map(
            (s) => `
          <div class="score-row">
            <div class="score-top"><span>${escapeHtml(s.dimension)}</span><span style="color:var(--sage)">${escapeHtml(s.raw)}</span></div>
            <div class="score-track"><div class="score-fill" style="width:${Math.min(100, s.score * 10)}%;background:${rev.accent}"></div></div>
            <div class="score-note">${inlineMd(s.note)}</div>
          </div>`
          )
          .join('')}</div>`
      : '';

    document.getElementById('tab-part-a').innerHTML = `
      ${switcherHtml()}
      ${scHtml}
      <div class="prose-card md-body">${renderMarkdown(tr.part_a_md)}</div>`;

    document.getElementById('tab-part-b').innerHTML = `
      ${switcherHtml()}
      <div class="goodreads-card">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;margin-bottom:0.75rem">
          <div class="gr-stars">${renderStars(tr.star_rating)} <span style="font-size:1rem;color:var(--ink);font-weight:700">${tr.star_display}</span></div>
          <div class="rc-badges">${tr.tags.map((t) => `<span class="badge badge-icp">${escapeHtml(t)}</span>`).join('')}</div>
        </div>
        <div class="md-body">${renderMarkdown(tr.part_b_md)}</div>
      </div>`;

    const sittingsHtml = tr.sittings
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

    document.getElementById('tab-journal').innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;margin-bottom:0.85rem">
        ${switcherHtml()}
        <div style="display:flex;gap:0.45rem">
          <button class="filter-pill" id="expand-all-sittings" type="button">Expand All</button>
          <button class="filter-pill" id="collapse-all-sittings" type="button">Collapse All</button>
        </div>
      </div>
      ${sittingsHtml}`;

    document.querySelectorAll('.model-switch-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        selectedTrack = btn.dataset.tr;
        renderTrackPanels();
      });
    });
    document.getElementById('expand-all-sittings')?.addEventListener('click', () => {
      document.querySelectorAll('.sitting-card').forEach((d) => (d.open = true));
    });
    document.getElementById('collapse-all-sittings')?.addEventListener('click', () => {
      document.querySelectorAll('.sitting-card').forEach((d) => (d.open = false));
    });
  }

  renderTrackPanels();

  document.querySelectorAll('#reviewer-tabs .tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#reviewer-tabs .tab-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const target = btn.dataset.tab;
      document.querySelectorAll('.tab-panel').forEach((p) => { p.hidden = p.id !== `tab-${target}`; });
    });
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
  document.getElementById('app').innerHTML = `
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
        <div class="lock-footnote">AES-256-GCM · PBKDF2-SHA256 · Unindexed &amp; Private</div>
      </div>
    </div>`;

  const passInput = document.getElementById('pass-input');
  const errEl = document.getElementById('lock-error');
  const submitBtn = document.getElementById('unlock-btn');
  document.getElementById('toggle-vis').addEventListener('click', (e) => {
    const isPw = passInput.type === 'password';
    passInput.type = isPw ? 'text' : 'password';
    e.target.textContent = isPw ? 'Hide' : 'Show';
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
  if (PAGE_TYPE === 'reviewer') renderReviewerPage(data, REVIEWER_ID);
  else renderPortalPage(data);
}

async function boot() {
  try {
    const res = await fetch(`${BASE_PATH}/data/portal.enc.json`, { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const encObj = await res.json();
    const saved = sessionStorage.getItem(SESSION_KEY);
    if (saved) {
      try { mountPortal(await decryptBundle(encObj, saved)); return; } catch { sessionStorage.removeItem(SESSION_KEY); }
    }
    renderLockScreen(encObj);
  } catch (err) {
    document.getElementById('app').innerHTML = `<div class="lock-screen"><div class="lock-card"><h1>Unable to Load Portal</h1><p>${escapeHtml(err.message)}</p></div></div>`;
  }
}

boot();
