/* ------------------------------------------------------------------------
   Analytics: heat map, hours histogram, stacked bars, data volume, timeline,
   per-person comparison and the "most frequent" lists.
   Everything is drawn as inline SVG / CSS - no external chart library, so the
   dashboard keeps working offline and nothing is loaded from the internet.
   ------------------------------------------------------------------------ */

const ana = {
  person: '', range: 'week', view: 'heat', topDim: 'url', topOrder: 'seconds',
  key: '', day: null, data: {}
};

const PALETTE = ['#58a6ff', '#7ee787', '#e3b341', '#ff9d96', '#c8a2ff', '#79c0ff',
                 '#f0883e', '#56d4dd', '#db61a2', '#a5d6ff', '#8ddb8c', '#d2a8ff'];

/* ------------------------------- helpers ------------------------------- */

function esc2(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function fmtBytes(bytes) {
  bytes = Number(bytes || 0);
  if (!bytes) return '0 MB';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i += 1; }
  return (bytes >= 100 || i === 0 ? Math.round(bytes) : bytes.toFixed(1)) + ' ' + units[i];
}
function fmtSecs(seconds) {
  seconds = Math.round(Number(seconds || 0));
  const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60), s = seconds % 60;
  if (h) return h + 'h ' + m + 'm';
  if (m) return m + 'm ' + s + 's';
  return s + 's';
}
function hourLabel(hour) { return String(hour).padStart(2, '0') + ':00'; }
function shortDay(day) { return day ? day.slice(5) : ''; }

function anaParams(extra) {
  const params = {range: ana.range};
  if (ana.person) params.person = ana.person;
  return Object.assign(params, extra || {});
}
function query(params) {
  return Object.keys(params)
    .filter(k => params[k] !== '' && params[k] !== null && params[k] !== undefined)
    .map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k])).join('&');
}

/* --------------------------- heat map (hours) --------------------------- */

function renderHeatmap(root, data) {
  const max = data.max_seconds || 1;
  const colours = ['#0d1f16', '#0f3d24', '#12603a', '#1b8a4b', '#2ea043', '#56d364', '#7ee787'];
  let html = '<div class="ana-heat">';
  html += '<div class="ana-heat-head"><span></span>';
  for (let h = 0; h < 24; h += 1) {
    html += '<span class="ana-heat-hlabel">' + (h % 3 === 0 ? String(h).padStart(2, '0') : '') + '</span>';
  }
  html += '<span class="ana-heat-total">day total</span></div>';
  (data.days || []).slice().reverse().forEach(day => {
    html += '<div class="ana-heat-row' + (ana.day === day.day ? ' sel' : '') + '" data-day="' + day.day + '">';
    html += '<span class="ana-heat-day" title="' + day.day + '">' + shortDay(day.day) + '</span>';
    for (let h = 0; h < 24; h += 1) {
      const seconds = (day.hours && day.hours[h]) || 0;
      const ratio = seconds / max;
      let level = 0;
      if (seconds > 0) level = Math.max(1, Math.min(6, Math.round(ratio * 6) || 1));
      const tip = day.day + ' ' + hourLabel(h) + ' · ' + fmtSecs(seconds);
      html += '<span class="ana-cell' + (seconds ? ' l' + level : '') + '" data-day="' + day.day +
        '" data-hour="' + h + '" title="' + esc2(tip) + '"></span>';
    }
    html += '<span class="ana-heat-sum">' + day.human + '</span></div>';
  });
  html += '</div>';
  html += '<div class="ana-legend">' + colours.map((c, i) =>
    '<i style="background:' + c + '"></i>').join('') +
    ' <span class="muted">quiet → busy (peak hour ' +
    esc2(data.totals.busiest_hour === null ? '—' : hourLabel(data.totals.busiest_hour)) + ')</span></div>';
  root.innerHTML = html;
  root.querySelectorAll('.ana-cell').forEach(cell => {
    cell.onclick = () => { selectDay(data, cell.dataset.day, cell.dataset.hour); };
  });
  root.querySelectorAll('.ana-heat-day').forEach(label => {
    label.onclick = () => { selectDay(data, label.parentNode.dataset.day, null); };
  });
}

async function selectDay(data, day, hour) {
  ana.day = day;
  renderHeatmap(document.getElementById('anaHeat'), data);
  const panel = document.getElementById('anaDayPanel');
  panel.style.display = 'block';
  panel.innerHTML = '<div class="empty">loading ' + esc2(day) +
    (hour !== null && hour !== undefined ? ' ' + hourLabel(Number(hour)) : '') + '…</div>';
  const usageP = api('/api/intel/usage?' + query({date: day, range: 'day', dimension: 'app',
    person: ana.person || ''})).catch(() => null);
  const siteP = api('/api/intel/usage?' + query({date: day, range: 'day', dimension: 'site',
    person: ana.person || ''})).catch(() => null);
  const logP = api('/api/intel/daylog?' + query({date: day, range: 'day', person: ana.person || '',
    per_day: 60})).catch(() => null);
  const [apps, sites, log] = await Promise.all([usageP, siteP, logP]);

  let html = '<div class="head"><h2>What happened on ' + esc2(day) +
    (hour !== null && hour !== undefined ? ' around ' + hourLabel(Number(hour)) : '') + '</h2>' +
    '<span class="spacer"></span>' +
    '<button class="btn" id="anaDayClose">close</button></div><div class="body">';
  if (apps && apps.items && apps.items.length) {
    const total = apps.totals.seconds || 1;
    html += '<div class="ana-split"><div><h3>Apps</h3><table class="ana-table"><tbody>' +
      apps.items.map(item => '<tr><td>' + esc2(item.name || item.key) +
        '<div class="muted" style="font-size:11px">' + esc2(item.category || '') + '</div></td>' +
        '<td class="right">' + esc2(item.human) + '</td>' +
        '<td style="width:120px">' + bar((item.seconds || 0) / total) + '</td></tr>').join('') +
      '</tbody></table></div>';
    html += '<div><h3>Sites</h3><table class="ana-table"><tbody>' +
      ((sites && sites.items) || []).slice(0, 12).map(item =>
        '<tr><td>' + esc2(item.name || item.key) + '</td><td class="right">' +
        esc2(item.human) + '</td></tr>').join('') + '</tbody></table></div></div>';
  } else {
    html += '<div class="empty">No app-level activity recorded for that day.</div>';
  }
  const entries = (log && log.days && log.days[0] && log.days[0].entries) || [];
  if (entries.length) {
    html += '<h3 style="margin-top:14px">Visits (newest first)</h3><table class="ana-table"><tbody>' +
      entries.map(entry => {
        let match = '';
        if (hour !== null && hour !== undefined) {
          const visitHour = parseInt((entry.time || '00:00').split(':')[0], 10);
          match = visitHour === Number(hour) ? ' style="background:rgba(88,166,255,.12)"' : '';
        }
        return '<tr' + match + '><td class="mono">' + esc2(entry.time) + '</td><td>' +
          esc2(entry.url || entry.domain || '') + '</td><td>' + esc2(entry.app || '—') + '</td>' +
          '<td>' + esc2(entry.category || '') + '</td><td class="right">' + esc2(entry.human) +
          '</td><td>' + (entry.person ? esc2(entry.person) : '<span class="muted">unknown</span>') +
          '</td></tr>';
      }).join('') + '</tbody></table>';
  }
  html += '</div>';
  panel.innerHTML = html;
  const close = document.getElementById('anaDayClose');
  if (close) close.onclick = () => { panel.style.display = 'none'; };
}

/* --------------------------- hours histogram --------------------------- */

function renderHours(root, data) {
  const hours = data.hours || [];
  const max = Math.max(1, ...hours.map(h => h.seconds));
  const width = 720, height = 190, pad = 26, barW = (width - pad * 2) / 24;
  let svg = '<svg viewBox="0 0 ' + width + ' ' + height + '" class="ana-svg">';
  svg += '<line x1="' + pad + '" y1="' + (height - pad) + '" x2="' + (width - pad) + '" y2="' +
    (height - pad) + '" stroke="#2b3540"/>';
  hours.forEach((hour, index) => {
    const h = Math.round((hour.seconds / max) * (height - pad * 2));
    const x = pad + index * barW + 2;
    const y = height - pad - h;
    const colour = hour.seconds ? PALETTE[Math.min(PALETTE.length - 1, Math.floor(index / 2) % PALETTE.length)] : '#222b35';
    svg += '<rect x="' + x.toFixed(1) + '" y="' + y + '" width="' + (barW - 4).toFixed(1) +
      '" height="' + Math.max(1, h) + '" rx="3" fill="' + colour + '" opacity="' +
      (hour.seconds ? 0.9 : 0.25) + '"><title>' + hourLabel(index) + ' · ' + hour.human +
      '</title></rect>';
    if (index % 2 === 0) {
      svg += '<text x="' + (x + (barW - 4) / 2).toFixed(1) + '" y="' + (height - pad + 14) +
        '" text-anchor="middle" class="ana-axis">' + index + '</text>';
    }
  });
  svg += '<text x="' + pad + '" y="14" class="ana-axis">busiest hour: ' +
    (data.totals.busiest_hour === null ? '—' : hourLabel(data.totals.busiest_hour)) +
    ' · peak ' + Math.round(max / 60) + ' min</text>';
  svg += '</svg>';
  root.innerHTML = svg + '<div class="muted" style="font-size:11.5px">Hour of day (0–23) · ' +
    'total ' + esc2(data.totals.human) + ' in this range</div>';
}

/* ---------------------- stacked daily bars + volume --------------------- */

function renderStacked(root, data, mode) {
  const days = data.days || [];
  const series = (data.stacked || []).slice(0, 8);
  const useBytes = mode === 'volume';
  const totals = days.map(day => useBytes ? (day.bytes || 0) : (day.seconds || 0));
  const max = Math.max(1, ...totals);
  const width = 720, height = 210, pad = 30, slot = (width - pad * 2) / Math.max(1, days.length);
  let svg = '<svg viewBox="0 0 ' + width + ' ' + height + '" class="ana-svg">';
  svg += '<line x1="' + pad + '" y1="' + (height - pad) + '" x2="' + (width - pad) + '" y2="' +
    (height - pad) + '" stroke="#2b3540"/>';
  days.forEach((day, index) => {
    const x = pad + index * slot + 2;
    if (useBytes) {
      const value = day.bytes || 0;
      const h = Math.round((value / max) * (height - pad * 2));
      svg += '<rect x="' + x.toFixed(1) + '" y="' + (height - pad - h) + '" width="' +
        Math.max(2, slot - 5).toFixed(1) + '" height="' + Math.max(1, h) +
        '" rx="3" fill="#58a6ff"><title>' + day.day + ' · ' + fmtBytes(value) + '</title></rect>';
    } else {
      let y = height - pad;
      series.forEach(seriesItem => {
        const point = (seriesItem.points || []).find(p => p.day === day.day);
        const value = point ? point.seconds : 0;
        if (!value) return;
        const h = (value / max) * (height - pad * 2);
        const colour = PALETTE[series.indexOf(seriesItem) % PALETTE.length];
        y -= h;
        svg += '<rect x="' + x.toFixed(1) + '" y="' + y.toFixed(1) + '" width="' +
          Math.max(2, slot - 5).toFixed(1) + '" height="' + h.toFixed(1) + '" fill="' + colour +
          '"><title>' + day.day + ' · ' + (seriesItem.name || seriesItem.key) + ' ' +
          fmtSecs(value) + '</title></rect>';
      });
    }
    if (slot > 16 || index % 3 === 0) {
      svg += '<text x="' + (x + slot / 2).toFixed(1) + '" y="' + (height - pad + 14) +
        '" text-anchor="middle" class="ana-axis">' + shortDay(day.day) + '</text>';
    }
  });
  svg += '</svg>';
  let legend = '';
  if (!useBytes && series.length) {
    legend = '<div class="ana-legend wrap">' + series.map((item, index) =>
      '<span><i style="background:' + PALETTE[index % PALETTE.length] + '"></i> ' +
      esc2(item.name || item.key) + ' <span class="muted">' + esc2(item.human) + '</span></span>').join('') +
      '</div>';
  }
  const caption = useBytes
    ? 'Data volume per day · total ' + fmtBytes(data.totals.bytes || 0)
    : 'Time per day, stacked by ' + (data.dimension === 'site' ? 'site' : data.dimension) +
      ' · total ' + esc2(data.totals.human);
  root.innerHTML = svg + legend + '<div class="muted" style="font-size:11.5px">' + caption + '</div>';
}

/* --------------------------- day timeline (gantt) ----------------------- */

function renderTimeline(root, data) {
  if (!data.bands || !data.bands.length) {
    root.innerHTML = '<div class="empty">Nothing recorded on ' + esc2(data.day || '') +
      ' — pick another day, or widen the range.</div>';
    return;
  }
  const width = 760, rowH = 34, pad = 92, height = data.bands.length * rowH + 40;
  const scale = (minute) => pad + (minute / 1440) * (width - pad - 16);
  let svg = '<svg viewBox="0 0 ' + width + ' ' + height + '" class="ana-svg">';
  for (let hour = 0; hour <= 24; hour += 2) {
    const x = scale(hour * 60);
    svg += '<line x1="' + x.toFixed(1) + '" y1="18" x2="' + x.toFixed(1) + '" y2="' +
      (height - 18) + '" stroke="#212a33"/>' +
      '<text x="' + x.toFixed(1) + '" y="12" text-anchor="middle" class="ana-axis">' +
      String(hour).padStart(2, '0') + '</text>';
  }
  data.bands.forEach((band, index) => {
    const y = 26 + index * rowH;
    svg += '<text x="4" y="' + (y + 15) + '" class="ana-band">' +
      esc2((band.name || '').slice(0, 14)) + '</text>';
    band.intervals.forEach(interval => {
      const x = scale(interval.start);
      const w = Math.max(2, scale(interval.end) - x);
      const colour = PALETTE[(band.intervals.indexOf(interval)) % PALETTE.length];
      svg += '<rect x="' + x.toFixed(1) + '" y="' + (y + 3) + '" width="' + w.toFixed(1) +
        '" height="15" rx="3" fill="' + colour + '" opacity="' +
        (interval.estimated ? 0.45 : 0.9) + '"><title>' + esc2(interval.start_time + '–' +
        interval.end_time + ' · ' + (interval.app || interval.domain || '') + ' · ' + interval.human) +
        '</title></rect>';
    });
  });
  svg += '</svg>';
  root.innerHTML = svg + '<div class="muted" style="font-size:11.5px">' +
    esc2(data.day) + ' · ' + esc2(data.total_human) + ' online · faded bands are estimated ' +
    '(connection-table sampling)</div>';
}

/* ------------------------- per-person comparison ------------------------ */

function renderPeopleBars(root, data) {
  const people = data.people || [];
  if (!people.length) {
    root.innerHTML = '<div class="empty">No people bound to devices yet — ' +
      'use <b>Family &amp; devices</b> to allocate them.</div>';
    return;
  }
  const max = Math.max(1, ...people.map(p => p.seconds));
  root.innerHTML = '<table class="ana-table"><thead><tr><th>Person</th><th></th>' +
    '<th class="right">Time</th><th class="right">Share</th></tr></thead><tbody>' +
    people.map(person => '<tr><td><span class="dot" style="background:' + esc2(person.color) +
      '"></span> ' + esc2(person.name) + '</td><td style="width:240px">' +
      bar(person.seconds / max) + '</td><td class="right">' + esc2(person.human) +
      '</td><td class="right">' + Math.round((person.seconds / (data.totals.seconds || 1)) * 100) +
      '%</td></tr>').join('') + '</tbody></table>';
}

/* ---------------------------- top lists -------------------------------- */

async function loadTop() {
  const root = document.getElementById('anaTop');
  if (!root) return;
  root.innerHTML = '<div class="empty">loading…</div>';
  const data = await api('/api/intel/top?' + query(anaParams({dimension: ana.topDim,
    order: ana.topOrder, limit: 15}))).catch(() => null);
  if (!data) { root.innerHTML = '<div class="empty">unavailable</div>'; return; }
  const isUrl = data.dimension === 'url';
  root.innerHTML = '<table class="ana-table"><thead><tr><th>#</th><th>' +
    (isUrl ? 'URL' : 'Name') + '</th><th>App / category</th><th class="right">Time</th>' +
    '<th class="right">' + (isUrl ? 'Visits' : 'Sessions') + '</th>' +
    '<th class="right">Data</th><th class="right">Share</th></tr></thead><tbody>' +
    data.items.map((item, index) => '<tr><td class="muted">' + (index + 1) + '</td>' +
      '<td class="mono" style="font-size:11.5px">' + esc2(item.key) + '</td>' +
      '<td>' + esc2(item.app || '—') + '<div class="muted" style="font-size:11px">' +
      esc2(item.category || '') + '</div></td>' +
      '<td class="right">' + esc2(item.human) + '</td>' +
      '<td class="right">' + item.visits + '</td>' +
      '<td class="right">' + fmtBytes(item.bytes) + '</td>' +
      '<td class="right">' + Math.round((item.share || 0) * 100) + '%</td></tr>').join('') +
    '</tbody></table>';
}

/* ------------------------------ page wiring ---------------------------- */

let analyticsReady = false;

async function loadAnalytics() {
  // controls are wired on first use, so the tab works whether it is opened by
  // the tab bar or by a deep link (#analytics)
  if (!analyticsReady) {
    try { initAnalytics(); analyticsReady = true; }
    catch (error) { setApiError('Analytics controls: ' + error.message); }
  }
  const people = await api('/api/intel/people').catch(() => null);
  const pick = document.getElementById('anaPerson');
  if (pick) {
    const current = ana.person;
    pick.innerHTML = '<option value="">All people</option>' +
      ((people && people.people) || []).map(person => '<option value="' + person.id + '">' +
        esc2(person.display_name || person.name) + '</option>').join('');
    pick.value = current;
  }
  await refreshAnalytics();
}

// expose for the inline dashboard script (see analyticsTab() there)
window.loadAnalytics = loadAnalytics;
window.initAnalytics = initAnalytics;
window.refreshAnalytics = refreshAnalytics;

async function refreshAnalytics() {
  const person = document.getElementById('anaPerson');
  const range = document.getElementById('anaRange');
  if (person) ana.person = person.value;
  if (range) ana.range = range.value;

  const heat = await api('/api/intel/heatmap?' + query(anaParams())).catch(() => null);
  const series = await api('/api/intel/series?' + query(anaParams({dimension: 'category',
    top: 7}))).catch(() => null);

  if (heat) {
    renderHeatmap(document.getElementById('anaHeat'), heat);
    renderHours(document.getElementById('anaHours'), heat);
    const kpis = document.getElementById('anaKpis');
    if (kpis) {
      kpis.innerHTML = [
        ['Total in range', heat.totals.human],
        ['Active days', heat.totals.active_days + ' of ' + heat.days.length],
        ['Busiest day', heat.totals.busiest_day || '—'],
        ['Busiest hour', heat.totals.busiest_hour === null ? '—' : hourLabel(heat.totals.busiest_hour)],
        ['Person', heat.person ? heat.person.name : 'all'],
      ].map(pair => '<div class="kpi"><div class="v">' + esc2(pair[1]) + '</div><div class="k">' +
        esc2(pair[0]) + '</div></div>').join('');
      kpis.dataset.total = heat.totals.seconds;
    }
  } else {
    setApiError('Analytics unavailable.');
  }

  if (series) {
    renderStacked(document.getElementById('anaStacked'), series, ana.view === 'volume' ? 'volume' : 'time');
    renderPeopleBars(document.getElementById('anaPeople'), series);
    const volume = document.getElementById('anaVolumeNote');
    if (volume) volume.textContent = fmtBytes(series.totals.bytes || 0) + ' transferred · ' +
      (series.totals.sessions || 0) + ' sessions';
  }

  const day = ana.day || (heat && heat.totals.busiest_day) || new Date().toISOString().slice(0, 10);
  ana.day = day;
  const gantt = await api('/api/intel/gantt?' + query({date: day, by: 'person',
    person: ana.person || ''})).catch(() => null);
  if (gantt) renderTimeline(document.getElementById('anaTimeline'), gantt);

  await loadTop();
}

function initAnalytics() {
  const person = document.getElementById('anaPerson');
  const range = document.getElementById('anaRange');
  const refresh = document.getElementById('anaRefresh');
  const topDim = document.getElementById('anaTopDim');
  const topOrder = document.getElementById('anaTopOrder');
  if (person) person.onchange = () => refreshAnalytics();
  if (range) range.onchange = () => refreshAnalytics();
  if (refresh) refresh.onclick = () => refreshAnalytics();
  if (topDim) topDim.onchange = () => { ana.topDim = topDim.value; loadTop(); };
  if (topOrder) topOrder.onchange = () => { ana.topOrder = topOrder.value; loadTop(); };
  document.querySelectorAll('[data-ana-view]').forEach(button => {
    button.onclick = () => {
      ana.view = button.dataset.anaView;
      document.querySelectorAll('[data-ana-view]').forEach(other =>
        other.classList.toggle('active', other === button));
      document.querySelectorAll('[data-ana-pane]').forEach(pane =>
        pane.style.display = pane.dataset.anaPane === ana.view ? '' : 'none');
    };
  });
}
