/* ------------------------------------------------------------------------
   Mobile "History" view for the classic dashboard.

   Layout follows the phone-first design: day accordions, a dot-and-line
   timeline of visits, the URL, the "Category · App" line, and the time on the
   left.  Data comes from /api/intel/daylog, so this is the same evidence the
   advanced dashboard uses - just shaped for a small screen.
   ------------------------------------------------------------------------ */

const hist = {person: '', range: 'week', open: {}, data: null, tab: 'timeline', assignment: null};

function hEsc(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function hSecs(seconds) {
  seconds = Math.round(Number(seconds || 0));
  const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60);
  if (h) return h + 'h ' + m + 'm';
  if (m) return m + 'm';
  return seconds + 's';
}
function hTime12(twentyFour) {
  const parts = String(twentyFour || '00:00').split(':');
  let hour = parseInt(parts[0], 10);
  const minute = parts[1] || '00';
  const suffix = hour >= 12 ? 'PM' : 'AM';
  hour = hour % 12; if (!hour) hour = 12;
  return hour + ':' + minute + ' ' + suffix;
}
function hDayLabel(day) {
  const date = new Date(day + 'T12:00:00');
  const today = new Date();
  const yesterday = new Date(Date.now() - 86400000);
  const same = (a, b) => a.toDateString() === b.toDateString();
  if (same(date, today)) return 'Today · ' + date.toLocaleDateString(undefined, {day: 'numeric', month: 'long'});
  if (same(date, yesterday)) return 'Yesterday · ' + date.toLocaleDateString(undefined, {day: 'numeric', month: 'long'});
  return date.toLocaleDateString(undefined, {weekday: 'short', day: 'numeric', month: 'long'});
}
function hFavicon(entry) {
  /* A local, offline "favicon": the first letter in a coloured circle.  No
     external requests, so the phone view works on a network with no internet. */
  const name = entry.app || entry.domain || '?';
  const colours = ['#667eea', '#48bb78', '#f6ad55', '#fc8181', '#764ba2', '#3182ce', '#d69e2e'];
  let hash = 0;
  for (let i = 0; i < name.length; i += 1) hash = (hash * 31 + name.charCodeAt(i)) % 997;
  const colour = colours[hash % colours.length];
  return '<span class="hfav" style="background:' + colour + '">' +
    hEsc(name.trim().charAt(0).toUpperCase()) + '</span>';
}

async function histAssignment() {
  if (hist.assignment) return hist.assignment;
  hist.assignment = await fetch('/api/intel/assignment').then(r => r.json()).catch(() => null);
  return hist.assignment;
}

/* ------------------------- person pills in the strip -------------------- */

async function loadPersonPills() {
  const strip = document.getElementById('intel-strip');
  if (!strip) return;
  const data = await histAssignment();
  if (!data || !data.people || !data.people.length) return;
  const row = document.createElement('div');
  row.className = 'isrow';
  row.id = 'person-pills';
  row.innerHTML = '<span class="islabel">people</span>' +
    data.people.map(person =>
      '<button class="hpill" data-person="' + person.id + '">' +
      '<span class="dot" style="background:' + hEsc(person.color) + '"></span>' +
      hEsc(person.display_name || person.name) +
      '<span class="hcount">' + person.macs.length + ' device' +
      (person.macs.length === 1 ? '' : 's') + '</span></button>').join('') +
    '<button class="hpill ghost" id="hOpenHistory">History timeline →</button>';
  const anchor = strip.querySelector('.isrow:last-child');
  if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(row, anchor.nextSibling);
  else strip.appendChild(row);
  row.querySelectorAll('[data-person]').forEach(button => {
    button.onclick = () => { hist.person = button.dataset.person; openHistory(); };
  });
  const open = document.getElementById('hOpenHistory');
  if (open) open.onclick = () => { hist.person = ''; openHistory(); };
}

/* ------------------------------ the overlay ----------------------------- */

function historyOverlay() {
  let overlay = document.getElementById('history-overlay');
  if (overlay) return overlay;
  overlay = document.createElement('div');
  overlay.id = 'history-overlay';
  overlay.innerHTML = [
    '<div class="hsheet">',
    '  <div class="hhead">',
    '    <button class="hback" id="hClose">←</button>',
    '    <h1>History</h1>',
    '    <a class="hadv" href="/intel#analytics" title="open the advanced monitoring dashboard">advanced</a>',
    '  </div>',
    '  <div class="htabs">',
    '    <button id="hTabTimeline" class="active">Timeline</button>',
    '    <button id="hTabApps">Most used</button>',
    '  </div>',
    '  <div class="hfilter">',
    '    <div class="hpeople" id="hPeople"></div>',
    '    <div class="hranges" id="hRanges">',
    '      <button data-range="day">Today</button>',
    '      <button data-range="week" class="active">7 days</button>',
    '      <button data-range="month">30 days</button>',
    '    </div>',
    '  </div>',
    '  <div class="hbody" id="hBody"><div class="hempty">loading…</div></div>',
    '</div>'
  ].join('');
  document.body.appendChild(overlay);
  document.getElementById('hClose').onclick = () => { overlay.style.display = 'none'; };
  document.getElementById('hTabTimeline').onclick = () => {
    hist.tab = 'timeline'; setHistoryTab(); renderHistory();
  };
  document.getElementById('hTabApps').onclick = () => {
    hist.tab = 'apps'; setHistoryTab(); renderHistory();
  };
  overlay.querySelectorAll('[data-range]').forEach(button => {
    button.onclick = () => {
      hist.range = button.dataset.range;
      overlay.querySelectorAll('[data-range]').forEach(other =>
        other.classList.toggle('active', other === button));
      loadHistory();
    };
  });
  return overlay;
}

function setHistoryTab() {
  document.getElementById('hTabTimeline').classList.toggle('active', hist.tab === 'timeline');
  document.getElementById('hTabApps').classList.toggle('active', hist.tab === 'apps');
}

async function openHistory() {
  const overlay = historyOverlay();
  overlay.style.display = 'block';
  await loadHistory();
}

async function loadHistory() {
  const data = hist.assignment || await histAssignment();
  const peopleRoot = document.getElementById('hPeople');
  if (peopleRoot) {
    peopleRoot.innerHTML = '<button data-person="" class="' + (hist.person ? '' : 'active') +
      '">Everyone</button>' +
      ((data && data.people) || []).map(person =>
        '<button data-person="' + person.id + '" class="' +
        (String(hist.person) === String(person.id) ? 'active' : '') + '">' +
        '<span class="dot" style="background:' + hEsc(person.color) + '"></span>' +
        hEsc(person.display_name || person.name) + '</button>').join('');
    peopleRoot.querySelectorAll('[data-person]').forEach(button => {
      button.onclick = () => {
        hist.person = button.dataset.person;
        peopleRoot.querySelectorAll('button').forEach(other =>
          other.classList.toggle('active', other === button));
        loadHistory();
      };
    });
  }
  const body = document.getElementById('hBody');
  body.innerHTML = '<div class="hempty">loading…</div>';
  const params = 'range=' + encodeURIComponent(hist.range) +
    (hist.person ? '&person=' + encodeURIComponent(hist.person) : '');
  const payload = await fetch('/api/intel/daylog?' + params).then(r => r.json()).catch(() => null);
  if (!payload) { body.innerHTML = '<div class="hempty">Could not load history.</div>'; return; }
  hist.data = payload;
  if (hist.tab === 'apps') {
    const top = await fetch('/api/intel/top?' +
      params.replace(/^range=/, 'range=') + '&dimension=app&order=seconds&limit=25')
      .then(r => r.json()).catch(() => null);
    renderHistoryApps(top);
    return;
  }
  renderHistory();
}

function renderHistory() {
  const body = document.getElementById('hBody');
  const payload = hist.data;
  if (!payload || !payload.days || !payload.days.length) {
    body.innerHTML = '<div class="hempty">Nothing recorded in this range yet.<br>' +
      '<span class="hsub">Activity appears here as the collector sees traffic.</span></div>';
    return;
  }
  let html = '<div class="hsummary">' + hEsc(payload.totals.human) + ' online · ' +
    payload.totals.visits + ' visits · ' + payload.totals.days + ' day(s)</div>';
  payload.days.forEach(day => {
    const open = hist.open[day.day] !== false;      /* newest open by default */
    html += '<div class="hday' + (open ? ' open' : '') + '" data-day="' + day.day + '">';
    html += '<button class="hdayhead"><span class="hdaylabel">' + hEsc(hDayLabel(day.day)) +
      '</span><span class="hdaymeta">' + hEsc(day.human) + ' · ' + day.visit_count +
      ' visits</span><span class="hchev">' + (open ? '⌃' : '⌄') + '</span></button>';
    if (open) {
      html += '<div class="hchips">' + (day.top_apps || []).map(app =>
        '<span class="hchip">' + hEsc(app.key) + ' <b>' + hEsc(app.human) + '</b></span>').join('') +
        '</div><div class="htl">';
      (day.entries || []).forEach(entry => {
        html += '<div class="hentry">' +
          '<span class="htime">' + hEsc(hTime12(entry.time)) + '</span>' +
          '<span class="hrail"><i class="hdot' + (entry.is_live ? ' live' : '') +
          (entry.estimated ? ' est' : '') + '"></i></span>' +
          hFavicon(entry) +
          '<span class="hmeta">' +
          '<span class="hurl">' + hEsc((entry.url || entry.domain || 'unknown').replace(/^https?:\/\//, '')) +
          '</span>' +
          '<span class="hsub">' + hEsc([entry.category, entry.app].filter(Boolean).join(' · ') || 'Unclassified') +
          ' · ' + hEsc(entry.human) +
          (entry.person ? ' · <b>' + hEsc(entry.person) + '</b>' : '') +
          (entry.is_live ? ' · <span class="hlive">live</span>' : '') +
          (entry.estimated ? ' · <span class="hest">estimated</span>' : '') +
          '</span></span></div>';
      });
      html += '</div>';
    }
    html += '</div>';
  });
  body.innerHTML = html;
  body.querySelectorAll('.hdayhead').forEach(head => {
    head.onclick = () => {
      const wrapper = head.parentNode;
      const day = wrapper.dataset.day;
      hist.open[day] = !(hist.open[day] !== false);
      renderHistory();
    };
  });
}

function renderHistoryApps(top) {
  const body = document.getElementById('hBody');
  const payload = hist.data;
  if (!top || !top.items || !top.items.length) {
    body.innerHTML = '<div class="hempty">No app-level activity in this range.</div>';
    return;
  }
  const total = (payload && payload.totals && payload.totals.seconds) || top.totals.seconds || 1;
  let html = '<div class="hsummary">Time per app · ' + hEsc(top.totals === undefined ? '' : '') + '</div>';
  html += '<div class="happlist">';
  top.items.forEach(item => {
    const share = Math.round(((item.seconds || 0) / total) * 100);
    html += '<div class="happrow"><div class="happtop"><span>' +
      '<b>' + hEsc(item.label || item.key) + '</b>' +
      '<span class="hsub">' + hEsc(item.category || '') + '</span></span>' +
      '<span class="happtime">' + hEsc(item.human) + ' · ' + share + '%</span></div>' +
      '<div class="hbar"><i style="width:' + Math.max(2, share) + '%"></i></div></div>';
  });
  html += '</div>';
  body.innerHTML = html;
}

/* --------------------- name badges on legacy device rows ----------------- */

async function annotateDeviceRows() {
  /* The classic dashboard lists devices by MAC in several places; this adds a
     small person badge next to each MAC once the assignment data is known. */
  const data = await histAssignment();
  if (!data) return;
  const names = {};
  (data.devices || []).forEach(device => {
    if (device.person) names[device.mac] = {name: device.person, certain: device.certain};
  });
  const macPattern = /\b([0-9a-f]{2}(:[0-9a-f]{2}){5})\b/i;
  document.querySelectorAll('td, .device-row, .device-card, li').forEach(node => {
    if (node.dataset.personBadge === 'done') return;
    const text = node.textContent || '';
    const match = text.match(macPattern);
    if (!match) return;
    const entry = names[match[1].toLowerCase()];
    node.dataset.personBadge = 'done';
    if (!entry) return;
    const badge = document.createElement('span');
    badge.className = 'hbadge' + (entry.certain ? ' certain' : '');
    badge.textContent = entry.name + (entry.certain ? ' ✓' : ' ?');
    node.appendChild(badge);
  });
}

window.addEventListener('DOMContentLoaded', () => {
  setTimeout(loadPersonPills, 1200);
  setTimeout(annotateDeviceRows, 2500);
  setInterval(annotateDeviceRows, 20000);
});
