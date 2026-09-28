/* ------------------------------------------------------------------------
   Classic dashboard: History timeline + People & device allocation.

   Two first-class sections of the mobile dashboard (nav: History, People),
   plus a full-screen sheet for phone use, plus person pills in the intel strip
   and person badges next to device MACs in the legacy tables.

   All data comes from the intelligence API, so the classic view shows exactly
   the same evidence as /intel - just shaped for a small screen.
   ------------------------------------------------------------------------ */

const hist = {
  person: '', range: 'week', open: {}, data: null, tab: 'timeline',
  assignment: null, top: null, mounted: []
};

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
function hBytes(bytes) {
  bytes = Number(bytes || 0);
  if (!bytes) return '0 MB';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i += 1; }
  return (bytes >= 100 || i === 0 ? Math.round(bytes) : bytes.toFixed(1)) + ' ' + units[i];
}
function hTime12(twentyFour) {
  const parts = String(twentyFour || '00:00').split(':');
  let hour = parseInt(parts[0], 10);
  const minute = parts[1] || '00';
  if (isNaN(hour)) return twentyFour || '';
  const suffix = hour >= 12 ? 'PM' : 'AM';
  hour = hour % 12; if (!hour) hour = 12;
  return hour + ':' + minute + ' ' + suffix;
}
function hDayLabel(day) {
  const date = new Date(day + 'T12:00:00');
  const today = new Date();
  const yesterday = new Date(Date.now() - 86400000);
  const same = (a, b) => a.toDateString() === b.toDateString();
  const stamp = date.toLocaleDateString(undefined, {weekday: 'short', day: 'numeric', month: 'long'});
  if (same(date, today)) return 'Today · ' + stamp;
  if (same(date, yesterday)) return 'Yesterday · ' + stamp;
  return stamp;
}
function hFavicon(entry) {
  /* A local, offline "favicon": initial in a coloured circle. */
  const name = entry.app || entry.domain || '?';
  const colours = ['#667eea', '#48bb78', '#f6ad55', '#fc8181', '#764ba2', '#3182ce', '#d69e2e'];
  let hash = 0;
  for (let i = 0; i < name.length; i += 1) hash = (hash * 31 + name.charCodeAt(i)) % 997;
  return '<span class="hfav" style="background:' + colours[hash % colours.length] + '">' +
    hEsc(name.trim().charAt(0).toUpperCase()) + '</span>';
}
function hGet(url) {
  return fetch(url, {headers: {'Accept': 'application/json'}})
    .then(response => response.json()).catch(() => null);
}

async function histAssignment(force) {
  if (hist.assignment && !force) return hist.assignment;
  hist.assignment = await hGet('/api/intel/assignment');
  return hist.assignment;
}

/* ------------------------------- rendering ------------------------------ */

function histParams(extra) {
  const params = {range: hist.range};
  if (hist.person) params.person = hist.person;
  return Object.assign(params, extra || {});
}
function histQuery(params) {
  return Object.keys(params)
    .filter(key => params[key] !== '' && params[key] !== null && params[key] !== undefined)
    .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(params[key])).join('&');
}

function histShellHtml(prefix) {
  return [
    '<div class="hfilter">',
    '  <div class="hpeople" data-hpeople="' + prefix + '"></div>',
    '  <div class="hranges" data-hranges="' + prefix + '">',
    '    <button data-range="day">Today</button>',
    '    <button data-range="week" class="active">7 days</button>',
    '    <button data-range="month">30 days</button>',
    '    <button data-range="quarter">90 days</button>',
    '  </div>',
    '</div>',
    '<div class="htabs">',
    '  <button data-htab="timeline" class="active">Timeline</button>',
    '  <button data-htab="apps">Most used</button>',
    '  <button data-htab="sites">Sites</button>',
    '  <button data-htab="data">Data</button>',
    '</div>',
    '<div class="hbody" data-hbody="' + prefix + '"><div class="hempty">loading…</div></div>'
  ].join('');
}

function mountHistory(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = histShellHtml(containerId);
  if (hist.mounted.indexOf(containerId) === -1) hist.mounted.push(containerId);
  container.querySelectorAll('[data-range]').forEach(button => {
    button.onclick = () => {
      hist.range = button.dataset.range;
      container.querySelectorAll('[data-range]').forEach(other =>
        other.classList.toggle('active', other === button));
      loadHistory();
    };
  });
  container.querySelectorAll('[data-htab]').forEach(button => {
    button.onclick = () => {
      hist.tab = button.dataset.htab;
      container.querySelectorAll('[data-htab]').forEach(other =>
        other.classList.toggle('active', other === button));
      renderHistoryAll();
    };
  });
}

async function loadHistory() {
  const data = await histAssignment();
  const people = (data && data.people) || [];
  hist.mounted.forEach(id => {
    const container = document.getElementById(id);
    if (!container) return;
    const root = container.querySelector('[data-hpeople]');
    if (!root) return;
    root.innerHTML = '<button data-person="" class="' + (hist.person ? '' : 'active') +
      '">Everyone</button>' + people.map(person =>
        '<button data-person="' + person.id + '" class="' +
        (String(hist.person) === String(person.id) ? 'active' : '') + '">' +
        '<span class="dot" style="background:' + hEsc(person.color) + '"></span>' +
        hEsc(person.display_name || person.name) + '</button>').join('');
    root.querySelectorAll('[data-person]').forEach(button => {
      button.onclick = () => {
        hist.person = button.dataset.person;
        loadHistory();
      };
    });
  });

  const params = histQuery(histParams());
  const [daylog, top] = await Promise.all([
    hGet('/api/intel/daylog?' + params),
    hGet('/api/intel/top?' + histQuery(histParams({dimension: 'app', order: 'seconds', limit: 30})))
  ]);
  hist.data = daylog;
  hist.top = top;
  renderHistoryAll();
}

function renderHistoryAll() {
  hist.mounted.forEach(id => {
    const container = document.getElementById(id);
    if (!container) return;
    const body = container.querySelector('[data-hbody]');
    if (!body) return;
    if (hist.tab === 'apps' || hist.tab === 'sites') renderHistogram(body, hist.tab);
    else if (hist.tab === 'data') renderDataView(body);
    else renderHistoryTimeline(body);
  });
}

function renderHistoryTimeline(body) {
  const payload = hist.data;
  if (!payload || !payload.days || !payload.days.length) {
    body.innerHTML = '<div class="hempty">Nothing recorded in this range yet.<br>' +
      '<span class="hsub">Activity appears here as the collector sees traffic.</span></div>';
    return;
  }
  let html = '<div class="hsummary">' + hEsc(payload.totals.human) + ' online · ' +
    payload.totals.visits + ' visits · ' + payload.totals.days + ' day(s)' +
    (payload.person ? ' · ' + hEsc(payload.person.name) : ' · everyone') + '</div>';
  payload.days.forEach(day => {
    const open = hist.open[day.day] !== false;
    html += '<div class="hday' + (open ? ' open' : '') + '">';
    html += '<button class="hdayhead" data-day="' + day.day + '">' +
      '<span class="hdaylabel">' + hEsc(hDayLabel(day.day)) + '</span>' +
      '<span class="hdaymeta">' + hEsc(day.human) + ' · ' + day.visit_count +
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
          '<span class="hurl">' + hEsc((entry.url || entry.domain || 'unknown')
            .replace(/^https?:\/\//, '')) + '</span>' +
          '<span class="hsub">' +
          hEsc([entry.category, entry.app].filter(Boolean).join(' · ') || 'Unclassified') +
          ' · ' + hEsc(entry.human) +
          (entry.person ? ' · <b>' + hEsc(entry.person) + '</b>' : ' <span class="hsub">unassigned</span>') +
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
      const day = head.dataset.day;
      hist.open[day] = !(hist.open[day] !== false);
      renderHistoryAll();
    };
  });
}

function renderHistogram(body, kind) {
  const payload = hist.top;
  const items = (payload && payload.items) || [];
  if (!items.length) {
    body.innerHTML = '<div class="hempty">No app-level activity in this range.</div>';
    return;
  }
  const seconds = (payload.totals && payload.totals.seconds) || 1;
  const byVisits = kind === 'sites';
  const sorted = byVisits ? items.slice().sort((a, b) => b.visits - a.visits) : items;
  let html = '<div class="hsummary">' + (byVisits ? 'Most visited apps' : 'Time per app') +
    ' · ' + hEsc(hSecs(seconds)) + ' total</div><div class="happlist">';
  sorted.forEach(item => {
    const share = Math.round(((item.seconds || 0) / seconds) * 100);
    html += '<div class="happrow"><div class="happtop"><span>' +
      '<b>' + hEsc(item.label || item.key) + '</b>' +
      '<span class="hsub">' + hEsc(item.category || '') + '</span></span>' +
      '<span class="happtime">' + hEsc(item.human) +
      (byVisits ? ' · ' + item.visits + ' visits' : ' · ' + share + '%') + '</span></div>' +
      '<div class="hbar"><i style="width:' + Math.max(2, share) +
      '%"></i></div></div>';
  });
  body.innerHTML = html + '</div>';
}

function renderDataView(body) {
  const payload = hist.data;
  if (!payload || !payload.days || !payload.days.length) {
    body.innerHTML = '<div class="hempty">No traffic in this range.</div>';
    return;
  }
  const max = Math.max(1, ...payload.days.map(day => day.bytes || 1));
  let html = '<div class="hsummary">Data volume per day</div><div class="happlist">';
  payload.days.forEach(day => {
    const share = Math.round(((day.bytes || 0) / max) * 100);
    html += '<div class="happrow"><div class="happtop"><span><b>' +
      hEsc(hDayLabel(day.day).split(' · ')[0]) + '</b><span class="hsub">' +
      hEsc(day.day) + '</span></span><span class="happtime">' +
      hBytes(day.bytes) + ' · ' + hEsc(day.human) + '</span></div>' +
      '<div class="hbar"><i style="width:' + Math.max(2, share) + '%"></i></div></div>';
  });
  body.innerHTML = html + '</div>';
}

/* ------------------------- people & device allocation ------------------- */

async function loadPeoplePanel(force) {
  const host = document.getElementById('peopleHost');
  if (!host) return;
  if (force) hist.assignment = null;
  const data = await histAssignment(force);
  if (!data) {
    host.innerHTML = '<div class="hempty">Could not load people and devices.</div>';
    return;
  }
  let html = '';
  html += '<div class="hsummary">' + data.assigned_count + ' of ' + data.device_count +
    ' devices allocated to a person</div>';

  html += '<div class="hcard"><h3>People</h3>';
  if (!data.people.length) {
    html += '<div class="hempty">No people yet. Add one below.</div>';
  } else {
    data.people.forEach(person => {
      html += '<div class="hprow">' +
        '<span class="hbullet" style="background:' + hEsc(person.color) + '"></span>' +
        '<div class="hpinfo"><b>' + hEsc(person.display_name || person.name) + '</b>' +
        (person.is_child ? ' <span class="htag">child</span>' : '') +
        '<div class="hsub">' + (person.macs.length
          ? person.macs.map(mac => {
              const device = (data.devices || []).find(item => item.mac === mac) || {};
              return hEsc(device.name && device.name !== mac ? device.name + ' · ' + mac : mac);
            }).join('<br>')
          : 'no devices allocated') + '</div></div>' +
        '<div class="hpactions">' +
        '<button class="hbtn" data-rename="' + person.id + '" data-name="' +
        hEsc(person.display_name || person.name) + '">rename</button>' +
        '<button class="hbtn danger" data-delete="' + person.id + '" data-name="' +
        hEsc(person.display_name || person.name) + '">delete</button>' +
        '</div></div>';
    });
  }
  html += '<div class="hprow"><input id="hNewPerson" placeholder="Add a person (e.g. Sam)">' +
    '<label class="hsub" style="display:flex;align-items:center;gap:6px">' +
    '<input type="checkbox" id="hNewChild" checked> child</label>' +
    '<button class="hbtn primary" id="hAddPerson">add</button></div></div>';

  html += '<div class="hcard"><h3>Devices</h3>';
  (data.devices || []).forEach(device => {
    const options = ['<option value="">— unassigned —</option>'].concat(
      data.people.map(person => '<option value="' + person.id + '"' +
        (String(device.person_id) === String(person.id) ? ' selected' : '') + '>' +
        hEsc(person.display_name || person.name) + '</option>')).join('');
    html += '<div class="hprow">' +
      '<div class="hpinfo"><b>' + hEsc(device.name) + '</b>' +
      '<div class="hsub mono">' + hEsc(device.mac) + '</div>' +
      '<div class="hsub">' + [
        device.vendor && device.vendor !== 'Unknown' ? hEsc(device.vendor) : null,
        device.is_randomized ? '<span class="htag warn">rotating MAC</span>' : null,
        device.online_today_human ? 'online today ' + hEsc(device.online_today_human) : null,
      ].filter(Boolean).join(' · ') + '</div>' +
      (device.suggestion && !device.person
        ? '<div class="hsub">possible match: ' + hEsc(device.suggestion.person) + ' (' +
          Math.round((device.suggestion.probability || 0) * 100) + '%)</div>'
        : '') + '</div>' +
      '<div class="hpactions">' +
      '<select data-assign="' + hEsc(device.mac) + '">' + options + '</select>' +
      (device.person ? '<span class="htag' + (device.certain ? ' ok' : '') + '">' +
        (device.certain ? 'confirmed' : 'probable') + '</span>' : '') +
      (device.suggestion && !device.person
        ? '<button class="hbtn" data-accept="' + hEsc(device.mac) + '" data-person="' +
          device.suggestion.person_id + '">accept suggestion</button>'
        : '') + '</div></div>';
  });
  html += '</div>';
  html += '<div class="hcard"><h3>How allocation works</h3><div class="hsub">' +
    'Name a person, then pick them for each device. A confirmed allocation is remembered, ' +
    'so reports stay attributed to that person even when the phone rotates its private MAC. ' +
    'Unassigned devices are still tracked — they are simply labelled by device instead of by name.' +
    '</div></div>';
  host.innerHTML = html;

  host.querySelectorAll('[data-assign]').forEach(select => {
    select.onchange = async () => {
      const mac = select.dataset.assign;
      const personId = select.value;
      select.disabled = true;
      if (personId) {
        await fetch('/api/intel/people/' + personId + '/bind',
          {method: 'POST', headers: {'Content-Type': 'application/json'},
           body: JSON.stringify({mac: mac, locked: true})}).catch(() => null);
      } else {
        const current = (data.devices || []).find(device => device.mac === mac) || {};
        if (current.person_id) {
          await fetch('/api/intel/people/' + current.person_id + '/unbind',
            {method: 'POST', headers: {'Content-Type': 'application/json'},
             body: JSON.stringify({mac: mac})}).catch(() => null);
        }
      }
      await loadPeoplePanel(true);
      await loadHistory();
    };
  });
  host.querySelectorAll('[data-accept]').forEach(button => {
    button.onclick = async () => {
      await fetch('/api/intel/people/' + button.dataset.person + '/bind',
        {method: 'POST', headers: {'Content-Type': 'application/json'},
         body: JSON.stringify({mac: button.dataset.accept, locked: true})}).catch(() => null);
      await loadPeoplePanel(true);
      await loadHistory();
    };
  });
  host.querySelectorAll('[data-rename]').forEach(button => {
    button.onclick = async () => {
      const name = prompt('Name for this person', button.dataset.name);
      if (!name) return;
      await fetch('/api/intel/people/' + button.dataset.rename,
        {method: 'PATCH', headers: {'Content-Type': 'application/json'},
         body: JSON.stringify({display_name: name, name: name})}).catch(() => null);
      await loadPeoplePanel(true);
    };
  });
  host.querySelectorAll('[data-delete]').forEach(button => {
    button.onclick = async () => {
      if (!confirm('Delete ' + button.dataset.name + '? Their devices are released, ' +
                   'the recorded history stays in the database.')) return;
      await fetch('/api/intel/people/' + button.dataset.delete,
        {method: 'DELETE'}).catch(() => null);
      await loadPeoplePanel(true);
      await loadHistory();
    };
  });
  const add = document.getElementById('hAddPerson');
  if (add) {
    add.onclick = async () => {
      const input = document.getElementById('hNewPerson');
      const name = input ? input.value.trim() : '';
      if (!name) return;
      await fetch('/api/intel/people', {method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name: name, is_child: document.getElementById('hNewChild').checked})})
        .catch(() => null);
      await loadPeoplePanel(true);
      await loadHistory();
    };
  }
}

/* --------------------- person pills + device badges -------------------- */

async function loadPersonPills() {
  const strip = document.getElementById('intel-strip');
  if (!strip) return;
  const data = await histAssignment();
  if (!data || !data.people || !data.people.length) return;
  let row = document.getElementById('person-pills');
  if (!row) {
    row = document.createElement('div');
    row.className = 'isrow';
    row.id = 'person-pills';
    const anchor = strip.querySelector('.isrow:last-child');
    if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(row, anchor.nextSibling);
    else strip.appendChild(row);
  }
  row.innerHTML = '<span class="islabel">people</span>' +
    data.people.map(person =>
      '<button class="hpill" data-person="' + person.id + '">' +
      '<span class="dot" style="background:' + hEsc(person.color) + '"></span>' +
      hEsc(person.display_name || person.name) +
      '<span class="hcount">' + person.macs.length + ' device' +
      (person.macs.length === 1 ? '' : 's') + '</span></button>').join('') +
    '<button class="hpill ghost" data-history="1">History timeline →</button>';
  row.querySelectorAll('[data-person]').forEach(button => {
    button.onclick = () => {
      hist.person = button.dataset.person;
      if (typeof showSection === 'function') showSection('history');
      loadHistory();
    };
  });
  const open = row.querySelector('[data-history]');
  if (open) open.onclick = () => {
    hist.person = '';
    if (typeof showSection === 'function') showSection('history');
    loadHistory();
  };
}

async function annotateDeviceRows() {
  const data = await histAssignment();
  if (!data) return;
  const names = {};
  (data.devices || []).forEach(device => {
    if (device.person) names[device.mac] = {name: device.person, certain: device.certain};
  });
  const pattern = /\b([0-9a-f]{2}(:[0-9a-f]{2}){5})\b/i;
  document.querySelectorAll('td, .device-row, .device-card, li').forEach(node => {
    if (node.dataset.personBadge === 'done') return;
    const text = node.textContent || '';
    const match = text.match(pattern);
    if (!match) return;
    node.dataset.personBadge = 'done';
    const entry = names[match[1].toLowerCase()];
    if (!entry) return;
    const badge = document.createElement('span');
    badge.className = 'hbadge' + (entry.certain ? ' certain' : '');
    badge.textContent = entry.name + (entry.certain ? ' ✓' : ' ?');
    node.appendChild(badge);
  });
}

/* ------------------------------- wiring -------------------------------- */

async function refreshClassic() {
  await loadPersonPills();
  await annotateDeviceRows();
  const badge = document.getElementById('people-badge');
  if (badge) {
    const data = hist.assignment;
    if (data && data.unassigned && data.unassigned.length) {
      badge.style.display = '';
      badge.textContent = data.unassigned.length;
    } else {
      badge.style.display = 'none';
    }
  }
}

async function showHistorySection() {
  mountHistory('historyBody');
  await loadHistory();
}
async function showPeopleSection() {
  await loadPeoplePanel();
}

window.histShowSection = function (section) {
  if (section === 'history') showHistorySection();
  if (section === 'people') showPeopleSection();
  if (section === 'home') refreshClassic();
};

window.addEventListener('DOMContentLoaded', () => {
  setTimeout(refreshClassic, 1200);
  setTimeout(annotateDeviceRows, 2600);
  setInterval(annotateDeviceRows, 20000);
  setInterval(refreshClassic, 20000);
});
