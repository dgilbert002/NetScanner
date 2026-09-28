/* Runtime verification for the two dashboards.
 *
 * Loads the real HTML with jsdom, inlines the external scripts, stubs fetch
 * with real API fixtures, then drives the UI (clicks the tabs) and reports any
 * JavaScript error and whether the key containers actually filled in.
 *
 * Usage: node /tmp/vt/verify.js <fixtures.json> <serverRoot>
 *   node --input-type=module ... (jsdom is ESM here)
 */

import fs from 'fs';
import path from 'path';
import {JSDOM, VirtualConsole} from 'jsdom';

const fixtures = JSON.parse(fs.readFileSync(process.argv[2] || '/tmp/vt/fixtures.json', 'utf8'));
const root = process.argv[3] || path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
const statics = path.join(root, 'src', 'static');

function inlineAssets(html) {
  // <script src="/static/x.js?v=3"> -> inline, so jsdom runs it
  html = html.replace(/<script[^>]*src="\/static\/([^"?]+)(\?[^"]*)?"[^>]*><\/script>/g,
    (match, file) => {
      const full = path.join(statics, file);
      if (!fs.existsSync(full)) return '<!-- missing ' + file + ' -->';
      return '<script>\n/* ' + file + ' */\n' + fs.readFileSync(full, 'utf8') + '\n</script>';
    });
  // stylesheets are irrelevant to behaviour
  html = html.replace(/<link[^>]*rel="stylesheet"[^>]*>/g, '');
  return html;
}

function makeFetch(log, missing) {
  return (url) => {
    const target = String(url);
    let key = target.replace(/^https?:\/\/[^/]+/, '');
    log.push(key);
    let payload = fixtures[key];
    if (payload === undefined) {
      // try without a query string, then with the query string sorted
      const noQuery = key.split('?')[0];
      payload = fixtures[noQuery];
    }
    if (payload === undefined) {
      missing.push(key);
      payload = {};
    }
    return Promise.resolve({
      ok: true, status: 200,
      json: () => Promise.resolve(payload),
      text: () => Promise.resolve(JSON.stringify(payload)),
    });
  };
}

async function check(label, file, drive) {
  const html = inlineAssets(fs.readFileSync(path.join(statics, file), 'utf8'));
  const errors = [];
  const log = [];
  const missing = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('jsdomError', error => errors.push('jsdomError: ' + error.message));
  virtualConsole.on('error', (...args) => errors.push('console.error: ' + args.join(' ')));
  virtualConsole.on('warn', () => {});
  virtualConsole.on('log', () => {});

  const dom = new JSDOM(html, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'http://localhost:5002/' + (file === 'index.html' ? '' : 'intel'),
    virtualConsole,
  });
  const {window} = dom;
  window.fetch = makeFetch(log, missing);
  window.prompt = () => null;
  window.confirm = () => false;
  window.alert = () => {};
  window.EventSource = class { constructor() {} close() {} addEventListener() {} };
  window.WebSocket = class { constructor() {} close() {} addEventListener() {} send() {} };

  await new Promise(resolve => setTimeout(resolve, 400));
  const report = {};
  try {
    await drive(window, report);
  } catch (error) {
    errors.push('drive: ' + error.message);
  }
  await new Promise(resolve => setTimeout(resolve, 600));
  report.errors = errors.concat(globalThis.__rejections || []);
  globalThis.__rejections = [];
  report.missingFixtures = Array.from(new Set(missing));
  report.requestCount = log.length;
  console.log('\n=== ' + label + ' (' + file + ')');
  console.log(JSON.stringify(report, null, 2));
  window.close();
  return report;
}

function textOf(window, selector) {
  const node = window.document.querySelector(selector);
  return node ? node.textContent.trim().slice(0, 120) : null;
}
function lengthOf(window, selector) {
  const node = window.document.querySelector(selector);
  return node ? node.innerHTML.length : -1;
}

let failures = 0;
// jsdom runs app scripts whose async failures surface as unhandled rejections;
// collect them instead of letting Node abort the whole run
process.on('unhandledRejection', reason => {
  globalThis.__rejections = globalThis.__rejections || [];
  globalThis.__rejections.push('unhandledRejection: ' + ((reason && reason.message) || reason));
});
process.on('uncaughtException', error => {
  globalThis.__rejections = globalThis.__rejections || [];
  globalThis.__rejections.push('uncaughtException: ' + error.message);
});

/* ------------------------------- /intel -------------------------------- */
const intelReport = await check('INTELLIGENCE DASHBOARD', 'intel.html', async (window, report) => {
  const tabs = Array.from(window.document.querySelectorAll('nav.tabs button, nav button'))
    .map(button => button.dataset.tab).filter(Boolean);
  report.tabs = tabs;
  report.hasAnalyticsTab = tabs.includes('analytics');

  // click every tab; a broken loader surfaces as an error here
  for (const tab of tabs) {
    const button = window.document.querySelector('[data-tab="' + tab + '"]');
    if (button) button.click();
    await new Promise(resolve => setTimeout(resolve, 180));
  }

  // the analytics tab is the one that used to kill the whole script
  const analytics = window.document.querySelector('[data-tab="analytics"]');
  if (analytics) analytics.click();
  await new Promise(resolve => setTimeout(resolve, 500));
  report.heatCells = window.document.querySelectorAll('.ana-cell').length;
  report.heatRows = window.document.querySelectorAll('.ana-heat-row').length;
  report.svgCharts = window.document.querySelectorAll('.ana-svg').length;
  report.topRows = window.document.querySelectorAll('#anaTop tbody tr').length;
  report.peopleRows = window.document.querySelectorAll('#anaPeople tbody tr').length;
  report.kpis = window.document.querySelectorAll('#anaKpis .kpi').length;
  report.heatText = textOf(window, '#anaHeat');
});

if (intelReport.errors.length || !intelReport.hasAnalyticsTab ||
    intelReport.heatCells < 24 || intelReport.svgCharts < 1) failures += 1;

/* ------------------------------ classic -------------------------------- */
const classicReport = await check('CLASSIC DASHBOARD', 'index.html', async (window, report) => {
  report.navItems = Array.from(window.document.querySelectorAll('.nav-link'))
    .map(link => (link.textContent || '').trim());
  report.hasHistorySection = !!window.document.getElementById('history-section');
  report.hasPeopleSection = !!window.document.getElementById('people-section');

  // open History the way a user would
  window.showSection('history');
  await new Promise(resolve => setTimeout(resolve, 700));
  report.historyDays = window.document.querySelectorAll('#historyBody .hday').length;
  report.historyEntries = window.document.querySelectorAll('#historyBody .hentry').length;
  report.historyTimes = Array.from(window.document.querySelectorAll('#historyBody .htime'))
    .slice(0, 3).map(node => node.textContent.trim());
  report.historyUrls = Array.from(window.document.querySelectorAll('#historyBody .hurl'))
    .slice(0, 2).map(node => node.textContent.trim());
  report.historyBodyLength = lengthOf(window, '#historyBody');

  // most-used tab
  const appsTab = window.document.querySelector('#historyBody [data-htab="apps"]');
  if (appsTab) appsTab.click();
  await new Promise(resolve => setTimeout(resolve, 250));
  report.appRows = window.document.querySelectorAll('#historyBody .happrow').length;

  // People section
  window.showSection('people');
  await new Promise(resolve => setTimeout(resolve, 600));
  report.peopleCards = window.document.querySelectorAll('#peopleHost .hcard').length;
  report.assignSelects = window.document.querySelectorAll('#peopleHost [data-assign]').length;
  report.personRows = window.document.querySelectorAll('#peopleHost .hprow').length;
  report.peopleHostLength = lengthOf(window, '#peopleHost');
  report.peopleText = textOf(window, '#peopleHost');
  report.pills = window.document.querySelectorAll('#person-pills .hpill').length;
});

if (classicReport.errors.length || !classicReport.hasHistorySection ||
    !classicReport.hasPeopleSection || classicReport.historyEntries < 1 ||
    classicReport.assignSelects < 1) failures += 1;

console.log('\n========================================');
console.log(failures ? 'VERIFICATION FAILED (' + failures + ' page(s))' : 'VERIFICATION PASSED');
process.exit(failures ? 1 : 0);
