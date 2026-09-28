"""Print the parental views for a simulated household.

Runs against a throwaway database in a temp directory, so it never touches the
real `src/database/enhanced_network_monitor.db` and never needs a LAN.  Useful
to see what the calendar, alerts, games and search views look like before the
collector has hours of real traffic behind it.

    .venv/bin/python scripts/demo_scenario.py            # or .venv-test/bin/python

The scenario: one child (Kid) plays 2 h of Roblox over the evening, opens an
adult site for 3 minutes, tries a proxy, and searches Google over plain HTTP;
an older child (Teen) plays Minecraft and chats on Discord.
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# must happen before src.main is imported
os.environ.setdefault('NETSCANNER_DB_URI',
                      'sqlite:///' + os.path.join(tempfile.mkdtemp(prefix='netscanner-demo-'),
                                                  'demo.db'))
os.environ.setdefault('NETSCANNER_INTEL_CAPTURE', '0')

from src.main import app  # noqa: E402

app.config['TESTING'] = True
KID = 'de:ad:be:ef:aa:01'
TEEN = 'aa:bb:cc:dd:ee:02'


def sequence(mac, host, dst_ip, src_port, minutes_ago, count, step=300, http=None):
    """Evidence for one visit: `count` samples `step` seconds apart."""
    now = datetime.utcnow()
    out = []
    for i in range(count):
        ts = now - timedelta(minutes=minutes_ago) + timedelta(seconds=step * i)
        if ts > now:
            break
        record = {'source': 'live', 'device_mac': mac, 'src_ip': '192.168.50.31',
                  'dst_ip': dst_ip, 'dst_port': 443, 'src_port': src_port,
                  'protocol': 'TCP', 'sni': None if http else host,
                  'observed_at': ts.isoformat(), 'bytes_down': 300000, 'packets': 30}
        if http:
            record.update({'http_host': http[0], 'http_path': http[1], 'dst_port': 80})
        out.append(record)
    return out


def main():
    client = app.test_client()

    # Sampling has to be quicker than the 90 s idle window, otherwise every
    # sample opens a new session - real captures arrive every few seconds.
    records = []
    records += sequence(KID, 'roblox.com', '128.116.1.1', 40100, 200, 120, step=60)
    records += sequence(KID, 'www.pornhub.com', '66.254.114.1', 40200, 60, 5, step=30)
    records += sequence(KID, 'super-unblock-proxy.xyz', '45.33.11.9', 40300, 50, 10, step=60)
    records += sequence(KID, None, '142.250.0.9', 40400, 40, 2, step=30,
                        http=('www.google.com', '/search?q=how+to+bypass+school+wifi'))
    records += sequence(KID, 'discord.com', '162.159.130.1', 40500, 30, 20, step=60)
    records += sequence(TEEN, 'minecraft.net', '13.107.1.1', 40600, 150, 45, step=60)
    records += sequence(TEEN, 'discord.com', '162.159.130.1', 40700, 120, 25, step=60)

    print(f"feeding {len(records)} evidence records …")
    print('  accepted:', client.post('/api/intel/observe', json=records).get_json()['accepted'])

    kid = client.post('/api/intel/people', json={'name': 'Kid', 'is_child': True}).get_json()['person']['id']
    teen = client.post('/api/intel/people', json={'name': 'Teen', 'is_child': True}).get_json()['person']['id']
    client.post(f'/api/intel/people/{kid}/bind', json={'mac': KID, 'locked': True})
    client.post(f'/api/intel/people/{teen}/bind', json={'mac': TEEN, 'locked': True})

    print('\n== alerts ==')
    summary = client.post('/api/intel/alerts/evaluate?hours=26').get_json()['summary']
    print(' ', summary)
    for row in client.get('/api/intel/alerts?hours=48').get_json()['alerts']:
        print(f"  [{row['severity']:<8}] {row['kind']:<15} {row['title'][:60]:<60} person={row['person']}")

    print('\n== per person (last 7 days) ==')
    for person in client.get('/api/intel/people/overview').get_json()['people']:
        print(f"  {person['name']}: today {person['today_human']}, week {person['week_human']}, "
              f"online {person['online_week_human']}, gaming {person['gaming_human']}, "
              f"alerts {person['alerts']} (critical {person['critical_alerts']})")
        print('     categories:', [(c['key'], c['human']) for c in person['top_categories']])
        print('     apps:      ', [(a['key'], a['human']) for a in person['top_apps']])
        print('     games:     ', [(g['key'], g['human']) for g in person['games']])

    print(f"\n== calendar: Kid × Roblox × 30 days ==")
    calendar = client.get(f'/api/intel/calendar?dimension=app&key=Roblox&range=month&person={kid}').get_json()
    print(' ', calendar['totals'])
    for day in calendar['days']:
        if day['seconds']:
            print(f"  {day['day']}  {day['human']:<12} {day['sessions']} session(s)")
    for session in calendar['sessions'][:3]:
        print(f"    session: active {session['human']}, span {session['span_human']}, "
              f"idle {session['idle_human']}, url {session['url']}")

    print('\n== range totals ==')
    for rng in ('day', 'week', 'month', '6months'):
        totals = client.get(f'/api/intel/usage?range={rng}&dimension=app&person={kid}').get_json()['totals']
        print(f"  {rng:<8} {totals['human']:<12} online {totals['online_human']:<12} "
              f"items {totals['distinct_keys']}")

    print('\n== games ==')
    games = client.get('/api/intel/usage?range=week&dimension=game').get_json()
    print(' ', games['totals']['human'], [(i['key'], i['human']) for i in games['items']])

    print('\n== search terms (plain HTTP only) ==')
    searches = client.get('/api/intel/searches?hours=168').get_json()
    print(' ', searches['note'])
    for row in searches['searches']:
        print(f"  {row['engine']:<14} “{row['term']}”  person={row['person']}")

    print('\n(throwaway database:', os.environ['NETSCANNER_DB_URI'], ')')


if __name__ == '__main__':
    main()
