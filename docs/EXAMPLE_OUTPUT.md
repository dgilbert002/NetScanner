# Example output — simulated household

Produced by `scripts/demo_scenario.py` on a throwaway database (no LAN needed):
one child plays Roblox for 2 h, opens an adult site, tries a proxy and searches
Google over plain HTTP; an older child plays Minecraft and chats on Discord.

```text
feeding 227 evidence records …
  accepted: 227

== alerts ==
  {'adult': 1, 'bypass': 1, 'gambling': 0, 'gaming': 0, 'late_night': 0, 'limits': 0, 'new_app': 2, 'raised': 4}
  [info    ] new_app         First use of Roblox                                          person=Kid
  [info    ] new_app         First use of Minecraft                                       person=Teen
  [warning ] unknown_bypass  Possible proxy/VPN tool: super-unblock-proxy.xyz             person=Kid
  [critical] adult_content   Adult site visited: pornhub.com                              person=Kid

== per person (last 7 days) ==
  Kid: today 2h 20m 30s, week 2h 20m 30s, online 2h 29m 30s, gaming 1h 59m 0s, alerts 3 (critical 1)
     categories: [('Gaming', '1h 59m 0s'), ('Messaging', '19m 0s'), ('Adult', '2m 0s'), ('Search', '30s'), ('Unknown', '0s')]
     apps:       [('Roblox', '1h 59m 0s'), ('Discord', '19m 0s'), ('Pornhub', '2m 0s'), ('Google', '30s')]
     games:      [('Roblox', '1h 59m 0s')]
  Teen: today 1h 8m 0s, week 1h 8m 0s, online 54m 0s, gaming 44m 0s, alerts 1 (critical 0)
     categories: [('Gaming', '44m 0s'), ('Messaging', '24m 0s')]
     apps:       [('Minecraft', '44m 0s'), ('Discord', '24m 0s')]
     games:      [('Minecraft', '44m 0s')]

== calendar: Kid × Roblox × 30 days ==
  {'active_days': 1, 'avg_per_active_day': 7140, 'best_day': '2026-09-28', 'hours': 1.98, 'human': '1h 59m 0s', 'seconds': 7140, 'sessions': 1}
  2026-09-28  1h 59m 0s    1 session(s)
    session: active 1h 59m 0s, span 1h 59m 0s, idle 0s, url https://roblox.com/

== range totals ==
  day      2h 20m 30s   online 2h 29m 30s   items 4
  week     2h 20m 30s   online 2h 29m 30s   items 4
  month    2h 20m 30s   online 2h 29m 30s   items 4
  6months  2h 20m 30s   online 2h 29m 30s   items 4

== games ==
  2h 43m 0s [('Roblox', '1h 59m 0s'), ('Minecraft', '44m 0s')]

== search terms (plain HTTP only) ==
  Search terms are only visible when the request was sent in clear text. HTTPS searches (essentially all of them today) cannot be read locally, by this or any other tool, without breaking TLS.
  google.com     “how to bypass school wifi”  person=Kid

(throwaway database: sqlite:////tmp/netscanner-demo-7r8ysuvy/demo.db )
```
