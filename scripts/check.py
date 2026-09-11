#!/usr/bin/env python3
"""Static checks and live remote-list checks; not a Shadowrocket runtime test."""
import concurrent.futures
import ipaddress
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sections = {}
section = None
for raw in (ROOT / 'shadowrocket.conf').read_text().splitlines():
    line = raw.strip()
    if not line or line.startswith('#'):
        continue
    if line.startswith('['):
        section = line
        sections[section] = []
    else:
        sections[section].append(line)

groups = dict(line.split(' = ', 1) for line in sections['[Proxy Group]'])
builtins = {'DIRECT', 'REJECT', 'PROXY'}
edges = {}
for name, value in groups.items():
    choices = [s for s in value.split(',')[1:] if '=' not in s]
    assert all(c in groups or c in builtins for c in choices), (name, choices)
    edges[name] = [c for c in choices if c in groups]
    match = re.search(r'policy-select-name=([^,]+)', value)
    if match:
        assert match[1] in choices, name

def visit(name, parents):
    assert name not in parents, ('group cycle', name)
    for child in edges[name]:
        visit(child, parents | {name})

for name in groups:
    visit(name, set())

filters = {n: re.compile(v.split('policy-regex-filter=', 1)[1])
           for n, v in groups.items() if 'policy-regex-filter=' in v}
for name, pattern in filters.items():
    for label in ['剩余流量 100 GB', '到期日期 2027-01-01', '日本 更新订阅', '新加坡 官网', 'HK traffic remaining']:
        assert not pattern.search(label), (name, label)
for name, label in [('香港节点', 'HK-01'), ('日本节点', '日本 01'),
                    ('新加坡节点', 'SG-01'), ('美国节点', 'US-01'), ('台湾节点', '台湾 01')]:
    assert filters[name].search(label), (name, label)
assert not filters['新加坡节点'].search('新西兰 01')
assert not filters['日本节点'].search('美国 日常 01')

rules = [line.split(',') for line in sections['[Rule]']]
assert rules[-1] == ['FINAL', '默认代理']
assert sum(r[0] == 'FINAL' for r in rules) == 1
for rule in rules:
    policy = rule[1] if rule[0] == 'FINAL' else rule[2]
    assert policy in groups or policy in builtins, rule

urls = [r[1] for r in rules if r[0] in {'RULE-SET', 'DOMAIN-SET'}]
assert len(urls) == len(set(urls))
def fetch(url):
    result = subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                             '--max-time', '45', '--retry', '2', url],
                            capture_output=True, text=True, check=True)
    entries = []
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith(('#', '//')):
            continue
        if url.endswith('_Domain.list'):
            assert ',' not in line and ' ' not in line, (url, line)
            entries.append(['DOMAIN-SUFFIX' if line.startswith('.') else 'DOMAIN', line.lstrip('.')])
            continue
        parts = [p.strip() for p in line.split(',')]
        assert parts[0] in {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
                           'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP', 'URL-REGEX',
                           'USER-AGENT', 'PROCESS-NAME'}, (url, line)
        assert len(parts) >= 2 and parts[1], (url, line)
        if parts[0] in {'IP-CIDR', 'IP-CIDR6'}:
            ipaddress.ip_network(parts[1], strict=False)
        entries.append(parts)
    assert entries, url
    return url, entries

with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    remote = dict(pool.map(fetch, urls))

expanded = []
for rule in rules:
    if rule[0] in {'RULE-SET', 'DOMAIN-SET'}:
        expanded.extend((r[0], r[1], rule[2]) for r in remote[rule[1]])
    elif rule[0] != 'FINAL':
        expanded.append(tuple(rule[:3]))

def domain_policy(host):
    # Only domain rules: intentionally does not simulate DNS, GEOIP, modules or SNI.
    for kind, value, policy in expanded:
        if ((kind == 'DOMAIN' and host == value)
            or (kind == 'DOMAIN-SUFFIX' and (host == value or host.endswith('.' + value)))
            or (kind == 'DOMAIN-KEYWORD' and value in host)):
            return policy
    return None

expected = {'ad.doubleclick.net': '广告过滤', 'aax.amazon-adsystem.com': '广告过滤',
            'api.openai.com': 'AI', 'claude.ai': 'AI', 'gemini.google.com': 'AI',
            'copilot.microsoft.com': 'AI', 'github.com': 'GitHub',
            'www.youtube.com': 'Google', 'www.apple.com': 'Apple',
            'www.microsoft.com': 'Microsoft', 'www.baidu.com': 'DIRECT'}
for host, policy in expected.items():
    assert domain_policy(host) == policy, (host, policy, domain_policy(host))
for host in ['www.azabu-u.ac.jp', 'www.nichibenren.or.jp', 'www.jungle.cn']:
    assert domain_policy(host) != '广告过滤', host

print(f'PASS: group references/cycles/defaults, node filters, {len(urls)} remote lists, '
      f'{sum(map(len, remote.values()))} remote entries, {len(expected) + 3} domain cases')
print('Static validation only; import and connection tests on iOS remain necessary.')
