import { test, expect } from 'vitest';
import {
  scanSections, fieldLines, fieldRange, diagText, fixLabel, mapDiagnostics, fixChanges,
  allowedIPsFromText, gatewayCandidates, reverseZones,
  dnsValueContext, dnsCompletionOptions, dnsHoverAt, dnsHoverText,
} from './wireguard-lint.js';

const DOC = `[Interface]
PrivateKey = abc
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = k1
AllowedIPs = 192.168.1.0/24

[Peer]
PublicKey = k2
AllowedIPs = 10.5.0.9/32, 10.0.0.0/16
`;

const tr = (key, params = {}) => {
  const table = {
    'lint.dns_global_outside': 'global {servers}',
    'lint.cmp_tilde': 'split domain',
    'lint.cmp_tilde_info': 'tilde info',
    'lint.cmp_gateway': 'gateway',
    'lint.cmp_zone': 'zone',
    'lint.cmp_template': 'template',
    'lint.cmp_template_info': 'template info',
    'lint.hover_match': 'match {domain}',
    'lint.fix_remove_dns': 'Remove DNS',
  };
  const s = table[key];
  return s === undefined ? key : s.replace(/\{(\w+)\}/g, (_, n) => params[n] ?? '');
};

test('scanSections tags lines with section and peer index', () => {
  const lines = scanSections(DOC);
  expect(lines[0]).toMatchObject({ section: 'interface', header: true });
  expect(lines[3]).toMatchObject({ section: 'interface', header: false });
  expect(lines[5]).toMatchObject({ section: 'peer', peer: 0, header: true });
  expect(lines[11]).toMatchObject({ section: 'peer', peer: 1 });
});

test('fieldLines resolves Interface and indexed Peer fields', () => {
  expect(fieldLines(DOC, 'Interface.DNS').map((l) => l.text)).toEqual(['DNS = 1.1.1.1']);
  expect(fieldLines(DOC, 'Peer[0].AllowedIPs')[0].text).toBe('AllowedIPs = 192.168.1.0/24');
  expect(fieldLines(DOC, 'Peer[1].AllowedIPs')[0].text).toContain('10.5.0.9/32');
  expect(fieldLines(DOC, 'Interface.MTU')).toEqual([]);
  expect(fieldLines(DOC, 'nonsense')).toEqual([]);
});

test('fieldRange anchors to the key line, else the section header, else line 1', () => {
  const dns = fieldRange(DOC, 'Interface.DNS');
  expect(DOC.slice(dns.from, dns.to)).toBe('DNS = 1.1.1.1');
  const mtu = fieldRange(DOC, 'Interface.MTU'); // key absent
  expect(DOC.slice(mtu.from, mtu.to)).toBe('[Interface]');
  const peer = fieldRange(DOC, 'Peer[1].Endpoint');
  expect(DOC.slice(peer.from, peer.to)).toBe('[Peer]');
  expect(peer.from).toBe(DOC.lastIndexOf('[Peer]'));
  const none = fieldRange('', 'Interface.DNS');
  expect(none).toEqual({ from: 0, to: 0 });
});

test('mapDiagnostics maps severity, translated text and fix', () => {
  const fix = { label: 'Remove DNS line', action: 'remove_dns' };
  const out = mapDiagnostics(DOC, [
    { field: 'Interface.DNS', severity: 'warning', code: 'dns_global_outside', message: 'EN', args: { servers: '1.1.1.1' }, fix },
    { field: 'Interface.MTU', severity: 'info', code: 'unknown_code', message: 'English fallback' },
    { field: 'Interface.DNS', severity: 'bogus', code: 'dns_error', message: 'validator text' },
  ], tr);
  expect(out[0]).toMatchObject({ severity: 'warning', message: 'global 1.1.1.1', fix });
  expect(DOC.slice(out[0].from, out[0].to)).toBe('DNS = 1.1.1.1');
  expect(out[1]).toMatchObject({ severity: 'info', message: 'English fallback', fix: null });
  expect(out[2].severity).toBe('info');
  expect(out[2].message).toBe('validator text');
});

test('diagText and fixLabel fall back to English', () => {
  expect(diagText({ code: 'x', message: 'm' }, tr)).toBe('m');
  expect(diagText({ message: 'm' })).toBe('m');
  expect(fixLabel({ action: 'remove_dns', label: 'L' }, tr)).toBe('Remove DNS');
  expect(fixLabel({ action: 'append_dns', label: 'Add reverse zones' }, tr)).toBe('Add reverse zones');
});

test('fixChanges removes DNS lines', () => {
  const ch = fixChanges(DOC, { action: 'remove_dns' });
  expect(ch).toHaveLength(1);
  const next = DOC.slice(0, ch[0].from) + ch[0].insert + DOC.slice(ch[0].to);
  expect(next).not.toContain('DNS =');
  expect(next).toContain('Address = 10.0.0.2/32\n\n[Peer]');
  expect(fixChanges('[Interface]\nAddress = 1.2.3.4/32\n', { action: 'remove_dns' })).toBeNull();
  expect(fixChanges(DOC, null)).toBeNull();
});

test('fixChanges appends reverse zones to the DNS line', () => {
  const doc = '[Interface]\nDNS = 192.168.1.1, ~corp.lan  \nMTU = 1380\n';
  const ch = fixChanges(doc, { action: 'append_dns', value: '~1.168.192.in-addr.arpa' });
  const next = doc.slice(0, ch[0].from) + ch[0].insert + doc.slice(ch[0].to);
  expect(next).toBe('[Interface]\nDNS = 192.168.1.1, ~corp.lan, ~1.168.192.in-addr.arpa  \nMTU = 1380\n');
  expect(fixChanges(doc, { action: 'append_dns', value: '' })).toBeNull();
});

test('allowedIPsFromText collects entries from every peer', () => {
  expect(allowedIPsFromText(DOC)).toEqual(['192.168.1.0/24', '10.5.0.9/32', '10.0.0.0/16']);
  expect(allowedIPsFromText('[Interface]\nDNS = 1.1.1.1\n')).toEqual([]);
});

test('gatewayCandidates mirrors the Go helper', () => {
  expect(gatewayCandidates(['192.168.1.0/24', '10.5.0.9/32', '10.0.0.0/16', '0.0.0.0/0', '::/0', 'junk']))
    .toEqual(['192.168.1.1', '10.5.0.1', '10.0.0.1']);
});

test('reverseZones mirrors the Go helper', () => {
  expect(reverseZones(['192.168.1.0/24', '10.0.0.0/16', '10.0.0.0/8', '0.0.0.0/0', '10.5.0.9/32']))
    .toEqual(['1.168.192.in-addr.arpa', '0.10.in-addr.arpa', '10.in-addr.arpa', '0.5.10.in-addr.arpa']);
});

test('dnsValueContext finds the token after DNS =', () => {
  expect(dnsValueContext('DNS = ')).toMatchObject({ valueStart: 6, tokenStart: 6, token: '', valueEmpty: true });
  expect(dnsValueContext('DNS = 1.1.1.1, ~co')).toMatchObject({ tokenStart: 15, token: '~co', valueEmpty: false });
  expect(dnsValueContext('dns=')).toMatchObject({ valueStart: 4, tokenStart: 4, valueEmpty: true });
  expect(dnsValueContext('Address = 10.0.0.2/32')).toBeNull();
  expect(dnsValueContext('# DNS = 1')).toBeNull();
});

test('dnsCompletionOptions offers ~, gateway, zones and a template line', () => {
  const opts = dnsCompletionOptions(DOC, tr);
  const labels = opts.map((o) => o.label);
  expect(labels).toContain('~');
  expect(opts.find((o) => o.label === '~')).toMatchObject({ kind: 'tilde', info: 'tilde info' });
  expect(labels).toContain('192.168.1.1');
  expect(labels).toContain('~1.168.192.in-addr.arpa');
  const line = opts.find((o) => o.kind === 'line');
  expect(line.insert).toBe('192.168.1.1, ~corp.lan, ~1.168.192.in-addr.arpa');
});

test('dnsCompletionOptions: template only for an empty value, defaults without AllowedIPs', () => {
  expect(dnsCompletionOptions(DOC, tr, { valueEmpty: false }).some((o) => o.kind === 'line')).toBe(false);
  const bare = dnsCompletionOptions('[Interface]\nDNS = ', tr);
  expect(bare.find((o) => o.kind === 'line').insert).toBe('192.168.1.1, ~corp.lan, ~1.168.192.in-addr.arpa');
  expect(bare.map((o) => o.label)).toEqual(['~', bare[1].label]);
});

test('dnsHoverAt locates the DNS key and ~tokens', () => {
  const line = 'DNS = 192.168.1.1, ~corp.lan';
  expect(dnsHoverAt(line, 1)).toEqual({ kind: 'key', from: 0, to: 3 });
  const hit = dnsHoverAt(line, line.indexOf('~corp') + 2);
  expect(hit).toMatchObject({ kind: 'match', domain: 'corp.lan', from: 19, to: 28 });
  expect(dnsHoverAt(line, 8)).toBeNull(); // on the IP
  expect(dnsHoverAt('Address = 1.2.3.4/32', 2)).toBeNull();
  expect(dnsHoverAt('  dns = 1.1.1.1', 3)).toMatchObject({ kind: 'key', from: 2, to: 5 });
});

test('dnsHoverText covers Global/Split/None plus the caveats', () => {
  const key = dnsHoverText({ kind: 'key' }, tr).map((p) => p.strong || p.text);
  expect(key).toEqual([
    'lint.hover_global_title', 'lint.hover_split_title', 'lint.hover_none_title',
    'lint.hover_nxdomain', 'lint.hover_dig',
  ]);
  const match = dnsHoverText({ kind: 'match', domain: 'corp.lan' }, tr);
  expect(match[0].text).toBe('match corp.lan');
  expect(match).toHaveLength(3);
});

test('reverseZones never covers more than the route', () => {
  expect(reverseZones(['172.16.0.0/12', '100.64.0.0/10'])).toEqual([]);
  expect(reverseZones(['10.1.0.0/22'])).toEqual([
    '0.1.10.in-addr.arpa', '1.1.10.in-addr.arpa', '2.1.10.in-addr.arpa', '3.1.10.in-addr.arpa',
  ]);
});

test('dnsCompletionOptions is prefix-only and never fuzzy-matches typed servers', () => {
  const doc = '[Interface]\nDNS = \n[Peer]\nAllowedIPs = 192.168.1.0/24\n';
  const tr = (k) => k;
  expect(dnsCompletionOptions(doc, tr, { valueEmpty: false, token: '1.1.1.1' })).toEqual([]);
  expect(dnsCompletionOptions(doc, tr, { valueEmpty: false, token: '192.168.1.2' })).toEqual([]);
  expect(dnsCompletionOptions(doc, tr, { valueEmpty: false, token: '192.168' }).map((o) => o.label)).toEqual(['192.168.1.1']);
  expect(dnsCompletionOptions(doc, tr, { valueEmpty: false, token: '~1.' }).map((o) => o.label)).toEqual(['~1.168.192.in-addr.arpa']);
});
