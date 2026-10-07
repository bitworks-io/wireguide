import { test, expect } from 'vitest';
import { EditorState } from '@codemirror/state';
import { CompletionContext } from '@codemirror/autocomplete';
import { createWireguardCompletion } from './wireguard-lang.js';

const tr = (key) => key;
const complete = createWireguardCompletion(tr);

function run(doc, explicit = false) {
  const state = EditorState.create({ doc });
  return complete(new CompletionContext(state, doc.length, explicit));
}

const DOC = '[Interface]\nAddress = 10.0.0.2/32\nDNS = ';
const PEER = '\n[Peer]\nAllowedIPs = 192.168.1.0/24, 10.9.0.0/24\n';

test('DNS value completion fires with nothing typed and lists ~, gateway, zones, template', () => {
  const doc = DOC + PEER;
  const state = EditorState.create({ doc });
  const pos = doc.indexOf('DNS = ') + 6;
  const res = complete(new CompletionContext(state, pos, false));
  expect(res).not.toBeNull();
  expect(res.from).toBe(pos);
  const labels = res.options.map((o) => o.label);
  expect(labels).toContain('~');
  expect(labels).toContain('192.168.1.1');
  expect(labels).toContain('~1.168.192.in-addr.arpa');
  expect(labels).toContain('~0.9.10.in-addr.arpa');
  expect(labels.some((l) => l.includes(', ~corp.lan, '))).toBe(true);
  expect(res.options.find((o) => o.label === '~').info).toBe('lint.cmp_tilde_info');
});

test('DNS completion after a comma replaces only the current token', () => {
  const doc = '[Interface]\nDNS = 1.1.1.1, ~co';
  const res = run(doc);
  expect(res.from).toBe(doc.length - 3);
  expect(res.options.some((o) => o.kind === 'line')).toBe(false);
});

test('non-DNS lines keep the key completion', () => {
  const res = run('[Interface]\nAdd', true);
  expect(res.options.map((o) => o.label)).toContain('Address = ');
});
