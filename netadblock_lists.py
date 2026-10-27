#!/usr/bin/env python3
"""NetadBlock list tooling (Python 3 standard library only).

  list      show the lists available in the registry and which ones are selected
  fetch     sync the upstream registry (optional), download the selected lists from
            their original sources and validate them        -> OUT/lists/*, OUT/manifest.json
  registry  generate a self-contained assets.json registry  -> OUT/assets.json
  bundle    copy fetched lists + registry into a built extension directory

OUT is meant to be committed to your own git repository: a source that fails keeps its
previous copy (and the run still succeeds, with a warning) until the copy is older than
"max_stale_days", at which point the run fails so you get notified.
Lists named in config "freeze" are never downloaded: the committed copy is kept as is.

The generated registry never points at uBlock Origin's servers: every list gets
[your mirror URL (optional), bundled local path] and nothing else.
"""
import argparse
import copy
import datetime
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
UA = 'NetadBlock-lists/1.0 (personal use)'
STUB_MARK = '! netadblock-stub'

# Entries that are not filter lists but are always needed.
INFRA = ('ublock-badlists', 'public_suffix_list.dat')

# Minimum number of non-comment lines for a download to be accepted.
MIN_RULES = {'ublock-badlists': 1}

# id -> (license, url). Source: uBO wiki "Filter list licenses" (checked Oct 2026,
# the page itself was last edited Apr 2024) and each project's own pages.
LICENSES = {
    'ublock-filters':     ('GPL-3.0', 'https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE'),
    'ublock-badware':     ('GPL-3.0', 'https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE'),
    'ublock-privacy':     ('GPL-3.0', 'https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE'),
    'ublock-unbreak':     ('GPL-3.0', 'https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE'),
    'ublock-quick-fixes': ('GPL-3.0', 'https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE'),
    'ublock-badlists':    ('GPL-3.0', 'https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE'),
    'easylist':           ('GPL-3.0 or CC BY-SA 3.0', 'https://easylist.to/pages/licence.html'),
    'easyprivacy':        ('GPL-3.0 or CC BY-SA 3.0', 'https://easylist.to/pages/licence.html'),
    'urlhaus-1':          ('CC0-1.0', 'https://gitlab.com/malware-filter/urlhaus-filter/-/blob/main/LICENSE.md'),
    'plowe-0':            ('McRae GPL - NON-COMMERCIAL use only', 'https://pgl.yoyo.org/license/'),
    'IDN-0':              ('GPL-3.0 or CC BY-SA 3.0', 'https://github.com/ABPindo/indonesianadblockrules/blob/master/LICENSE'),
    'public_suffix_list.dat': ('MPL-2.0', 'https://publicsuffix.org/list/'),
}


def log(msg):
    print(msg, flush=True)


def warn(msg):
    print(('::warning::' if os.environ.get('GITHUB_ACTIONS') else 'WARNING ') + msg, flush=True)


def age_days(ts):
    t = datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    return (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() / 86400


def load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)
        f.write('\n')


def urls_of(entry, field='contentURL'):
    v = entry.get(field) or []
    return [v] if isinstance(v, str) else list(v)


def is_remote(u):
    return u.startswith(('http://', 'https://'))


def local_paths(entry):
    return [u for u in urls_of(entry) if not is_remote(u)]


def http_get(url, timeout=60, retries=3):
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001 - report whatever went wrong
            last = e
            if not url.startswith('file:'):
                time.sleep(2 ** i)
    raise RuntimeError(f'{last}')


def validate(key, data, prev_bytes=None):
    """Return None if the download looks sane, else a short reason."""
    if len(data) < 200:
        return f'too small ({len(data)} bytes)'
    text = data.decode('utf-8', 'replace')
    head = text[:400].lstrip().lower()
    if head.startswith(('<!doctype html', '<html')):
        return 'looks like an HTML page, not a list'
    if key == 'public_suffix_list.dat':
        return None if '===BEGIN ICANN DOMAINS===' in text else 'not a public suffix list'
    rules = sum(1 for ln in text.splitlines()
                if ln.strip() and not ln.lstrip().startswith(('!', '#', '[')))
    need = MIN_RULES.get(key, 20)
    if rules < need:
        return f'only {rules} rules (need >= {need})'
    if prev_bytes and len(data) < prev_bytes * 0.5:
        return f'shrank from {prev_bytes} to {len(data)} bytes (truncated?)'
    return None


def list_file(key):
    return 'lists/public_suffix_list.dat' if key == 'public_suffix_list.dat' else f'lists/{key}.txt'


def write_licenses(out, items):
    lines = [
        '# Filter list sources and licenses',
        '',
        'These lists are third-party works bundled/mirrored by NetadBlock (personal build).',
        'Each keeps its own license. Lists marked non-commercial must not be used commercially.',
        '',
        '| id | title | license | origin | fetched (UTC) | sha256 (first 12) |',
        '|---|---|---|---|---|---|',
    ]
    for key, it in sorted(items.items()):
        lines.append(f"| {key} | {it['title']} | {it['license']} ({it['license_url']}) | "
                     f"{it['source_url']} | {it['fetched_at']} | {it['sha256'][:12]} |")
    lines.append('')
    with open(os.path.join(out, 'LICENSES-lists.md'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def snapshot_path(a, cfg):
    return a.registry or os.path.join(ROOT, cfg['registry'])


def validate_registry(reg, required):
    if not isinstance(reg, dict) or 'assets.json' not in reg:
        return 'not a uBO registry'
    if any(not isinstance(v, dict) for v in reg.values()):
        return 'malformed entries'
    if sum(1 for v in reg.values() if v.get('content') == 'filters') < 20:
        return 'too few filter lists'
    missing = [k for k in required if k not in reg]
    return f'selected lists missing upstream: {missing}' if missing else None


def sync_registry(snap, cfg, out):
    """Fresh upstream registry > last synced copy (kept in OUT) > bundled snapshot."""
    required = list(cfg['lists']) + list(INFRA)
    synced = os.path.join(out, 'source-registry.json')
    entry = snap.get('assets.json', {})
    urls = list(cfg.get('registry_sources', []))
    urls += [u for u in urls_of(entry) if is_remote(u)]
    urls += [u for u in urls_of(entry, 'cdnURLs') if is_remote(u)]
    for u in urls:
        try:
            reg = json.loads(http_get(u).decode('utf-8'))
        except Exception as e:  # noqa: BLE001
            log(f'  registry: {u} failed ({e})')
            continue
        why = validate_registry(reg, required)
        if why:
            log(f'  registry: {u} rejected ({why})')
            continue
        save_json(synced, reg)
        log(f'  registry: synced from {u} ({len(reg)} entries)')
        return reg, 'upstream sync'
    if os.path.exists(synced):
        warn('registry sync failed; using the previously synced copy')
        return load_json(synced), 'previous sync'
    warn('registry sync failed; using the bundled snapshot')
    return snap, 'snapshot'


def working_registry(a, cfg, out):
    """Registry used by the offline commands (list, registry): the synced copy if any."""
    synced = os.path.join(out, 'source-registry.json')
    if cfg.get('sync_registry') and os.path.exists(synced):
        return load_json(synced)
    return load_json(snapshot_path(a, cfg))


def cmd_list(a):
    cfg = load_json(a.config)
    reg = working_registry(a, cfg, a.out)
    selected = set(cfg['lists'])
    rows = []
    for key, e in reg.items():
        if e.get('content') != 'filters':
            continue
        rows.append((key, 'YES' if key in selected else '-', 'on' if not e.get('off') else 'off',
                     LICENSES.get(key, ('?',))[0][:24], e.get('title', key)))
    log(f"{'id':28} {'chosen':6} {'default':7} {'license (known)':24} title")
    for r in sorted(rows, key=lambda r: (r[1] != 'YES', r[0].lower())):
        log(f'{r[0]:28} {r[1]:6} {r[2]:7} {r[3]:24} {r[4][:60]}')
    log(f'{len(rows)} lists in registry, {len(selected)} chosen. License "?" = not verified by this tool: check before mirroring publicly.')
    return 0


def cmd_fetch(a):
    cfg = load_json(a.config)
    out = a.out
    os.makedirs(out, exist_ok=True)
    snap = load_json(snapshot_path(a, cfg))
    if cfg.get('sync_registry'):
        reg, origin = sync_registry(snap, cfg, out)
    else:
        reg, origin = snap, 'snapshot (sync disabled)'
    log(f'registry source: {origin}')
    os.makedirs(os.path.join(out, 'lists'), exist_ok=True)
    mpath = os.path.join(out, 'manifest.json')
    prev = load_json(mpath)['items'] if os.path.exists(mpath) else {}
    items, problems, warnings = {}, [], []
    max_stale = float(cfg.get('max_stale_days', 7))
    frozen = set(cfg.get('freeze', []))
    for key in list(cfg['lists']) + list(INFRA):
        entry = reg.get(key)
        if entry is None:
            problems.append(f'{key}: not found in registry')
            continue
        # Order: "sources" overrides -> registry URLs (what uBO itself uses) -> registry CDN URLs
        # -> "fallback_sources" (e.g. the original sites, used only if all of the above fail).
        urls = list(cfg.get('sources', {}).get(key, []))
        urls += [u for u in urls_of(entry) if is_remote(u)]
        urls += [u for u in urls_of(entry, 'cdnURLs') if is_remote(u)]
        urls += list(cfg.get('fallback_sources', {}).get(key, []))
        seen = set()
        urls = [u for u in urls if not (u in seen or seen.add(u))]
        old = prev.get(key)
        if key in frozen and old and os.path.exists(os.path.join(out, list_file(key))):
            items[key] = old
            log(f'  {key}: FROZEN, keeping the committed copy (not downloading)')
            continue
        data, used = None, None
        for u in urls:
            try:
                d = http_get(u)
            except RuntimeError as e:
                log(f'  {key}: {u} failed ({e})')
                continue
            why = validate(key, d, old['bytes'] if old else None)
            if why:
                log(f'  {key}: {u} rejected ({why})')
                continue
            data, used = d, u
            break
        dest = os.path.join(out, list_file(key))
        if data is None:
            if old and os.path.exists(dest):
                items[key] = old
                age = age_days(old['fetched_at'])
                if age > max_stale:
                    problems.append(f'{key}: all sources failed and the kept copy is {age:.1f} days old (limit {max_stale:g})')
                else:
                    warnings.append(f'{key}: all sources failed, keeping previous copy ({age:.1f} days old)')
            else:
                problems.append(f'{key}: all sources failed and no previous copy')
            continue
        tmp = dest + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(data)
        os.replace(tmp, dest)
        lic, lic_url = LICENSES.get(key, ('unknown - read the list header', ''))
        items[key] = {
            'title': entry.get('title', key),
            'file': list_file(key),
            'source_url': used,
            'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'fetched_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'license': lic,
            'license_url': lic_url,
        }
        log(f'  {key}: ok ({len(data)} bytes) <- {used}')
    save_json(mpath, {'items': items})
    write_licenses(out, items)
    for w in warnings:
        warn(w)
    for p in problems:
        log(('::error::' if os.environ.get('GITHUB_ACTIONS') else 'PROBLEM ') + p)
    log(f'fetch: {len(items)} item(s) in {out}, {len(warnings)} warning(s), {len(problems)} problem(s)')
    return 1 if problems else 0


def strip_upstream(entry):
    entry.pop('cdnURLs', None)
    entry.pop('patchURLs', None)


def build_registry(src, cfg, mirror):
    selected = set(cfg['lists'])
    out = {}
    for key, e in src.items():
        e = copy.deepcopy(e)
        if key == 'assets.json':
            e['contentURL'] = ([f'{mirror}/assets.json'] if mirror else []) + ['assets/assets.json']
            strip_upstream(e)
        elif key in INFRA:
            local = local_paths(e)
            e['contentURL'] = ([f'{mirror}/{list_file(key)}'] if mirror else []) + local
            strip_upstream(e)
        elif e.get('content') == 'filters':
            if key not in selected:
                if cfg.get('others', 'remove') == 'keep':
                    out[key] = e
                continue
            local = local_paths(e) or [f'assets/lists/{key}.txt']
            e['contentURL'] = ([f'{mirror}/lists/{key}.txt'] if mirror else []) + local
            strip_upstream(e)
        out[key] = e
    return out


def cmd_registry(a):
    cfg = load_json(a.config)
    src = working_registry(a, cfg, a.out)
    mirror = (a.mirror or cfg.get('mirror_base_url') or '').rstrip('/')
    reg = build_registry(src, cfg, mirror)
    path = os.path.join(a.out, 'assets.json')
    save_json(path, reg)
    remote = sorted({re.match(r'https?://([^/]+)', u).group(1)
                     for e in reg.values() for f in ('contentURL', 'cdnURLs', 'patchURLs')
                     for u in urls_of(e, f) if is_remote(u)})
    log(f'registry: {len(reg)} entries -> {path}')
    log(f'registry: mirror = {mirror or "(none: lists are bundled only, never downloaded)"}')
    log(f'registry: remote hosts referenced = {remote or "none"}')
    return 0


def cmd_bundle(a):
    manifest = load_json(os.path.join(a.lists, 'manifest.json'))['items']
    reg = load_json(os.path.join(a.lists, 'assets.json'))
    dest = a.build
    assets_dir = os.path.join(dest, 'assets')
    shutil.copy(os.path.join(a.lists, 'assets.json'), os.path.join(assets_dir, 'assets.json'))
    dev = os.path.join(assets_dir, 'assets.dev.json')
    if os.path.exists(dev):
        os.remove(dev)
    missing = []
    for key, it in manifest.items():
        entry = reg.get(key)
        local = local_paths(entry) if entry else []
        if not local:
            missing.append(f'{key}: no local path in registry')
            continue
        target = os.path.join(dest, local[0])
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy(os.path.join(a.lists, it['file']), target)
    # Remove the stub files that tools/make-assets.sh needed in order to run.
    removed = 0
    for root, _, files in os.walk(assets_dir):
        for fn in files:
            p = os.path.join(root, fn)
            if os.path.getsize(p) < 64:
                with open(p, encoding='utf-8', errors='ignore') as f:
                    if f.read().strip() == STUB_MARK:
                        os.remove(p)
                        removed += 1
    lic = os.path.join(a.lists, 'LICENSES-lists.md')
    if os.path.exists(lic):
        shutil.copy(lic, os.path.join(dest, 'LICENSES-lists.md'))
    # Every selected list must now be present at its first local path.
    for key in manifest:
        entry = reg.get(key)
        if entry and local_paths(entry) and not os.path.exists(os.path.join(dest, local_paths(entry)[0])):
            missing.append(f'{key}: file missing after bundling')
    for m in missing:
        log(f'PROBLEM {m}')
    log(f'bundle: {len(manifest)} list(s) bundled, {removed} stub file(s) removed, {len(missing)} problem(s)')
    return 1 if missing else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--config', default=os.path.join(HERE, 'config.json'))
    ap.add_argument('--registry', help='source registry (default: config "registry")')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('list')
    p.add_argument('--out', default=os.path.join(ROOT, 'dist', 'netadblock-lists'))
    p.set_defaults(fn=cmd_list)
    p = sub.add_parser('fetch')
    p.add_argument('--out', default=os.path.join(ROOT, 'dist', 'netadblock-lists'))
    p.set_defaults(fn=cmd_fetch)
    p = sub.add_parser('registry')
    p.add_argument('--out', default=os.path.join(ROOT, 'dist', 'netadblock-lists'))
    p.add_argument('--mirror', help='base URL of your own mirror (no trailing slash)')
    p.set_defaults(fn=cmd_registry)
    p = sub.add_parser('bundle')
    p.add_argument('--lists', default=os.path.join(ROOT, 'dist', 'netadblock-lists'))
    p.add_argument('--build', required=True, help='built extension directory')
    p.set_defaults(fn=cmd_bundle)
    a = ap.parse_args()
    sys.exit(a.fn(a))


if __name__ == '__main__':
    main()
