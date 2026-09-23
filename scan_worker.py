#!/usr/bin/env python3
"""Row#07 hunter - runs on compromised shared-hosting box.
Watches fresh deployments/clones + a funded-watchlist of known-unlocked
implementations/proxies. Stdlib only. Writes JSONL results beside itself."""
import base64, json, os, random, re, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, urlopen
from urllib.error import URLError

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_P = os.path.join(HERE, 'state.json')
SEED_P = os.path.join(HERE, 'watch_seed.json')
HITS_P = os.path.join(HERE, 'hits_open.jsonl')
ALERTS_P = os.path.join(HERE, 'alerts.jsonl')
STATUS_P = os.path.join(HERE, 'status.json')

EPS = {
    'eth': ['https://ethereum-rpc.publicnode.com', 'https://eth-mainnet.public.blastapi.io',
            'https://rpc.flashbots.net', 'https://eth.llamarpc.com', 'https://1rpc.io/eth',
            'https://eth.drpc.org'],
    'bsc': ['https://bsc-dataseed.binance.org', 'https://bsc-dataseed1.defibit.io',
            'https://binance.llamarpc.com', 'https://bsc.blockrazor.xyz',
            'https://1rpc.io/bnb', 'https://bsc-pokt.nodies.app'],
}
FRESH_CALLER = '0x00000000000000000000000000000000DeadBEEF'
WD40 = FRESH_CALLER[2:].lower()
DELEG_PATTERNS = ('363d3d373d3d3d363d73', '5af43d82803e903d91602b57fd5bf3',
                  '366000600037611000600036600073')
E1967 = '360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'

INIT_VARIANTS = [('initialize()', '8129fc1c'), ('initialize(address)', 'c4d66de8' + WD40.rjust(64, '0')),
                 ('init()', 'e1c7392a')]
GETTERS = {'owner()': '8da5cb5b', 'admin()': 'f851a440'}
EV_INIT, EV_OWN = '0xc7f505b2', '0x8be0079c'

_lock = threading.Lock()


def load_json(p, dflt):
    try:
        return json.load(open(p))
    except Exception:
        return dflt


def save_json(p, obj):
    tmp = p + '.tmp'
    json.dump(obj, open(tmp, 'w'))
    os.replace(tmp, p)


class Ep:
    def __init__(self):
        self.i = {}
        self.bad = {}
        self.lock = threading.Lock()

    def pick(self, ch):
        with self.lock:
            eps = EPS[ch]
            n = self.i.get(ch, 0)
            e = eps[n % len(eps)]
            self.i[ch] = n + 1
            # skip recently bad endpoints
            bad = self.bad.setdefault(ch, {})
            for _ in range(len(eps)):
                if bad.get(e, 0) > time.time():
                    n += 1
                    e = eps[n % len(eps)]
                else:
                    break
            return e

    def mark_bad(self, ch, ep, secs=90):
        with self.lock:
            self.bad.setdefault(ch, {})[ep] = time.time() + secs


EPX = Ep()


def rpc_once(url, method, params, timeout=18):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = Request(url, data=body, headers={
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/124.0 Safari/537.36'})
    with urlopen(req, timeout=timeout) as r:
        j = json.load(r)
    if isinstance(j, dict) and j.get('error'):
        raise RuntimeError(str(j['error'])[:80])
    return j.get('result')


def rpc(ch, method, params, tries=3):
    last = None
    for k in range(tries):
        ep = EPX.pick(ch)
        try:
            return rpc_once(ep, method, params)
        except Exception as e:
            last = str(e)[:70]
            msg = last.lower()
            if any(x in msg for x in ('403', 'forbid', 'rate', 'limit', 'too many', 'timeout',
                                      'capacity', '502', '503', 'unauthor')) :
                EPX.mark_bad(ch, ep, secs=150)
            time.sleep(0.25 * (k + 1))
    raise RuntimeError(last or 'fail')


def sim_calls(ch, calls):
    blk = rpc(ch, 'eth_simulateV1', [{
        "blockStateCalls": [{"calls": calls}], "validation": False,
        "traceTransfers": True}, "latest"])
    return (blk or [{}])[0]


TRT = 'ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'


def probe_addr(ch, addr):
    """Returns record when an initialize variant executes w/ evidence or owner becomes us."""
    calls, plan = [], []
    for gn, gs in GETTERS.items():
        calls.append({"from": FRESH_CALLER, "to": addr, "input": '0x' + gs}); plan.append(('base', gn))
    for lab, cd in INIT_VARIANTS:
        calls.append({"from": FRESH_CALLER, "to": addr, "input": '0x' + cd}); plan.append(('fire', lab))
        for gn, gs in GETTERS.items():
            calls.append({"from": FRESH_CALLER, "to": addr, "input": '0x' + gs})
            plan.append(('read:' + lab, gn))
    b = sim_calls(ch, calls)
    cs = b.get('calls') or []
    events, takeovers, changes, tok_in = [], [], [], []
    for tr in (b.get('transfers') or []):
        d = str(tr.get('to', '')).lower().replace('0x', '')
        try:
            v = int(str(tr.get('value') or '0'), 16)
        except Exception:
            v = 0
        if d.endswith(WD40) and v:
            tok_in.append({'native': str(v)})
    base = {}
    cur = None
    for i, pl in enumerate(plan):
        if i >= len(cs):
            break
        kind, lab = pl
        c = cs[i]; rd = c.get('returnData') or ''
        st = c.get('status'); lg = c.get('logs') or []
        tops = [(l.get('topics') or [''])[0].lower() for l in lg]
        if kind == 'base':
            base[lab] = rd[-40:].lower() if len(rd) >= 41 else ''
        elif kind == 'fire':
            ev_i = any(t.startswith(EV_INIT) for t in tops)
            ev_o = any(t.startswith(EV_OWN) for t in tops)
            if st == '0x1' and (ev_i or ev_o):
                events.append(lab)
            cur = lab if st == '0x1' else None
        else:
            short = lab.split(':', 1)[1] if ':' in lab else lab
            var_lab = lab.split(':', 1)[0]
            w = rd[-40:].lower() if len(rd) >= 20 else ''
            if w and int(w, 16):
                if base.get(short) != w:
                    changes.append({'by': var_lab, 'getter': short, 'after': w[:14] + '..'})
                if w.endswith(WD40):
                    takeovers.append({'by': var_lab, 'getter': short})
    hit = bool(events or takeovers)
    rec = None
    if hit:
        nb = 0
        try:
            nb = int(rpc(ch, 'eth_getBalance', [addr, 'latest']) or '0x0', 16)
        except Exception:
            pass
        rec = {'ts': int(time.time()), 'chain': ch, 'addr': addr, 'events': events[:3],
               'takeover': takeovers[:2], 'changes': changes[:3], 'native_wei': nb}
    return rec, changes, takeovers


BN_BATCH = int(os.environ.get('SW_BN', '130'))
ADD_CAP = int(os.environ.get('SW_ADDCAP', '1100'))
WATCH_STEP = int(os.environ.get('SW_WSTEP', '110'))
LOG_SPAN = int(os.environ.get("SW_LOG","300"))
TOPIC_PAIRCREATED='0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9'
TOPIC_UPGRADED='0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b'


def addr_from_word(w):
    try:
        if not isinstance(w, str): return None
        ww = w.lower().replace('0x','')
        if len(ww) < 40: return None
        cand = '0x'+ww[-40:]
        if int(cand,16)==0 or cand == FRESH_CALLER.lower(): return None
        # heuristic: skip obvious big-number words (not used here)
        return cand
    except Exception:
        return None


def harvest_log_addrs(ch, lo, hi):
    out=[]
    for topic in (TOPIC_PAIRCREATED, TOPIC_UPGRADED):
        try:
            lg = rpc(ch,'eth_getLogs',[{'fromBlock':hex(lo),'toBlock':hex(hi),'topics':[topic]}],tries=2)
        except Exception:
            continue
        for entry in (lg or []):
            for t in (entry.get('topics') or [])[1:]:
                a=addr_from_word(t)
                if a: out.append(a)
            d=(entry.get('data') or '')[2:]
            for i in range(0,len(d)-63,64):
                a=addr_from_word(d[i:i+64])
                if a: out.append(a)
    return out


CODE_KEEP_MAX = 300      # bytecode length that screams clone/proxy/mini-logic
MINI_SCAN_CODE_MIN = 400


def classify_code(codehex):
    if not codehex or codehex == '0x':
        return None
    b = codehex[2:].lower()
    nbytes = len(b) // 2
    if any(p in b[:300] for p in DELEG_PATTERNS):
        return 'clone'
    if E1967 in b:
        return 'proxy1967'
    if nbytes <= CODE_KEEP_MAX:
        return 'mini'
    return None


def process_candidates(ch, addrs, state, outlock, stats):
    cands = sorted(set(a.lower() for a in addrs if isinstance(a, str)))
    if not cands:
        return
    chunk = 90
    parts = [cands[i:i + chunk] for i in range(0, len(cands), chunk)]
    kept = []

    def codes_for(part):
        try:
            res = rpc(ch, 'eth_getCode', [part, 'latest'])
            return part, (res if isinstance(res, list) else None)
        except Exception:
            return part, None

    from concurrent.futures import as_completed as _ac
    tC = time.time()
    with ThreadPoolExecutor(max_workers=9) as ex:
        futs = [ex.submit(codes_for, pp) for pp in parts[:40]]
        done_chunks = 0
        for fu in _ac(futs):
            part, res = fu.result()
            done_chunks += 1
            if res:
                for a, c in zip(part, res):
                    shape = classify_code(c if isinstance(c, str) else '')
                    if shape:
                        kept.append((a, shape))
            if done_chunks % 12 == 0:
                print(f'[sw] {ch} codepass {done_chunks}/{len(futs)} kept={len(kept)} {time.time()-tC:.0f}s', flush=True)
    stats['checked'] += len(cands)

    def work(item):
        a, shape = item
        try:
            rec, changes, takes = probe_addr(ch, a)
            return rec
        except Exception:
            return None

    print(f'[sw] {ch} probing {min(len(kept),140)} shapes', flush=True)
    with ThreadPoolExecutor(max_workers=8) as ex:
        for rec in ex.map(work, kept[:140]):
            if not rec:
                continue
            with outlock:
                with open(HITS_P, 'a') as f:
                    f.write(json.dumps(rec) + '\n')
                wl = state.setdefault('watch', [])
                if rec['addr'] not in wl:
                    wl.append(rec['addr'])
                stats['hits'] += 1


def refresh_watch_prices(stats):
    pass


import fcntl


_LOCKFH = None


def _single_instance():
    global _LOCKFH
    _LOCKFH = open(os.path.join(HERE, 'run.lock'), 'w')
    try:
        fcntl.flock(_LOCKFH, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except Exception:
        return False


def main():
    if not _single_instance():
        print('[sw] another instance holds the lock, exiting', flush=True)
        return
    outlock = threading.Lock()
    state = load_json(STATE_P, {'cursor': {}, 'seen': {}, 'watch': [],
                                'known_hits': 0, 'cycles': 0})
    seed = load_json(SEED_P, {'watch': []})
    for a in (seed.get('watch') or []):
        if a not in state['watch']:
            state['watch'].append(a)
    print('[sw] start pid=%d watch=%d cursor=%s' % (os.getpid(), len(state['watch']),
                                                    state.get('cursor')), flush=True)
    while True:
        t0 = time.time()
        stats = {'chains': {}}
        for ch in ('eth', 'bsc'):
            try:
                head = int(rpc(ch, 'eth_blockNumber', []), 16)
            except Exception as e:
                stats['chains'][ch] = {'err': str(e)[:50]}
                continue
            cur = state['cursor'].get(ch)
            cur = int(cur) if cur not in (None, '',) and str(cur).isdigit() else None
            if cur is None:
                try: cur = int(str(state['cursor'].get(ch)),16) if state['cursor'].get(ch) else None
                except Exception: cur=None
            span_back = 4200 if ch == 'eth' else 19000
            lo_default = max(1, head - span_back)
            cur = int(cur) if cur else lo_default
            if cur > head - 800:      # behind enough? normal path scans next window
                lo = min(cur + 900, head)
                hi = min(lo + 899, head)
            else:
                lo, hi = cur + 901, min(cur + 1800, head)
            if lo > head:
                lo, hi = lo_default, min(lo_default + 449, head)
            bn_list = list(range(hi, lo - 1, -1))[:BN_BATCH]
            print(f'[sw] {ch} window {lo}-{hi} blocks={len(bn_list)}', flush=True)

            def grab(bn):
                try:
                    return rpc(ch, 'eth_getBlockByNumber', [hex(bn), True])
                except Exception:
                    return None

            # --- event-log lane: incremental & range-capped ---
            try:
                lc = state.setdefault('logcur', {}).get(ch)
                lc = int(lc) if str(lc).isdigit() else None
            except Exception:
                lc = None
            if lc is None:
                lc = max(1, hi - LOG_SPAN)
            lfrom = lc + 1
            lto = min(max(lfrom + LOG_SPAN - 1, lfrom), hi)
            if lfrom <= hi:
                ev = harvest_log_addrs(ch, lfrom, lto)
                state.setdefault('logcur', {})[ch] = lto
            else:
                ev = []
            print(f'[sw] {ch} logs {lfrom}-{lto} found={len(ev)}', flush=True)

            seen_addrs = set(a.lower() for a in ev)
            add_from_logs = len(seen_addrs)
            # merge block-tx recipients later once fetched
            logs_seed = sorted(seen_addrs)
            add_map = {a: 'logseed' for a in logs_seed}
            done_max = hi
            with ThreadPoolExecutor(max_workers=10) as ex:
                for blk in ex.map(grab, bn_list):
                    if not blk:
                        continue
                    for tx in (blk.get('transactions') or []):
                        to = tx.get('to')
                        if to:
                            tgl = to.lower()
                            if tgl not in add_map:
                                add_map[tgl] = 'tx'
            print(f'[sw] {ch} seeds(log)={add_from_logs}', flush=True)
            adds = sorted(add_map.keys())
            if len(adds) > ADD_CAP:
                keep_logs = [a for a in adds if add_map[a]=='logseed']
                rest = [a for a in adds if add_map[a]!='logseed']
                budget = max(50, ADD_CAP - len(keep_logs))
                adds = keep_logs + (random.sample(rest, min(len(rest), budget)) if rest else [])
            print(f'[sw] {ch} candidates total={len(adds)} logs={add_from_logs}', flush=True)
            stats['chains'][ch] = {'window': [lo, hi], 'tx_targets': len(adds)}
            state['cursor'][ch] = hi
            process_candidates(ch, adds, state, outlock, stats.setdefault(ch, {'checked': 0, 'hits': 0}))

        # -------- watchlist funding sweep -----------
        wl = state.get('watch') or []
        fund_alerts = 0
        for ch in ('eth', 'bsc'):
            sub = [a for a in wl]
            if not sub:
                continue
            step = WATCH_STEP
            for i in range(0, len(sub), step):
                part = sub[i:i + step]
                try:
                    bal_res = None
                    payload = [{"jsonrpc": "2.0", "id": k, "method": "eth_getBalance",
                                "params": [p, "latest"]} for k, p in enumerate(part)]
                    ep = EPX.pick(ch)
                    req = Request(ep, data=json.dumps(payload).encode(),
                                  headers={'Content-Type': 'application/json'})
                    with urlopen(req, timeout=22) as rr:
                        arr = json.load(rr)
                    got = {j.get('id'): j.get('result') for j in arr}
                    for k, p in enumerate(part):
                        v = got.get(k)
                        if not v or v == '0x0':
                            continue
                        wei = int(v, 16)
                        if wei <= 320000000000000:
                            continue
                        with outlock:
                            al = {'ts': int(time.time()), 'kind': 'funded-candidate',
                                  'chain': ch, 'addr': p, 'wei': wei}
                            with open(ALERTS_P, 'a') as f:
                                f.write(json.dumps(al) + '\n')
                        fund_alerts += 1
                except Exception:
                    continue
        state['cycles'] = (state.get('cycles') or 0) + 1
        dt = max(1, time.time() - t0)
        status = {'pid': os.getpid(), 'cycle': state['cycles'], 'elapsed': round(dt, 1),
                  'watch_size': len(state['watch']), 'stats': stats,
                  'fund_alerts_total_session': fund_alerts,
                  'now_head': {ch: state['cursor'].get(ch) for ch in ('eth', 'bsc')}}
        save_json(STATUS_P, status)
        save_json(STATE_P, state)
        print('[sw] cyc=%d %.0fs watch=%d alerts=%d %s' %
              (state['cycles'], dt, len(state['watch']), fund_alerts,
               {k: v for k, v in stats.get('chains', {}).items()}), flush=True)
        sleep_for = max(2, 14 - dt)
        time.sleep(sleep_for)


if __name__ == '__main__':
    main()
