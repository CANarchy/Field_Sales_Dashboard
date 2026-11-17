#!/usr/bin/env python3
"""Rebuild the Field Survey Dashboard from KARMA grid exports (no Power BI).
Reuses the transforms/render logic of build_from_powerbi.py; inputs are the
ResultsByForm survey export and the Buyer Commitments export."""
import collections, datetime as dt, json, os, re, sys
from openpyxl import load_workbook
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_from_powerbi as B

import argparse
ap = argparse.ArgumentParser(description='Build the dashboard from KARMA grid exports (no Power BI).')
ap.add_argument('survey_xlsx', help='KARMA ResultsByForm export (.xlsx)')
ap.add_argument('buyer_xlsx', help='KARMA Buyer Commitments export (.xlsx)')
ap.add_argument('--out', default='dist')
ap.add_argument('--pulled', default=dt.date.today().strftime('%m/%d/%Y'), help='date the exports were pulled, for the footer')
args = ap.parse_args()
REPO = os.path.dirname(os.path.abspath(__file__))
SURVEY_X, BUY_X, OUT = args.survey_xlsx, args.buyer_xlsx, args.out

empmap = json.load(open(f'{REPO}/empmap.json', encoding='utf-8'))
dist_fallback = json.load(open(f'{REPO}/dist_codes.json', encoding='utf-8'))
s, tc = B.s, B.tc

def us_dt(v):  # "11/15/2026 10:29:10 PM" -> "2026-11-15 22:29"
    return dt.datetime.strptime(s(v), '%m/%d/%Y %I:%M:%S %p').strftime('%Y-%m-%d %H:%M')

def dist_names(cell):
    out = []
    for part in [p.strip() for p in s(cell).split(',') if p.strip()]:
        code, _, name = part.partition('-')
        code, name = code.strip(), name.strip()
        # some names contain commas themselves ("Liberty Coca Cola Beverages - Philadelph"); re-join orphan fragments
        if not code.isdigit():
            if out: out[-1] = out[-1] + ', ' + part
            continue
        name = dist_fallback.get(code, name) or name
        out.append(name)
    out = [d for d in out if d and not B.SODA.search(d)]
    return ' · '.join(dict.fromkeys(out)) or '—'

# ---------------------------------------------------------------- surveys
wb = load_workbook(SURVEY_X)
ws = wb.active
hdr = [c.value for c in ws[10]]
H = {h: i for i, h in enumerate(hdr)}
PHOTO_COLS = [('Photo of cold vault/warm shelf/or tap handles in account', 'Shelf/Vault'), ('Photo 1', 'Photo 1'),
              ('Photo 2', 'Photo 2'), ('Picture of New Display', 'New Display'), ('Picture of New W&W/POS/Suction Cup', 'W&W/POS')]
rows, seen, unknown = [], set(), collections.Counter()
for r in ws.iter_rows(min_row=11):
    v = [c.value for c in r]
    emp = s(v[H['Employee']])
    if not emp:
        continue
    vip = s(v[H['VIP ID#']])
    dts = us_dt(v[H['Date']])
    key = (vip, emp, dts)
    if key in seen:
        continue
    seen.add(key)
    if emp in empmap:
        role = empmap[emp][0]
    else:
        role = 'Field Sales Representative'; unknown[emp] += 1
    notes, com = s(v[H['Notes:']]), s(v[H['Comments']])
    note = notes + (' — ' + com if notes and com else com if com else '')
    photos = []
    for col, lab in PHOTO_COLS:
        c = r[H[col]]
        if c.hyperlink and c.hyperlink.target:
            photos.append([lab, c.hyperlink.target])
    ride = tc(v[H['Who are you riding with:']])
    rn = s(v[H['Name of MBC employee you are riding with:']])
    if 'Mbrew' in ride and rn:
        ride += ': ' + ' '.join(tc(rn).split())
    chain = s(v[H['Chain']])
    chain = 'Independents' if chain.upper() in ('', 'INDEPENDENTS') else tc(chain)
    rows.append([
        emp, role, dts, tc(v[H['Account']]), tc(v[H['City']]), s(v[H['ST']]).upper(),
        s(v[H['Premise']]).upper(), tc(v[H['COT']]), chain, dist_names(v[H['Servicing Dist.']]),
        note, B.norm_yn(v[H['Follow up required?']]), B.norm_yn(v[H['New display built?']]), photos, vip,
        tc(v[H['Address']]), s(v[H['Zip']])[:5], ride, B.norm_yn(v[H['Did you gain any bonus objectives? (FSR Only)']]),
        B.norm_yn(v[H['New W&W/POS/Suction Cup?']]),
    ])
rows.sort(key=lambda r: (r[2], r[0]))

# ---------------------------------------------------------------- buyer commitments
b = pd.read_excel(BUY_X, header=None)
hdr_row = b.iloc[5].tolist()
ce_label = s(b.iloc[3, 21])  # "3 Months 9/1/2026 thru 11/12/2026"
data = b.iloc[7:]
accts = {}
for _, x in data.iterrows():
    g = lambda i: '' if pd.isna(x[i]) else s(x[i])
    if g(0) == 'Total' or g(8) == 'Total' or not g(5):
        continue
    vip = g(5)
    a = accts.setdefault(vip, dict(acct=tc(g(0)), addr=tc(g(1)), city=tc(g(2)), st=g(3).upper(), zip=g(4)[:5],
                                   vip=vip, blocks={}))
    dc, parent, rep = g(6), g(7), g(8)
    blk = a['blocks'].setdefault((dc, rep), dict(dc=dc, parent=parent, rep=rep, case_eq=0.0, status='OPEN', dates=[],
                                                 commits=[], contact=dict(name='', phone='', spoke=''), note=''))
    try:
        blk['case_eq'] = round(float(x[21]), 2) if not pd.isna(x[21]) else blk['case_eq']
    except (TypeError, ValueError):
        pass
    brand = g(11)
    if brand and brand != '(blank)':
        try: qty = int(float(g(14) or 0))
        except ValueError: qty = 0
        c = dict(brand=tc(brand), qty=qty, got=B.norm_yn(g(15)), loc=g(17), instr=g(16))
        if c not in blk['commits']:
            blk['commits'].append(c)
    if g(18) or g(19) or g(20):
        blk['contact'] = dict(name=tc(g(18)), phone=re.sub(r'\.0$', '', g(19)), spoke=tc(g(20)))
    if g(13):
        blk['note'] = g(13)
buy = []
for vip, a in accts.items():
    blocks = []
    for blk in a['blocks'].values():
        blk['status'] = 'FULFILLED' if blk['case_eq'] > 0 else 'OPEN'
        if not blk['commits'] and not blk['note']:
            blk['note'] = B.AUTO_NOTE
        blocks.append(blk)
    a['blocks'] = blocks
    buy.append(a)
buy.sort(key=lambda a: (a['st'], a['acct']))
B.refresh_karma(buy, rows)

# ---------------------------------------------------------------- render
B.HERE = REPO
tpl = f'{REPO}/template/dashboard.html'
inner = open(tpl, encoding='utf-8').read()
m = re.search(r'(\d+)/(\d+)/\d+ thru (\d+)/(\d+)/\d+', ce_label)
win = f'{m.group(1)}/{m.group(2)}–{m.group(3)}/{m.group(4)}' if m else ce_label
inner = inner.replace('5/1–10/2 depletion window', win + ' depletion window')
d0, d1 = rows[0][2][:10], rows[-1][2][:10]
foot = (f'Source: KARMA ResultsByForm export pulled {args.pulled} (surveys {d0} to {d1}) and Buyer Commitments export '
        f'1/1/2026–11/15/2026 · {len(rows):,} field surveys · {len(buy):,} commitment accounts; case equivalents {ce_label}. '
        'Energy (Coca-Cola system) distributors stripped per the approved parent list.')
inner = re.sub(r'(<div class="foot">)[^<]*', lambda mm: mm.group(1) + foot, inner)
os.makedirs(OUT, exist_ok=True)
# reuse B.render with the patched template
orig = B.render
def render_patched(rows, buy, empmap, out_dir, subtitle=None):
    bak = open(tpl, encoding='utf-8').read()
    open(tpl, 'w', encoding='utf-8').write(inner)
    try:
        return orig(rows, buy, empmap, out_dir, subtitle)
    finally:
        open(tpl, 'w', encoding='utf-8').write(bak)
path = render_patched(rows, buy, empmap, OUT)

blocks = sum(len(x['blocks']) for x in buy)
openb = sum(1 for x in buy for bl in x['blocks'] if bl['status'] == 'OPEN')
print(f'Surveys: {len(rows):,} ({d0} to {d1}); {len({r[0] for r in rows})} reps; states {len({r[5] for r in rows})}')
print(f'Commitments: {len(buy):,} accounts, {blocks:,} blocks, {openb:,} open; CE {ce_label}')
print(f'Wrote {path} ({os.path.getsize(path)/1e6:.1f} MB)')
if unknown:
    print('NEW EMPLOYEES not in empmap.json:', ', '.join(f'{k} ({n})' for k, n in unknown.most_common()))
