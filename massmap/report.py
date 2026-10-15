"""Reconcile evidence and render self-contained HTML using only the standard library."""
import csv
import datetime as dt
import json
from html import escape
from pathlib import Path

from .model import (MassMapError, atomic_json, endpoint_key, read_json, reconcile,
                    records, row_sort, xml_root)

def comparison(current, baseline):
    def opened(report):
        return {endpoint_key(r): r for r in report['observations'] if r['evidence'] == 'confirmed-open'}
    old, new = opened(baseline), opened(current)
    warnings = []
    if not current.get('manifest') or not baseline.get('manifest'):
        warnings.append('One or both reports lack run metadata; coverage equivalence is unknown.')
    else:
        a, b = current['manifest'], baseline['manifest']
        if a['scope']['effective'] != b['scope']['effective'] or a['options'] != b['options']:
            warnings.append('Scope or scan settings differ; observations are not directly comparable.')
        if a['status'] != 'completed' or b['status'] != 'completed':
            warnings.append('One or both runs are incomplete; absence is not evidence of closure.')
        if a.get('tools') != b.get('tools'):
            warnings.append('Scanner versions or paths differ.')
    changes = []
    for key in new.keys() - old.keys():
        changes.append(dict(new[key], change='newly-observed'))
    for key in old.keys() - new.keys():
        changes.append(dict(old[key], change='no-longer-observed'))
    for key in old.keys() & new.keys():
        fields = ('service', 'product', 'version', 'tunnel', 'cpes')
        if any(old[key].get(f) != new[key].get(f) for f in fields):
            changes.append(dict(new[key], change='service-changed', previous={f: old[key].get(f) for f in fields}))
    return {'warnings': warnings, 'changes': sorted(changes, key=row_sort),
            'note': 'No-longer-observed does not mean closed. Discovery misses and changed coverage can explain differences.'}


def safe_csv(value):
    text = str(value)
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else text


def generate(xml_path, directory, manifest=None, baseline=None):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    root = xml_root(xml_path)
    for old in root.findall('massmap'):
        root.remove(old)
    found = []
    if manifest is not None and (directory / 'discovery.json').is_file():
        found = read_json(directory / 'discovery.json')
    observations = reconcile(found, records(root))
    report = {'schema': 1, 'generated': dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
              'manifest': manifest, 'observations': observations,
              'source_xml': str(Path(xml_path).resolve())}
    if baseline:
        baseline = Path(baseline)
        prior = read_json(baseline / 'report.json' if baseline.is_dir() else baseline)
        if prior.get('schema') != 1 or not isinstance(prior.get('observations'), list):
            raise MassMapError('Baseline must be a MassMap report.json (schema 1)')
        report['comparison'] = comparison(report, prior)
    atomic_json(directory / 'report.json', report)
    fields = ['address', 'protocol', 'port', 'state', 'reason', 'service', 'product', 'version', 'evidence', 'source']
    with (directory / 'services.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in observations:
            writer.writerow({key: safe_csv(row.get(key, '')) for key in fields})
    target = directory / 'report.html'
    temp = target.with_suffix('.html.tmp')
    temp.write_text(render_html(root, report), encoding='utf-8')
    temp.replace(target)
    return report


CSS = r"""
:root{color-scheme:light;--bg:#f0f4fa;--paper:#fff;--ink:#172841;--muted:#596b83;--line:#dce4ef;--soft:#edf2fa;--accent:#1766cb;--green:#16734b;--green-bg:#e6f6ed;--amber:#946000;--amber-bg:#fff3d5;--red:#b3344c;--red-bg:#fdebf0;--blue:#245db8;--blue-bg:#eaf1ff;--purple:#7450b0;--purple-bg:#f2ebff;--cyan:#087883;--cyan-bg:#e1f5f6;--warn:var(--amber);--shadow:0 3px 16px #18396508}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;--bg:#0d1422;--paper:#151f30;--ink:#e2eafa;--muted:#9babC2;--line:#2a3850;--soft:#1d2b42;--accent:#78acff;--green:#72dca6;--green-bg:#173c30;--amber:#f2c36b;--amber-bg:#3d321c;--red:#ff93a7;--red-bg:#422432;--blue:#8cb8ff;--blue-bg:#203452;--purple:#c0a4fc;--purple-bg:#322747;--cyan:#71d6e2;--cyan-bg:#19383e;--shadow:none}}
:root[data-theme=dark]{color-scheme:dark;--bg:#0d1422;--paper:#151f30;--ink:#e2eafa;--muted:#9babc2;--line:#2a3850;--soft:#1d2b42;--accent:#78acff;--green:#72dca6;--green-bg:#173c30;--amber:#f2c36b;--amber-bg:#3d321c;--red:#ff93a7;--red-bg:#422432;--blue:#8cb8ff;--blue-bg:#203452;--purple:#c0a4fc;--purple-bg:#322747;--cyan:#71d6e2;--cyan-bg:#19383e;--shadow:none}
*{box-sizing:border-box}html{scroll-padding-top:75px}body{margin:0;background:var(--bg);color:var(--ink);font:13px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1480px;margin:auto;padding:0 32px}header{display:flex;align-items:center;gap:18px;padding:19px 0;border-bottom:1px solid var(--line)}.brand{font-size:26px;font-weight:800;letter-spacing:-1.3px}.brand span{color:var(--accent)}.brand:before{content:"";display:inline-block;width:9px;height:23px;background:linear-gradient(180deg,#36cfc5,#4582ff);border-radius:3px;margin-right:10px;vertical-align:-2px}.actions{display:flex;align-items:center;gap:8px;margin-left:auto}h1{font-size:28px;line-height:1.2;letter-spacing:-.8px;margin:27px 0 7px}h2{font-size:17px;letter-spacing:-.3px;margin:0}h3{font-size:13px;margin:14px 0 8px}p{margin:8px 0 12px}.muted,small{color:var(--muted)}small{font-size:11px}.run-subtitle{font-size:12px;color:var(--muted);margin-bottom:22px;overflow-wrap:anywhere}a{color:var(--accent);text-underline-offset:3px}code{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}pre{font:11px/1.65 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:var(--bg);border:1px solid var(--line);padding:12px;border-radius:6px;margin:8px 0}button,input,select{font:inherit;color:var(--ink);background:var(--paper);border:1px solid var(--line);border-radius:6px;padding:7px 11px;max-width:100%}button,summary{cursor:pointer}button:hover{border-color:var(--accent);background:var(--soft)}button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid var(--accent);outline-offset:3px}button[disabled]{opacity:.45;cursor:default}#theme{display:inline-flex;align-items:center;justify-content:center;width:36px;height:36px;padding:8px}#theme svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}#theme .sun{display:none}:root[data-theme=dark] #theme .sun{display:block}:root[data-theme=dark] #theme .moon{display:none}
.layout{margin-top:6px}.sections{display:flex;gap:5px;flex-wrap:wrap;position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line);padding:10px 0;margin-bottom:22px}.sections a{font-size:12px;font-weight:600;color:var(--muted);text-decoration:none;padding:6px 12px;border-radius:5px}.sections a:hover,.sections a:focus{background:var(--blue-bg);color:var(--blue)}.content{min-width:0}section{margin-bottom:28px;scroll-margin-top:12px}.section-head{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:12px;flex-wrap:wrap}.section-head p{font-size:12px;color:var(--muted);margin:3px 0 0}.section-head .actions button{font-size:11px;padding:5px 9px}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:12px 0 14px}.stat{position:relative;background:var(--paper);border:1px solid var(--line);border-top:3px solid var(--blue);border-radius:8px;padding:15px 17px;box-shadow:var(--shadow)}.stat:nth-child(2){border-top-color:var(--purple)}.stat:nth-child(3){border-top-color:var(--green)}.stat:nth-child(4){border-top-color:var(--amber)}.stat:nth-child(1) .value{color:var(--blue)}.stat:nth-child(2) .value{color:var(--purple)}.stat:nth-child(3) .value{color:var(--green)}.stat:nth-child(4) .value{color:var(--amber)}.label{font-size:11px;font-weight:600;color:var(--muted)}.value{font-size:30px;font-weight:750;line-height:1.35;margin:5px 0;letter-spacing:-1px;font-variant-numeric:tabular-nums}.run-meta{display:flex;gap:12px;align-items:center;flex-wrap:wrap;color:var(--muted);font-size:12px}.notice{font-size:12px;border:1px solid var(--amber);border-left:3px solid var(--amber);background:var(--amber-bg);color:var(--amber);padding:9px 12px;border-radius:5px;overflow-wrap:anywhere;margin:12px 0}
.badge,.service-tag,.proto{display:inline-flex;align-items:center;gap:5px;vertical-align:middle;padding:2px 7px;border-radius:5px;font-size:11px;font-weight:600;line-height:1.65;white-space:nowrap;color:var(--muted);background:var(--soft)}.state-open,.evidence-open{color:var(--green);background:var(--green-bg)}.state-closed,.state-error{color:var(--red);background:var(--red-bg)}.state-filtered,.state-uncertain,.evidence-unconfirmed{color:var(--amber);background:var(--amber-bg)}.state-running{color:var(--blue);background:var(--blue-bg)}.badge.state:before{content:"";width:5px;height:5px;border-radius:50%;background:currentColor;flex-shrink:0}.service-web{color:var(--blue);background:var(--blue-bg)}.service-access{color:var(--purple);background:var(--purple-bg)}.service-data{color:var(--amber);background:var(--amber-bg)}.service-infra{color:var(--cyan);background:var(--cyan-bg)}.proto{font-size:9px;letter-spacing:.5px;text-transform:uppercase;padding:1px 5px;margin-left:6px;color:var(--cyan);background:var(--cyan-bg)}.proto.udp{color:var(--purple);background:var(--purple-bg)}.tls{color:var(--cyan);font-size:10px;font-weight:650;margin-left:5px}.reason{display:block;font-size:10px;color:var(--muted);margin-top:3px}.state-key{display:flex;align-items:center;gap:14px;flex-wrap:wrap;color:var(--muted);font-size:11px}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;background:var(--muted)}.dot.open{background:var(--green)}.dot.closed{background:var(--red)}.dot.uncertain{background:var(--amber)}.dot.info{background:var(--blue)}.overview{background:var(--paper);border:1px solid var(--line);border-radius:8px;padding:14px 17px;margin:14px 0;box-shadow:var(--shadow)}.overview-title{font-size:11px;font-weight:650;color:var(--muted);margin-bottom:10px;display:flex;justify-content:space-between;gap:12px}.state-bar{display:flex;height:7px;gap:3px;overflow:hidden;border-radius:4px;margin-bottom:10px;background:var(--soft)}.state-bar span{min-width:3px;background:var(--muted)}.state-bar .state-open{background:var(--green)}.state-bar .state-closed{background:var(--red)}.state-bar .state-filtered,.state-bar .state-uncertain{background:var(--amber)}.service-chips{display:flex;gap:7px;flex-wrap:wrap;margin-top:11px}.service-chips button{font-size:11px;border:1px solid transparent;padding:3px 9px}.service-chips button[aria-pressed=true]{border-color:currentColor}.service-chips b{margin-left:7px;opacity:.75}.toolbar{display:flex;gap:10px;align-items:end;flex-wrap:wrap;padding:12px;background:var(--paper);border:1px solid var(--line);border-radius:8px 8px 0 0;border-bottom:0}.toolbar label{font-size:11px;color:var(--muted);display:flex;flex-direction:column;gap:4px}.search{flex:1;min-width:180px}.search input{width:100%}.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:0 0 8px 8px;background:var(--paper)}table{border-collapse:collapse;text-align:left;font-size:12px;width:100%}th{font-size:10px;letter-spacing:.55px;color:var(--muted);font-weight:650;background:var(--soft)}td,th{padding:9px 13px;border-bottom:1px solid var(--line);vertical-align:middle;overflow-wrap:anywhere}td small{font-size:10px}tbody tr:hover{background:var(--soft)}tr:last-child td{border-bottom:0}th button{padding:0;border:0;background:none;font:inherit;text-transform:inherit;letter-spacing:inherit}td:first-child code{color:var(--accent);font-weight:550}.product{display:block;color:var(--muted);font-size:11px;margin-top:3px}.port-number{font-weight:650;font-variant-numeric:tabular-nums}.pager{display:flex;gap:10px;align-items:center;font-size:11px;color:var(--muted);margin-top:10px}.pager button{font-size:11px;padding:4px 9px}.empty{color:var(--muted);padding:12px;font-size:12px}
#hosts{font-size:12px}.host-toolbar{margin-bottom:10px;gap:8px;align-items:center}.host-toolbar input{font-size:12px;flex:1;min-width:180px}.host-toolbar span{font-size:11px;color:var(--muted)}.host{border:1px solid var(--line);border-radius:8px;background:var(--paper);margin:9px 0;box-shadow:var(--shadow);overflow:hidden}.host>summary{padding:12px 14px;font-size:12px;list-style:none;display:flex;align-items:center;gap:12px;flex-wrap:wrap}.host>summary::-webkit-details-marker,.port-row>summary::-webkit-details-marker{display:none}.host>summary:before,.port-row>summary:before{content:"›";color:var(--muted);font-size:19px;line-height:1;display:inline-block;width:10px;flex-shrink:0;transition:transform .12s}.host[open]>summary:before,.port-row[open]>summary:before{transform:rotate(90deg)}.host[open]>summary{border-bottom:1px solid var(--line);background:var(--soft)}.host-identity{display:flex;align-items:center;gap:10px;flex-wrap:wrap;min-width:0}.host-identity code{font-size:12px;font-weight:700;color:var(--accent)}.hostname{font-size:11px;color:var(--muted)}.host-counts{display:flex;gap:6px;margin-left:auto;flex-wrap:wrap}.port-preview{display:flex;gap:5px;flex-wrap:wrap}.port-preview code{font-size:10px;color:var(--muted);border:1px solid var(--line);padding:1px 5px;border-radius:4px}.host-body{padding:10px 14px 12px}.host-meta{display:flex;align-items:center;flex-wrap:wrap;gap:8px;font-size:11px;color:var(--muted);margin-bottom:10px}.host-meta p{margin:0}.port-labels,.port-row>summary{display:grid;grid-template-columns:10px 90px 104px 120px minmax(110px,1fr) 65px;gap:10px;align-items:center}.port-labels{font-size:9px;color:var(--muted);letter-spacing:.6px;padding:7px 10px;background:var(--soft);border-radius:5px 5px 0 0}.port-row{border:1px solid var(--line);border-top:0;font-size:12px}.port-row:last-child{border-radius:0 0 5px 5px}.port-row>summary{list-style:none;padding:8px 10px;font-size:11px;min-height:37px}.port-row>summary:hover{background:var(--soft)}.port-row[open]>summary{background:var(--soft)}.port-row .badge,.port-row .service-tag{font-size:10px;padding:1px 6px;justify-self:start;max-width:100%;white-space:normal}.port-row .port-number{font:600 11px ui-monospace,monospace}.port-product{color:var(--muted);font-size:11px;overflow-wrap:anywhere}.script-count{color:var(--purple);font-size:10px;text-align:right}.port-detail{padding:10px 13px 10px 30px;border-top:1px dashed var(--line);background:var(--bg)}.facts{display:flex;gap:7px 18px;flex-wrap:wrap;color:var(--muted);font-size:11px;margin-bottom:6px}.facts strong{font-weight:550;color:var(--ink)}.cpe{font-size:10px;color:var(--muted);margin:5px 0}.script{border:1px solid var(--line);border-radius:5px;background:var(--paper);margin:6px 0;font-size:11px}.script>summary{color:var(--purple);font:500 11px ui-monospace,monospace;padding:7px 9px}.script pre{margin:0;border:0;border-top:1px solid var(--line);border-radius:0 0 5px 5px;font-size:10px;max-height:340px;overflow:auto}.host-facts{margin:10px 0 0}.host-facts>summary{font-size:11px;color:var(--muted)}.method-copy{background:var(--paper);padding:14px 17px;border:1px solid var(--line);border-radius:8px;margin-top:12px;font-size:12px}.method-copy p:last-child{margin-bottom:0}#provenance .host{padding:0}#provenance .host>summary:before{display:none}footer{border-top:1px solid var(--line);padding:18px 0 25px;font-size:11px;color:var(--muted);margin-top:22px}.js-only{display:none}.js .js-only{display:flex}[hidden]{display:none!important}.skip{position:absolute;left:-10000px}.skip:focus{left:10px;top:10px;background:var(--paper);padding:10px;z-index:10}
@media(max-width:900px){main{padding:0 18px}.port-preview{display:none}.port-labels,.port-row>summary{grid-template-columns:10px 75px 94px 100px minmax(80px,1fr);gap:7px}.script-count{display:none}.sections{gap:2px}.sections a{padding:6px 8px}.stats{gap:8px}.stat{padding:12px}.value{font-size:27px}}
@media(max-width:600px){body{font-size:12px}main{padding:0 12px}header{padding:13px 0}.brand{font-size:23px}h1{font-size:24px}.sections{position:static;margin-bottom:16px}.sections a{font-size:11px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.stat{padding:11px}.value{font-size:26px}.stat small{font-size:10px}.state-key{gap:8px}.toolbar{padding:9px;gap:8px}.toolbar input,.toolbar select,.host-toolbar input{font-size:16px}.search{flex-basis:100%}.section-head .actions{margin-left:0}.host>summary{padding:10px;gap:7px}.host-counts{margin-left:22px}.host-body{padding:8px}.host-identity{gap:5px}.port-labels{display:none}.port-row:first-of-type{border-top:1px solid var(--line);border-radius:5px 5px 0 0}.port-row>summary{grid-template-columns:8px 70px minmax(0,1fr) minmax(0,1fr);gap:6px;padding:8px 6px}.port-product{grid-column:3/5;font-size:10px}.port-detail{padding:8px}.port-row .badge{font-size:9px}.host-meta{gap:5px}.overview{padding:12px}.run-meta{gap:7px}.host-toolbar{flex-wrap:wrap}.host-toolbar input{min-width:0;width:100%}}
@media print{:root,:root[data-theme=dark]{color-scheme:light;--bg:#fff;--paper:#fff;--ink:#15243a;--muted:#52627a;--line:#cbd3df;--soft:#f2f5fa;--accent:#225dac;--green:#11633e;--green-bg:#e6f6ed;--amber:#805200;--amber-bg:#fff4db;--red:#a52a41;--red-bg:#fdebf0;--blue:#245db8;--blue-bg:#eaf1ff;--purple:#674397;--purple-bg:#f2ebff;--cyan:#087580;--cyan-bg:#e1f5f6}*{box-shadow:none!important}main{max-width:none;padding:0}body{background:white;font-size:10px}.sections,.actions,.toolbar,.pager,.js-only,.skip{display:none!important}.table-wrap{overflow:visible;border-radius:5px}.host{break-inside:auto}.host>summary,h2,h3{break-after:avoid}.port-row>summary{grid-template-columns:10px 70px 90px 100px minmax(60px,1fr) 50px}.script pre{max-height:none;overflow:visible;font-size:9px}pre{font-size:9px}a{color:inherit;text-decoration:none}tr{break-inside:avoid}thead{display:table-header-group}.stats{gap:7px}.stat{padding:8px}.value{font-size:23px}.service-chips{display:none}[data-page-hidden]{display:table-row!important}.port-detail{background:white}.port-preview{display:none}footer{font-size:9px}}
"""

JS = r"""
(() => {
'use strict';
document.documentElement.classList.add('js');
const table = document.getElementById('services');
const tbody = table.tBodies[0];
let rows = Array.from(tbody.rows), page = 0, direction = 1, sortKey = '';
const search = document.getElementById('search');
const state = document.getElementById('state');
const size = document.getElementById('page-size');
const previous = document.getElementById('previous');
const next = document.getElementById('next');
let matched = rows, serviceFilter = "";
function render() {
 const q = search.value.toLowerCase().trim();
 matched = rows.filter(r => (!serviceFilter || r.dataset.service === serviceFilter) && r.textContent.toLowerCase().includes(q) && (state.value === 'all' || r.dataset.state === state.value || r.dataset.evidence === state.value));
 const limit = Number(size.value), pages = Math.max(1, Math.ceil(matched.length / limit));
 page = Math.min(page, pages - 1);
 const visible = new Set(matched.slice(page * limit, (page + 1) * limit));
 const matching = new Set(matched);
 rows.forEach(r => {r.hidden = !visible.has(r); r.toggleAttribute('data-page-hidden', matching.has(r) && !visible.has(r));});
 previous.disabled = page === 0; next.disabled = page >= pages - 1;
 document.getElementById('row-count').textContent = matched.length + (matched.length === 1 ? ' observation · Page ' : ' observations · Page ') + (page + 1) + ' of ' + pages;
 document.getElementById('empty').hidden = matched.length !== 0;
}
[search, state, size].forEach(el => el.addEventListener(el === search ? 'input' : 'change', () => {page = 0; render();}));
previous.addEventListener('click', () => {page--; render();});next.addEventListener('click', () => {page++; render();});
function ipKey(address) {
 if (!address.includes(':')) return address.split('.').map(x => x.padStart(3,'0')).join('.');
 const sides = address.split('::');
 const left = sides[0] ? sides[0].split(':') : [];
 const right = sides.length > 1 && sides[1] ? sides[1].split(':') : [];
 return [...left, ...Array(Math.max(0, 8-left.length-right.length)).fill('0'), ...right].map(x => x.padStart(4,'0')).join(':');
}
table.querySelectorAll('[data-sort]').forEach(button => button.addEventListener('click', () => {
 const key = button.dataset.sort; direction = sortKey === key ? -direction : 1; sortKey = key;
 rows.sort((a,b) => direction * (key === 'port' ? Number(a.dataset.port)-Number(b.dataset.port) : ipKey(a.dataset.address).localeCompare(ipKey(b.dataset.address))));
 rows.forEach(r => tbody.appendChild(r));
 table.querySelectorAll('th').forEach(th => th.removeAttribute('aria-sort'));
 button.parentElement.setAttribute('aria-sort', direction === 1 ? 'ascending' : 'descending');
 page = 0; render();
}));
// Address links reveal the host without expanding every banner/script.
const hostElements = Array.from(document.querySelectorAll('#hosts .evidence-host'));
const hosts = new Map(hostElements.map(host => [host.dataset.hostAddress, host]));
rows.forEach(row => {const host = hosts.get(row.dataset.address); if(!host)return; const code = row.cells[0].querySelector('code'); if(!code)return; const link = document.createElement('a'); link.href='#'+host.id; code.replaceWith(link); link.appendChild(code); link.addEventListener('click',()=>{if(host.hidden){hostSearch.value='';filterHosts();}host.open=true;});});
document.getElementById('expand').addEventListener('click', () => document.querySelectorAll('#hosts details').forEach(d => d.open = true));
document.getElementById('collapse').addEventListener('click', () => document.querySelectorAll('#hosts details').forEach(d => d.open = false));
const hostSearch = document.getElementById('host-search');
function filterHosts() {
 const query = hostSearch.value.toLowerCase().trim();
 hostElements.forEach(host => host.hidden = !host.textContent.toLowerCase().includes(query));
 const count = hostElements.filter(host => !host.hidden).length;
 document.getElementById('host-count').textContent = count + ' of ' + hostElements.length + ' hosts';
 document.getElementById('hosts-empty').hidden = count !== 0;
}
hostSearch.addEventListener('input', filterHosts);
filterHosts();
const chips = Array.from(document.querySelectorAll('[data-service][aria-pressed]'));
function filterService(service) {
 serviceFilter = service; page = 0;
 chips.forEach(chip => chip.setAttribute('aria-pressed', String(chip.dataset.service === service)));
 const reset = document.getElementById('reset-service');
 if(reset)reset.setAttribute('aria-pressed', String(!service));
 render();
}
chips.forEach(chip => chip.addEventListener('click', () => {filterService(serviceFilter === chip.dataset.service ? '' : chip.dataset.service); document.getElementById('inventory').scrollIntoView({block:'start'});}));
const resetService = document.getElementById('reset-service');
if(resetService)resetService.addEventListener('click', () => filterService(''));
const themeButton = document.getElementById('theme');
const themePreference = matchMedia('(prefers-color-scheme: dark)');
let manualTheme = false;
function setTheme(dark) {
 document.documentElement.dataset.theme = dark ? 'dark' : 'light';
 const label = dark ? 'Switch to Light Theme' : 'Switch to Dark Theme';
 themeButton.setAttribute('aria-label', label); themeButton.title = label;
}
setTheme(themePreference.matches);
themeButton.addEventListener('click', () => {manualTheme = true; setTheme(document.documentElement.dataset.theme !== 'dark');});
themePreference.addEventListener('change', event => {if (!manualTheme) setTheme(event.matches);});
let printState = null;
window.addEventListener('beforeprint', () => {if(printState)return; printState=Array.from(document.querySelectorAll('details')).map(d=>[d,d.open]); printState.forEach(([d])=>d.open=true);});
window.addEventListener('afterprint', () => {if(printState)printState.forEach(([d,open])=>d.open=open);printState=null;});
document.getElementById('print').addEventListener('click', () => window.print());
function revealHash() {
 const target = document.getElementById(location.hash.slice(1));
 if (!target) return;
 if(hostElements.some(host=>host.contains(target)&&host.hidden)){hostSearch.value='';filterHosts();}
 for (let node=target; node; node=node.parentElement) {if(node.tagName === 'DETAILS'){node.open=true;node.hidden=false;}}
 target.scrollIntoView({block:'start'});
}
window.addEventListener('hashchange',revealHash);
if(location.hash)revealHash();
render();
})();
"""

def e(value):
    """Escape every dynamic value for HTML text and quoted attributes."""
    return escape(str(value), quote=True)


def tag(name, content='', **attrs):
    attributes = ''.join(f' {key.replace("_", "-")}="{e(value)}"' for key, value in attrs.items())
    return f'<{name}{attributes}>{content}</{name}>'


def notice(text):
    return tag('p', e(text), **{'class': 'notice'})


def script_html(script):
    def nested(element, depth=0):
        lines = []
        for child in element:
            if child.tag in ('table', 'elem'):
                lines.append('  ' * depth + child.get('key', '') + ': ' +
                             (''.join(child.itertext()) if child.tag == 'elem' else ''))
                if child.tag == 'table':
                    lines.extend(nested(child, depth + 1))
        return lines
    output = script.get('output') or '\n'.join(nested(script))
    return tag('details', tag('summary', e(script.get('id', ''))) + tag('pre', e(output)),
               **{'class': 'script'})


def state_class(state):
    return {'open': 'state-open', 'closed': 'state-closed',
            'filtered': 'state-filtered', 'open|filtered': 'state-uncertain',
            'closed|filtered': 'state-uncertain', 'unfiltered': 'state-uncertain',
            'completed': 'state-open', 'failed': 'state-error', 'interrupted': 'state-filtered',
            'running': 'state-running'}.get(state, 'state-neutral')


def state_badge(state):
    labels = {'open': 'Open', 'closed': 'Closed', 'filtered': 'Filtered',
              'open|filtered': 'Open | Filtered', 'closed|filtered': 'Closed | Filtered',
              'unfiltered': 'Unfiltered', 'completed': 'Completed', 'failed': 'Failed',
              'interrupted': 'Interrupted', 'running': 'Running', 'unknown': 'Unknown'}
    return tag('span', e(labels.get(state, state or 'Unknown')),
               **{'class': 'badge state ' + state_class(state)})


def service_class(name):
    name = name.lower()
    if name.startswith(('http', 'ssl/http')):
        return 'service-web'
    if name in ('ssh', 'telnet', 'ms-wbt-server', 'rdp', 'vnc', 'winrm'):
        return 'service-access'
    if name.startswith(('mysql', 'postgres', 'mongodb', 'redis', 'microsoft-ds', 'ms-sql', 'oracle')):
        return 'service-data'
    if name in ('domain', 'dns', 'snmp', 'ntp', 'ldap', 'ldaps', 'smtp', 'ftp', 'kerberos-sec'):
        return 'service-infra'
    return 'service-other'


def service_tag(name, tunnel=''):
    result = tag('span', e(name or 'unknown'), **{'class': 'service-tag ' + service_class(name)})
    if tunnel == 'ssl':
        result += tag('span', 'TLS', **{'class': 'tls'})
    return result


def host_html(host):
    address = next((a.get('addr', '') for a in host.findall('address')
                    if a.get('addrtype') in ('ipv4', 'ipv6')), '')
    ports = sorted(host.findall('ports/port'), key=lambda p: (p.get('protocol', ''), int(p.get('portid', 0))))
    opened = [p for p in ports if p.find('state') is not None and p.find('state').get('state') == 'open']
    uncertain = sum(p.find('state') is not None and p.find('state').get('state') in
                    ('filtered', 'open|filtered', 'closed|filtered', 'unfiltered') for p in ports)
    names = host.findall('hostnames/hostname')
    identity = tag('code', e(address))
    if names:
        identity += tag('span', e(names[0].get('name', '')), **{'class': 'hostname'})
    counts = tag('span', f'{len(opened)} Open', **{'class': 'badge state-open'})
    if uncertain:
        counts += tag('span', f'{uncertain} Uncertain', **{'class': 'badge state-uncertain'})
    preview = ''.join(tag('code', e(p.get('portid', '')) + '/' + e(p.get('protocol', ''))) for p in opened[:4])
    if len(opened) > 4:
        preview += tag('code', f'+{len(opened) - 4}')
    summary = tag('span', identity, **{'class': 'host-identity'})
    summary += tag('span', preview, **{'class': 'port-preview'})
    summary += tag('span', counts, **{'class': 'host-counts'})
    body = [tag('summary', summary), '<div class="host-body">']
    status = host.find('status')
    if status is not None:
        body.append(tag('div', 'Nmap Host State: ' + tag('strong', e(status.get('state', 'unknown'))) +
                        ' · ' + e(status.get('reason', '')), **{'class': 'host-meta'}))
    if ports:
        body.append('<div class="port-labels" aria-hidden="true"><span></span><span>Port</span><span>State</span><span>Service</span><span>Product / Version</span><span>Scripts</span></div>')
    for port in ports:
        state = port.find('state')
        service = port.find('service')
        state = state.attrib if state is not None else {}
        attrs = service.attrib if service is not None else {}
        scripts = port.findall('script')
        product = ' '.join(attrs.get(k, '') for k in ('product', 'version')).strip()
        row_summary = tag('span', e(port.get('portid', '')) + '/' + e(port.get('protocol', '')),
                          **{'class': 'port-number'})
        row_summary += state_badge(state.get('state', 'unknown'))
        row_summary += tag('span', service_tag(attrs.get('name', ''), attrs.get('tunnel', '')))
        row_summary += tag('span', e(product or '—'), **{'class': 'port-product'})
        row_summary += tag('span', f'{len(scripts)} NSE' if scripts else '—', **{'class': 'script-count'})
        facts = []
        for label, value in (('Reason', state.get('reason')), ('Detection', attrs.get('method')),
                             ('Confidence', attrs.get('conf')), ('Extra Info', attrs.get('extrainfo'))):
            if value:
                facts.append(tag('span', e(label) + ': ' + tag('strong', e(value))))
        content = tag('div', ''.join(facts), **{'class': 'facts'})
        if service is not None:
            content += ''.join(tag('p', tag('code', e(cpe.text or '')), **{'class': 'cpe'}) for cpe in service.findall('cpe'))
        content += ''.join(script_html(script) for script in scripts)
        if not facts and not scripts and (service is None or not service.findall('cpe')):
            content += tag('p', 'No additional evidence recorded.', **{'class': 'muted'})
        body.append(tag('details', tag('summary', row_summary) + tag('div', content, **{'class': 'port-detail'}),
                        id=f'port-{address}-{port.get("protocol", "")}-{port.get("portid", "")}',
                        **{'class': 'port-row'}))
    if not ports:
        body.append(tag('p', 'No individual port records. Review aggregated states and scan details.', **{'class': 'muted'}))
    host_scripts = host.findall('hostscript/script')
    if host_scripts:
        body.append(tag('h3', f'Host Scripts · {len(host_scripts)}'))
        body.extend(script_html(script) for script in host_scripts)
    extra = []
    for name in names:
        extra.append(tag('p', 'Hostname: ' + e(name.get('name', '')) + ' (' + e(name.get('type', '')) + ')'))
    for aggregated in host.findall('ports/extraports'):
        extra.append(tag('p', e(aggregated.get('count', '')) + ' additional ports: ' +
                         e(aggregated.get('state', '')) +
                         ' (aggregated by Nmap; individual port states are not reconstructed).'))
    for match in host.findall('os/osmatch'):
        extra.append(tag('p', 'OS Estimate: ' + e(match.get('name', '')) + ' · ' + e(match.get('accuracy', '')) + '% match'))
    if extra:
        body.append(tag('details', tag('summary', 'Host Metadata & Aggregated States') + ''.join(extra), **{'class': 'host-facts'}))
    body.append('</div>')
    return tag('details', ''.join(body), id='host-' + address, data_host_address=address,
               **{'class': 'host evidence-host'})


def overview_html(observations, confirmed):
    states = {}
    for row in observations:
        states[row['state']] = states.get(row['state'], 0) + 1
    summary = ', '.join(f'{name}: {count}' for name, count in sorted(states.items()))
    bar = ''.join(tag('span', '', style=f'flex-grow:{count}', title=f'{name}: {count}',
                      **{'class': state_class(name)}) for name, count in sorted(states.items()))
    legend = ''.join(tag('span', state_badge(name) + f' {count}') for name, count in sorted(states.items()))
    content = '<div class="overview-title"><span>Recorded Endpoint States</span><span>Explicit Records Only</span></div>'
    content += tag('div', bar, role='img', aria_label=summary or 'No endpoint observations', **{'class': 'state-bar'})
    content += tag('div', legend, **{'class': 'state-key'})
    services = {}
    for row in confirmed:
        name = row.get('service') or 'unknown'
        services[name] = services.get(name, 0) + 1
    if services:
        chips = []
        for name, count in sorted(services.items(), key=lambda item: (-item[1], item[0]))[:12]:
            chips.append(tag('button', e(name) + tag('b', str(count)), type='button', data_service=name,
                             aria_pressed='false', aria_label=f'Filter Service: {name}',
                             **{'class': 'service-tag ' + service_class(name)}))
        chips.append(tag('button', 'All Services', id='reset-service', type='button', aria_pressed='true'))
        content += tag('div', ''.join(chips), aria_label='Services Observed Open', **{'class': 'service-chips js-only'})
    return tag('div', content, **{'class': 'overview'})


def render_html(root, report):
    manifest = report.get('manifest')
    observations = report['observations']
    confirmed = [row for row in observations if row['evidence'] == 'confirmed-open']
    finished = root.find('runstats/finished')
    status = manifest['status'] if manifest else (
        'completed' if finished is not None and finished.get('exit') == 'success' else 'unknown')
    run_id = manifest['run_id'] if manifest else 'Imported Nmap Scan'
    scope = manifest['scope']['address_count'] if manifest else '—'
    diff = report.get('comparison')
    parts = ['''<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>MassMap Scan Report</title><style>''', CSS, '''</style></head><body>
<a class="skip" href="#summary">Skip to report</a><main>
<header><div class="brand">mass<span>map</span></div>
<div class="actions js-only"><button id="print" type="button">Print / PDF</button><button id="theme" type="button" aria-label="Switch to Dark Theme" title="Switch to Dark Theme"><svg class="sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/></svg><svg class="moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20.5 14A9 9 0 0 1 10 3.5 9 9 0 1 0 20.5 14Z"/></svg></button></div></header>
<h1>Network Scan Report</h1>''', tag('p', e(run_id) + ' · ' + e(report['generated']), **{'class': 'run-subtitle'}),
             '<div class="layout"><nav class="sections" aria-label="Report Sections">']
    links = [('summary', 'Summary'), ('inventory', 'Service Inventory'), ('hosts', 'Host Evidence')]
    if diff:
        links.append(('changes', 'Changes'))
    links += [('method', 'Method & Limits'), ('provenance', 'Scan Details')]
    parts.extend(tag('a', e(label), href='#' + anchor) for anchor, label in links)
    parts.append('</nav><div class="content"><section id="summary"><h2>Summary</h2><div class="stats">')
    for label, value, detail in (
        ('Discovery / Input Scope', scope, 'Target Addresses Before Scanning'),
        ('Hosts with Open Ports', len({r['address'] for r in confirmed}), 'Recorded by Nmap'),
        ('Confirmed Open Endpoints', len(confirmed), 'Host / Protocol / Port Tuples'),
        ('Uncertain Endpoints', sum(r['evidence'] != 'confirmed-open' and r['state'] != 'closed' for r in observations),
         'Filtered, Unconfirmed or Ambiguous')):
        parts.append(tag('div', tag('div', e(label), **{'class': 'label'}) +
                         tag('div', e(value), **{'class': 'value'}) + tag('small', e(detail)), **{'class': 'stat'}))
    totals = root.find('runstats/hosts')
    parts.append('</div>' + tag('div', state_badge(status) + tag('span', 'Nmap Targets: ' +
                               e(totals.get('total', '') if totals is not None else 'Unavailable')), **{'class': 'run-meta'}))
    if observations:
        parts.append(overview_html(observations, confirmed))
    warnings = list(manifest.get('warnings', [])) if manifest else [
        'Imported XML: original scope, discovery results and run provenance are unavailable.']
    if manifest and manifest.get('error'):
        warnings.append(manifest['error'])
    parts.extend(notice(warning) for warning in warnings)
    parts.append('''</section><section id="inventory"><div class="section-head"><div><h2>Service Inventory</h2><p>Endpoints, fingerprints and verification evidence.</p></div></div>
<div class="toolbar js-only"><label class="search">Search Address, Service or Product<input id="search" type="search" placeholder="Search Observations"></label>
<label>State<select id="state"><option value="all">All States</option><option value="open">Open</option><option value="not-confirmed">Not Confirmed</option><option value="open|filtered">Open | Filtered</option><option value="closed">Closed</option><option value="filtered">Filtered</option></select></label>
<label>Rows<select id="page-size"><option>25</option><option>50</option><option>100</option></select></label></div>
<div class="table-wrap"><table id="services"><thead><tr><th scope="col"><button data-sort="address" type="button">Host ↕</button></th><th scope="col"><button data-sort="port" type="button">Port ↕</button></th><th scope="col">Service / Product</th><th scope="col">State</th><th scope="col">Evidence</th></tr></thead><tbody>''')
    for row in observations:
        evidence = row['evidence']
        label = {'confirmed-open': 'Confirmed Open', 'not-confirmed': 'Not Confirmed'}.get(evidence, 'Recorded State')
        badge = tag('span', label, **{'class': 'badge ' + ('evidence-open' if evidence == 'confirmed-open' else 'evidence-unconfirmed' if evidence == 'not-confirmed' else '')})
        cells = [tag('code', e(row['address'])), tag('span', e(row['port']), **{'class': 'port-number'}) + tag('span', e(row['protocol']), **{'class': 'proto ' + row['protocol']}),
                 service_tag(row.get('service', ''), row.get('tunnel', '')) + tag('span', ' '.join(e(row.get(k, '')) for k in ('product', 'version')), **{'class': 'product'}),
                 state_badge(row['state']) + tag('span', e(row.get('reason', '')), **{'class': 'reason'}),
                 badge + '<br>' + tag('small', e(row.get('source', '')))]
        parts.append(tag('tr', ''.join(tag('td', cell) for cell in cells), data_address=row['address'],
                         data_port=row['port'], data_state=row['state'], data_evidence=evidence, data_service=row.get('service') or 'unknown'))
    parts.append('</tbody></table><p id="empty" class="empty" hidden>No matching observations.</p></div>')
    if not observations:
        parts.append('<p class="empty">No endpoint records. Check run status and coverage before interpreting this result.</p>')
    parts.append('''<div class="pager js-only"><button id="previous" type="button">Previous</button><span id="row-count" role="status" aria-live="polite"></span><button id="next" type="button">Next</button></div></section>
<section id="hosts"><div class="section-head"><div><h2>Host Evidence</h2><p>Expand a host, then a port to inspect banners and scripts.</p></div><div class="actions js-only"><button id="expand" type="button">Expand All Evidence</button><button id="collapse" type="button">Collapse All Evidence</button></div></div>
<div class="host-toolbar js-only"><input id="host-search" type="search" aria-label="Search Host Evidence" placeholder="Find a Host, Service or Script"><span id="host-count" role="status" aria-live="polite"></span></div><p id="hosts-empty" class="empty" hidden>No matching hosts.</p>''')
    parts.extend(host_html(host) for host in root.findall('host'))
    scripts = root.findall('prescript/script') + root.findall('postscript/script')
    if scripts:
        parts.append('<h3>Scan Scripts</h3>')
        parts.extend(script_html(script) for script in scripts)
    parts.append('</section>')
    if diff:
        parts.append('<section id="changes"><h2>Changes from Baseline</h2>')
        parts.extend(notice(warning) for warning in diff['warnings'] + [diff['note']])
        for row in diff['changes']:
            parts.append(tag('p', tag('span', e(row['change']), **{'class': 'badge'}) + ' ' +
                             tag('code', e(row['address'])) + ' · ' + e(row['port']) + '/' + e(row['protocol']) +
                             ' · ' + e(row.get('product', '')) + ' ' + e(row.get('version', ''))))
        if not diff['changes']:
            parts.append('<p>No endpoint or service changes observed.</p>')
        parts.append('</section>')
    parts.append('''<section id="method"><h2>Method &amp; Limits</h2><div class="method-copy">
<p>Open ports are observations, not confirmed vulnerabilities. Service names and versions are fingerprints, not proof of a vulnerability. A missing observation does not establish that a host is offline or a port is closed.</p>
<p class="muted">With <code>-Pn</code>, Nmap skips normal host discovery. “Up” may mean user-specified rather than a verified response. UDP <code>open|filtered</code> remains uncertain. Only explicit Nmap <code>open</code> records count as confirmed open.</p>
<p class="muted">This report preserves aggregated port states and script evidence. Discovery misses, timeouts, filtering, packet loss and differences in scope can affect coverage. Consult Scan Details and raw XML.</p></div></section>
<section id="provenance"><h2>Scan Details</h2><details class="host"><summary>Commands, Configuration and Run History</summary>''')
    parts.append(tag('pre', e(json.dumps(manifest, indent=2, ensure_ascii=False) if manifest else root.get('args', ''))))
    parts.append('''</details></section><footer>MassMap · Scan Report. All report assets are embedded; no network requests are made on load.</footer>
</div></div></main><script>''')
    parts += [JS, '</script></body></html>']
    return ''.join(parts)
