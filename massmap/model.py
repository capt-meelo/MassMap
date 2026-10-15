"""Validated scopes and structured scanner output. No network activity here."""
import hashlib
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path


class MassMapError(Exception):
    pass


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def atomic_json(path, data):
    path = Path(path)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    temp.replace(path)


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise MassMapError(f'Cannot read {path}: {exc}') from exc


def ports(value):
    result = set()
    for token in value.split(','):
        if not re.fullmatch(r'\d+(?:-\d+)?', token):
            raise MassMapError('Ports must be a comma-separated list of numbers/ranges (1-65535).')
        lo, _, hi = token.partition('-')
        lo, hi = int(lo), int(hi or lo)
        if not 1 <= lo <= hi <= 65535:
            raise MassMapError(f'Invalid port range: {token}')
        result.update(range(lo, hi + 1))
    return sorted(result)


def port_spec(values):
    values = sorted(set(values))
    groups = []
    start = end = None
    for value in values:
        if end is not None and value == end + 1:
            end = value
        else:
            if start is not None:
                groups.append(str(start) if start == end else f'{start}-{end}')
            start = end = value
    if start is not None:
        groups.append(str(start) if start == end else f'{start}-{end}')
    return ','.join(groups)


def read_networks(path, family):
    networks = []
    try:
        lines = Path(path).read_text(encoding='utf-8-sig').splitlines()
    except OSError as exc:
        raise MassMapError(f'Cannot read target file {path}: {exc}') from exc
    for line, value in enumerate(lines, 1):
        value = value.split('#', 1)[0].strip()
        if not value:
            continue
        try:
            if '%' in value:
                raise ValueError('scoped IPv6 addresses are not supported')
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise MassMapError(f'{path}:{line}: expected an IP address or CIDR: {value}') from exc
        if network.version != family:
            raise MassMapError(f'{path}:{line}: address family differs from --family {family}')
        if family == 6 and network.prefixlen != 128:
            raise MassMapError(f'{path}:{line}: IPv6 requires individual addresses (/128)')
        networks.append(network)
    if family == 6:
        return sorted(set(networks), key=lambda n: int(n.network_address))
    return list(ipaddress.collapse_addresses(networks))


def scope(target_file, exclude_file, family):
    original = read_networks(target_file, family)
    if not original:
        raise MassMapError('The target file contains no addresses.')
    excluded = read_networks(exclude_file, family) if exclude_file else []
    effective = original[:]
    for exclusion in excluded:
        remaining = []
        for network in effective:
            if network.subnet_of(exclusion):
                continue
            if exclusion.subnet_of(network):
                remaining.extend(network.address_exclude(exclusion))
            else:
                remaining.append(network)
        effective = remaining
    effective = sorted(set(effective) if family == 6 else ipaddress.collapse_addresses(effective),
                       key=lambda n: int(n.network_address))
    if not effective:
        raise MassMapError('Exclusions remove the entire target scope.')
    return {
        'requested': [str(n) for n in original],
        'excluded': [str(n) for n in excluded],
        'effective': [str(n) for n in effective],
        'address_count': sum(n.num_addresses for n in effective),
        'input_sha256': digest(target_file),
        'exclusions_sha256': digest(exclude_file) if exclude_file else None,
    }


def guard_xml(path):
    # Permit Nmap's simple external DOCTYPE declaration, but never entity declarations
    # or internal DTD subsets. ElementTree does not fetch external DTDs.
    tail = b''
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            sample = tail + chunk
            if b'\x00' in sample or re.search(br'<!ENTITY|<!DOCTYPE[^>]*\[', sample, re.I):
                raise MassMapError(f'Unsafe XML declarations or encoding: {path}')
            tail = sample[-4096:]


def xml_root(path, require_finished=False):
    try:
        guard_xml(path)
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise MassMapError(f'Invalid or incomplete XML in {path}: {exc}') from exc
    if root.tag != 'nmaprun':
        raise MassMapError(f'Expected nmaprun XML in {path}')
    if require_finished:
        finished = root.find('runstats/finished')
        if finished is None or finished.get('exit', 'success') != 'success':
            raise MassMapError(f'Scanner did not finish successfully: {path}')
    return root


def host_address(host):
    for address in host.findall('address'):
        if address.get('addrtype') in ('ipv4', 'ipv6'):
            try:
                return str(ipaddress.ip_address(address.get('addr', '')))
            except ValueError as exc:
                raise MassMapError('Invalid IP address in scanner XML') from exc
    raise MassMapError('Host has no IP address in scanner XML')


def endpoint_key(row):
    return row['address'], row['protocol'], int(row['port'])


def row_sort(row):
    return (ipaddress.ip_address(row['address']).version,
            int(ipaddress.ip_address(row['address'])), row['protocol'], int(row['port']))


def records(root):
    result = {}
    for host in root.findall('host'):
        address = host_address(host)
        for port in host.findall('ports/port'):
            proto = port.get('protocol', '')
            try:
                number = int(port.get('portid', ''))
            except ValueError as exc:
                raise MassMapError('Invalid port in scanner XML') from exc
            if proto not in ('tcp', 'udp', 'sctp') or not 0 <= number <= 65535:
                raise MassMapError('Invalid endpoint in scanner XML')
            state = port.find('state')
            service = port.find('service')
            row = {
                'address': address, 'protocol': proto, 'port': number,
                'state': state.get('state', 'unknown') if state is not None else 'unknown',
                'reason': state.get('reason', '') if state is not None else '',
                'service': service.get('name', '') if service is not None else '',
                'product': service.get('product', '') if service is not None else '',
                'version': service.get('version', '') if service is not None else '',
                'tunnel': service.get('tunnel', '') if service is not None else '',
                'cpes': [e.text or '' for e in port.findall('service/cpe')],
            }
            result[endpoint_key(row)] = row
    return sorted(result.values(), key=row_sort)


def discoveries(paths, networks, allowed_ports):
    found = {}
    allowed = set(allowed_ports)
    scope_networks = [ipaddress.ip_network(n) for n in networks]
    for path in paths:
        # Masscan writes one host element per observation. Streaming avoids retaining
        # the full discovery XML; the result is deduplicated by endpoint tuple.
        try:
            guard_xml(path)
            root = None
            finished = False
            for event, element in ET.iterparse(path, events=('start', 'end')):
                if root is None:
                    root = element
                    if root.tag != 'nmaprun':
                        raise MassMapError(f'Expected nmaprun XML in {path}')
                if event == 'end' and element.tag == 'host':
                    wrapper = ET.Element('nmaprun')
                    wrapper.append(element)
                    for row in records(wrapper):
                        ip = ipaddress.ip_address(row['address'])
                        if (row['protocol'] != 'tcp' or row['port'] not in allowed
                                or not any(ip in n for n in scope_networks)):
                            raise MassMapError(f'Out-of-scope discovery in {path}: {row["address"]}:{row["port"]}')
                        if row['state'] == 'open':
                            found[endpoint_key(row)] = row
                    root.remove(element)
                elif event == 'end' and element.tag == 'finished':
                    finished = element.get('exit', 'success') == 'success'
            if not finished:
                raise MassMapError(f'Incomplete discovery XML: {path}')
        except (ET.ParseError, OSError) as exc:
            raise MassMapError(f'Invalid discovery XML: {path}: {exc}') from exc
    return sorted(found.values(), key=row_sort)


def reconcile(discovery, verification):
    observed = {endpoint_key(r): r for r in discovery}
    checked = {endpoint_key(r): r for r in verification}
    output = []
    for key in observed.keys() | checked.keys():
        row = dict(checked.get(key, observed.get(key)))
        row['masscan_observed'] = key in observed
        row['nmap_recorded'] = key in checked
        if key not in checked:
            row.update(state='unknown', reason='No explicit Nmap port record', evidence='not-confirmed')
        elif row['state'] == 'open':
            row['evidence'] = 'confirmed-open'
        elif key in observed:
            row['evidence'] = 'not-confirmed'
        else:
            row['evidence'] = 'other-state'
        row['source'] = 'masscan+nmap' if key in observed and key in checked else ('nmap' if key in checked else 'masscan')
        output.append(row)
    return sorted(output, key=row_sort)
