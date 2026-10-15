"""Scanner execution, terminal progress and restartable, isolated runs."""
import concurrent.futures
import contextlib
import copy
import datetime as dt
import fcntl
import ipaddress
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
import unicodedata
import xml.etree.ElementTree as ET
from pathlib import Path

from . import __version__
from .model import (MassMapError, atomic_json, digest, discoveries,
                    port_spec, ports, read_json, scope, xml_root)

ROOT = Path(__file__).resolve().parent.parent
NMAP_CHECKPOINT_SIZE = 256
SCAN_SEED = 1


class ScanInterrupted(MassMapError):
    """A user-requested stop, with saved run state."""


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


def platform_name():
    if platform.system() == 'Linux' and 'microsoft' in platform.release().lower():
        return 'WSL2' if 'wsl2' in platform.release().lower() else 'WSL (check version 2)'
    return platform.system()


def binary(name, required=True):
    result = shutil.which(name)
    if not result:
        # sudo may have removed Homebrew from PATH. Resolve common native locations.
        for directory in ('/opt/homebrew/bin', '/usr/local/bin', '/usr/bin'):
            path = Path(directory) / name
            if path.is_file() and os.access(path, os.X_OK):
                result = str(path)
                break
    if not result and required:
        raise MassMapError(f'{name} is missing. See README installation instructions.')
    return str(Path(result).absolute()) if result else None


def tool_version(name):
    path = binary(name, required=False)
    if not path:
        return {'path': None, 'version': 'not installed'}
    try:
        run = subprocess.run([path, '--version'], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, timeout=10)
        lines = run.stdout.strip().splitlines()
        return {'path': path, 'version': lines[0] if lines else f'exit {run.returncode}'}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'path': path, 'version': str(exc)}


@contextlib.contextmanager
def run_lock(directory):
    with (Path(directory) / '.lock').open('a') as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MassMapError('This run is already in use by another MassMap process.') from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def validate_options(options, legacy=False):
    o = dict(options)
    if legacy:
        # Only migrate settings whose scan behavior matches the fixed workflow.
        retired = {'backend': 'masscan', 'family': 4, 'protocol': 'tcp', 'mode': 'union',
                   'scan_type': 'syn', 'version_intensity': 7, 'scripts': 'none',
                   'jobs': 1, 'discovery_batches': 1, 'batch_size': NMAP_CHECKPOINT_SIZE,
                   'timing': 4, 'host_timeout': None, 'nmap_max_rate': None}
        for key, expected in retired.items():
            if key in o and o.pop(key) != expected:
                raise MassMapError(f'This run uses a removed scan setting ({key}). Start a new scan; '
                                   'use the report command to view existing results.')
        o.pop('script_timeout', None)
        # Omitting a previously explicit retry setting could change traffic or
        # expose a system-config default. Do not silently mix those experiments.
        if 'retries' in o:
            raise MassMapError('This run used an explicit retry setting that is no longer supported. '
                               'Start a new scan; use the report command to view existing results.')
    if set(o) - {'ports', 'rate', 'wait', 'interface', 'seed'}:
        raise MassMapError('Unsupported saved scan options. Start a new scan.')
    o.setdefault('seed', SCAN_SEED)
    for key in ('rate', 'wait', 'seed'):
        if type(o[key]) is not int:
            raise MassMapError(f'{key} must be an integer')
    if o['rate'] < 1 or o['wait'] < 1 or o['seed'] < 0:
        raise MassMapError('Rate and wait must be positive; the scan seed must be nonnegative.')
    if not isinstance(o['ports'], str):
        raise MassMapError('Ports must be a string')
    o['ports'] = port_spec(ports(o['ports']))
    if o['interface'] is not None and (not isinstance(o['interface'], str) or not o['interface']
            or o['interface'].startswith('-') or any(c.isspace() for c in o['interface'])):
        raise MassMapError('Invalid network interface name')
    return o


def build_scope(args):
    return scope(args.targets, args.exclude_file, 4)


def prepare_run(options, target_scope, output=None):
    directory = Path(output).expanduser().absolute() if output else ROOT / 'results' / (
        dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    try:
        directory.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise MassMapError(f'Output directory already exists; use resume: {directory}') from exc
    (directory / 'targets.txt').write_text('\n'.join(target_scope['effective']) + '\n', encoding='utf-8')
    manifest = {'schema': 1, 'massmap_version': __version__, 'run_id': directory.name,
                'created': now(), 'updated': now(), 'status': 'pending',
                'platform': platform_name(), 'options': options, 'scope': target_scope,
                'checkpoint_size': NMAP_CHECKPOINT_SIZE, 'tools': {}, 'jobs': [], 'warnings': [], 'input_files': {'targets.txt': digest(directory / 'targets.txt')}}
    manifest['warnings'].append('Hosts with no Masscan observations do not receive Nmap verification.')
    if platform_name().startswith('WSL'):
        manifest['warnings'].append('WSL networking/firewalls may restrict raw packets; verify the combined scan on this network or use a Linux VPS.')
    default_config = Path('/etc/masscan/masscan.conf')
    if default_config.is_file():
        manifest['masscan_system_config_sha256'] = digest(default_config)
        manifest['warnings'].append('Masscan also reads /etc/masscan/masscan.conf; recorded its SHA-256.')
    atomic_json(directory / 'manifest.json', manifest)
    return directory


def make_job(kind, index, targets, port_list):
    return {'id': f'{kind}-{index:04d}', 'kind': kind, 'targets': targets,
            'ports': port_list, 'status': 'pending', 'attempts': []}


def discovery_jobs(options):
    return [make_job('masscan', 0, [], options['ports'])]


def verification_jobs(found):
    if not found:
        return []
    # Research workflow: check the union of discovered ports on every discovered host.
    port_list = port_spec(row['port'] for row in found)
    hosts = sorted({row['address'] for row in found}, key=ipaddress.ip_address)
    batch_size = NMAP_CHECKPOINT_SIZE
    return [make_job('nmap', index, hosts[start:start + batch_size], port_list)
            for index, start in enumerate(range(0, len(hosts), batch_size))]


def command(job, options, directory, output, resolve=True):
    kind = job['kind']
    exe = binary(kind) if resolve else kind
    target_path = directory / 'targets.txt' if kind == 'masscan' else directory / job['id'] / 'targets.txt'
    if kind == 'masscan':
        args = [exe, '-p', job['ports'], '--rate', str(options['rate']), '--wait', str(options['wait']),
                '--seed', str(options['seed']),
                '-iL', str(target_path), '-oX', str(output)]
        if options['interface']:
            args.extend(['-e', options['interface']])
    else:
        args = [exe, '-sS', '-sV', '--stats-every', '5s', '-Pn', '-n',
                '-T4', '-p', job['ports'],
                '-iL', str(target_path), '-oX', str(output)]
        if options['interface']:
            args.extend(['-e', options['interface']])
    return args


def authorize_tools():
    binary('nmap')
    binary('masscan')
    if os.geteuid() != 0:
        result = subprocess.run([binary('sudo'), '-v'])
        if result.returncode:
            raise MassMapError('Masscan and Nmap SYN scans require sudo/root privileges.')


def execute_job(job, options, directory, cancel, force=None):
    force = force if force is not None else threading.Event()
    work = directory / job['id']
    work.mkdir(exist_ok=True)
    if job['kind'] == 'nmap':
        (work / 'targets.txt').write_text('\n'.join(job['targets']) + '\n', encoding='utf-8')
    attempt = len(job['attempts'])
    # A hard kill can leave files before the result reached the manifest. Never
    # overwrite those artifacts or get stuck trying to recreate attempt zero.
    while (work / f'attempt-{attempt}.xml').exists() or (work / f'attempt-{attempt}.log').exists():
        attempt += 1
    output = work / f'attempt-{attempt}.xml'
    log = work / f'attempt-{attempt}.log'
    args = command(job, options, directory, output)
    using_sudo = os.geteuid() != 0
    if using_sudo:
        args = [binary('sudo'), '-n', '--'] + args
    result = {'started': now(), 'command': args, 'xml': str(output.relative_to(directory)),
              'log': str(log.relative_to(directory)), 'status': 'failed'}
    started = time.monotonic()
    try:
        # Precreate user-owned files before the privileged scanner opens them.
        output.touch(exist_ok=False)
        with log.open('w', encoding='utf-8') as stream:
            # Keep sudo in the authenticated terminal session so its timestamp
            # from sudo -v remains valid. sudo forwards signals to its child.
            proc = subprocess.Popen(args, cwd=work, stdout=stream, stderr=subprocess.STDOUT,
                                    start_new_session=not using_sudo)
            def signal_scanner(sig):
                try:
                    if using_sudo:
                        # sudo forwards catchable signals to its privileged child.
                        # Never SIGKILL the supervisor: that could orphan the scanner.
                        proc.send_signal(sig)
                    else:
                        os.killpg(proc.pid, sig)
                except ProcessLookupError:
                    pass  # Exiting between poll and signal delivery is normal.
            sent = None
            repeated_int = False
            terminated = None
            while proc.poll() is None:
                if cancel.is_set():
                    current = time.monotonic()
                    if sent is None:
                        signal_scanner(signal.SIGINT)
                        sent = current
                    elif not repeated_int and (force.is_set() or current - sent >= 1):
                        # Masscan's second interrupt skips its receive-wait period.
                        signal_scanner(signal.SIGINT)
                        repeated_int = True
                    elif terminated is None and (current - sent >= 3 or
                                                  (force.is_set() and repeated_int)):
                        signal_scanner(signal.SIGTERM)
                        terminated = current
                    elif terminated is not None and current - terminated >= 2:
                        signal_scanner(signal.SIGTERM if using_sudo else signal.SIGKILL)
                        terminated = current
                time.sleep(0.1)
            if cancel.is_set() and not using_sudo:
                # A scanner may exit before children it created have stopped.
                signal_scanner(signal.SIGKILL)
            result['exit_code'] = proc.returncode
        if cancel.is_set():
            result['status'] = 'interrupted'
        elif proc.returncode:
            result['error'] = f'{job["id"]} exited {proc.returncode}; see {log}'
        else:
            if job['kind'] == 'masscan':
                discoveries([output], (directory / 'targets.txt').read_text(encoding='utf-8').splitlines(),
                            ports(job['ports']))
            else:
                xml_root(output, require_finished=True)
            result.update(status='completed', sha256=digest(output))
    except (OSError, MassMapError) as exc:
        result['error'] = str(exc)
        if cancel.is_set():
            result['status'] = 'interrupted'
    result.update(finished=now(), elapsed_seconds=round(time.monotonic() - started, 3))
    return result


def save_manifest(directory, manifest):
    manifest['updated'] = now()
    atomic_json(directory / 'manifest.json', manifest)


def stage_name(kind):
    return 'Discovery' if kind == 'masscan' else 'Service Detection'


def progress_line(directory, job, elapsed, label=None):
    """Read a bounded log tail, including Masscan's carriage-return updates."""
    work = Path(directory) / job['id']
    logs = list(work.glob('attempt-*.log'))
    status = ''
    if logs:
        # Attempts are numbered; modification times can tie on fast filesystems.
        latest = max(logs, key=lambda path: int(path.stem.split('-')[-1]))
        try:
            with latest.open('rb') as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                stream.seek(max(0, size - 8192))
                tail = stream.read(8192).decode('utf-8', errors='replace')
            for line in reversed(re.split(r'[\r\n]', tail)):
                if re.search(r'\d+(?:\.\d+)?%|^Stats:|waiting', line, re.I):
                    # Scanner text is untrusted: strip terminal control sequences.
                    status = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', line)
                    status = ''.join(c for c in status if c.isprintable()).strip()[:220]
                    break
        except OSError:
            pass  # The worker may not have created its log yet.
    match = re.search(r'(\d+(?:\.\d+)?)%', status)
    if match:
        percent = min(100.0, max(0.0, float(match.group(1))))
        filled = int(percent / 10)
        bar = '[' + '#' * filled + '-' * (10 - filled) + f'] {percent:.1f}%'
    else:
        bar = '[Running]'
    seconds = int(elapsed)
    duration = f'{seconds // 3600:02d}:{seconds // 60 % 60:02d}:{seconds % 60:02d}'
    label = label or stage_name(job['kind'])
    parts = [f'{label} {bar}', f'{duration} Elapsed']
    remaining = re.search(r'(\d+:\d+(?::\d+)?)\s+remaining', status, re.I)
    parts.append('ETA ' + (remaining.group(1) if remaining else 'Unknown'))
    phase = re.search(r'^(.+?) Timing:', status)
    if phase:
        parts.append(phase.group(1).strip())
    rate = re.search(r'rate:\s*([\d.]+)-kpps', status, re.I)
    if rate:
        parts.append(rate.group(1) + ' kpps')
    found = re.search(r'found=(\d+)', status)
    if found:
        parts.append(found.group(1) + ' Found')
    return ' | '.join(parts)



class ProgressDisplay:
    """One replaceable terminal row; redirected output keeps only durable messages."""
    def __init__(self, stream=None):
        self.stream = stream if stream is not None else sys.stdout
        self.interactive = self.stream.isatty() and os.environ.get('TERM') != 'dumb'
        self.visible = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.clear()

    def clear(self):
        if self.visible:
            self.stream.write('\r\x1b[2K')
            self.stream.flush()
            self.visible = False

    def message(self, text):
        self.clear()
        print(text, file=self.stream, flush=True)

    def update(self, text):
        if not self.interactive:
            return
        try:
            columns = os.get_terminal_size(self.stream.fileno()).columns
        except (OSError, ValueError):
            columns = shutil.get_terminal_size(fallback=(80, 24)).columns
        # Leave the last cell unused so terminals never auto-wrap the status row.
        clipped, width = [], 0
        for char in text:
            cells = 0 if unicodedata.combining(char) else (2 if unicodedata.east_asian_width(char) in 'WF' else 1)
            if width + cells > max(0, columns - 1):
                break
            clipped.append(char)
            width += cells
        self.stream.write('\r\x1b[2K' + ''.join(clipped))
        self.stream.flush()
        self.visible = True


def run_jobs(directory, manifest, kind, cancel, force=None):
    options = manifest['options']
    pending = [j for j in manifest['jobs'] if j['kind'] == kind and j['status'] != 'completed']
    last_refresh = time.monotonic()
    last_progress = last_refresh
    started_jobs = {}
    stop_announced = False
    force_announced = False
    stage = [j for j in manifest['jobs'] if j['kind'] == kind]
    name = stage_name(kind)
    labels = {job['id']: name + (f' ({index + 1} of {len(stage)})' if len(stage) > 1 else '')
              for index, job in enumerate(stage)}
    completed_count = len(stage) - len(pending)
    if stage and not pending:
        print(f'{name}: Already Completed', flush=True)
    elif completed_count:
        print(f'{name}: Resuming ({completed_count} of {len(stage)} Completed)', flush=True)
    with ProgressDisplay() as progress, concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        active = {}
        while pending or active:
            if cancel.is_set() and not stop_announced:
                progress.message('Stopping scanners; saving run state. Press Ctrl+C again to stop faster.')
                stop_announced = True
            if force is not None and force.is_set() and not force_announced:
                progress.message('Stopping remaining scanners now…')
                force_announced = True
            # Long scans can outlive sudo's normal timestamp. Renew only an
            # already-valid credential, never prompt inside a worker or log.
            if os.geteuid() != 0 and time.monotonic() - last_refresh > 60:
                try:
                    subprocess.run([binary('sudo'), '-n', '-v'], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                except subprocess.TimeoutExpired:
                    pass  # A later scanner invocation will fail visibly if authorization expired.
                last_refresh = time.monotonic()
            while pending and not active and not cancel.is_set():
                job = pending.pop(0)
                job['status'] = 'running'
                save_manifest(directory, manifest)
                progress.message(f'{labels[job["id"]]}: Starting')
                started_jobs[job['id']] = time.monotonic()
                active[pool.submit(execute_job, job, options, directory, cancel, force)] = job
            if not active:
                break
            done, _ = concurrent.futures.wait(active, timeout=0.2,
                                               return_when=concurrent.futures.FIRST_COMPLETED)
            current = time.monotonic()
            if not cancel.is_set() and current - last_progress >= 5:
                job = next(iter(active.values()))
                progress.update(progress_line(directory, job, current - started_jobs[job['id']], labels[job['id']]))
                last_progress = current
            for future in done:
                job = active.pop(future)
                result = future.result()
                job['attempts'].append(result)
                job['status'] = result['status']
                progress.message(f'{labels[job["id"]]}: {result["status"].capitalize()} '
                                 f'in {result["elapsed_seconds"]:.1f}s')
                save_manifest(directory, manifest)
                if result['status'] == 'failed':
                    cancel.set()
    if any(j['status'] != 'completed' for j in manifest['jobs'] if j['kind'] == kind):
        raise MassMapError(f'{name} incomplete. See manifest/logs, then run: python3 massmap.py resume {shlex.quote(str(directory))}')


def completed_paths(directory, manifest, kind):
    return [directory / j['attempts'][-1]['xml'] for j in manifest['jobs']
            if j['kind'] == kind and j['status'] == 'completed']


def merge_nmap(directory, manifest):
    root = ET.Element('nmaprun', scanner='nmap', version=manifest.get('tools', {}).get('nmap', {}).get('version', 'unavailable'),
                      args='See manifest.json for per-job arguments', startstr=manifest['created'])
    counts = {'up': 0, 'down': 0, 'total': 0}
    for path in completed_paths(directory, manifest, 'nmap'):
        source = xml_root(path, require_finished=True)
        root.set('version', source.get('version', root.get('version')))
        for host in source.findall('host'):
            root.append(copy.deepcopy(host))
        for tag in ('prescript', 'postscript', 'scaninfo'):
            for item in source.findall(tag):
                root.append(copy.deepcopy(item))
        stats = source.find('runstats/hosts')
        if stats is not None:
            for key in counts:
                counts[key] += int(stats.get(key, '0'))
    stats = ET.SubElement(root, 'runstats')
    ET.SubElement(stats, 'hosts', {k: str(v) for k, v in counts.items()})
    ET.SubElement(stats, 'finished', exit='success' if manifest['status'] == 'completed' else 'error',
                  timestr=now(), summary=manifest['status'])
    ET.ElementTree(root).write(directory / 'nmap.xml', encoding='utf-8', xml_declaration=True)
    return root


def run(directory):
    directory = Path(directory).resolve()
    with run_lock(directory):
        manifest = read_json(directory / 'manifest.json')
        if manifest.get('schema') != 1:
            raise MassMapError('Unsupported run manifest schema')
        if manifest.get('checkpoint_size', NMAP_CHECKPOINT_SIZE) != NMAP_CHECKPOINT_SIZE:
            raise MassMapError('Checkpoint settings changed. Start a new scan.')
        options = validate_options(manifest['options'], legacy=True)
        manifest['options'] = options
        # Refuse changed inputs or completed results rather than silently mixing scans.
        for name, expected in manifest['input_files'].items():
            if digest(directory / name) != expected:
                raise MassMapError(f'Run input changed: {name}')
        for job in manifest['jobs']:
            if job['status'] == 'completed':
                attempt = job['attempts'][-1]
                if digest(directory / attempt['xml']) != attempt['sha256']:
                    raise MassMapError(f'Completed result changed: {attempt["xml"]}')
        default_config = Path('/etc/masscan/masscan.conf')
        current_config = digest(default_config) if default_config.is_file() else None
        if current_config != manifest.get('masscan_system_config_sha256'):
            raise MassMapError('Masscan system configuration changed. Start a fresh run.')
        authorize_tools()
        versions = {name: tool_version(name) for name in ('nmap', 'masscan')}
        if manifest['tools'] and manifest['tools'] != versions:
            raise MassMapError('Tool versions/paths changed. Start a fresh run to avoid mixing environments.')
        manifest['tools'] = versions
        manifest['status'] = 'running'
        manifest.pop('error', None)
        cancel = threading.Event()
        interrupted = threading.Event()
        force = threading.Event()
        def stop(signum, frame):
            if interrupted.is_set():
                force.set()
            interrupted.set()
            cancel.set()
        previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
        save_manifest(directory, manifest)
        try:
            if not any(j['kind'] == 'masscan' for j in manifest['jobs']):
                manifest['jobs'].extend(discovery_jobs(options))
            run_jobs(directory, manifest, 'masscan', cancel, force)
            found = discoveries(completed_paths(directory, manifest, 'masscan'),
                                manifest['scope']['effective'], ports(options['ports']))
            atomic_json(directory / 'discovery.json', found)
            if not any(j['kind'] == 'nmap' for j in manifest['jobs']):
                manifest['jobs'].extend(verification_jobs(found))
            save_manifest(directory, manifest)
            run_jobs(directory, manifest, 'nmap', cancel, force)
            if interrupted.is_set():
                raise MassMapError('Run interrupted')
            manifest['status'] = 'completed'
        except (MassMapError, OSError) as exc:
            manifest['status'] = 'interrupted' if interrupted.is_set() else 'failed'
            manifest['error'] = str(exc)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
            save_manifest(directory, manifest)
        # Include all completed discovery batches even when a later batch failed.
        try:
            atomic_json(directory / 'discovery.json', discoveries(
                completed_paths(directory, manifest, 'masscan'),
                manifest['scope']['effective'], ports(options['ports'])))
        except MassMapError as exc:
            manifest['warnings'].append(f'Discovery evidence could not be loaded: {exc}')
            save_manifest(directory, manifest)
        merge_nmap(directory, manifest)
        from .report import generate
        print('Generating HTML, JSON and CSV reports…', flush=True)
        try:
            manifest.pop('report_error', None)
            save_manifest(directory, manifest)
            generate(directory / 'nmap.xml', directory, manifest=manifest)
        except (MassMapError, OSError) as exc:
            manifest['report_error'] = str(exc)
            save_manifest(directory, manifest)
            raise
        print(f'Report: {directory / "report.html"}', flush=True)
        if manifest['status'] == 'interrupted':
            raise ScanInterrupted(f'Run interrupted. Resume with: python3 massmap.py resume {shlex.quote(str(directory))}')
        if manifest['status'] != 'completed':
            raise MassMapError(manifest.get('error', 'Run incomplete'))
    return directory


def dry_plan(options, target_scope):
    directory = Path('/RUN')
    jobs = discovery_jobs(options)
    return {'options': options, 'scope': target_scope,
            'initial_commands': [command(j, options, directory, directory / j['id'] / 'attempt-0.xml', resolve=False) for j in jobs],
            'verification': 'Union of discovered ports on every discovered host; Nmap SYN scan with standard service detection',
            'discovery_probe_count': target_scope['address_count'] * len(ports(options['ports'])),
            'note': 'No scanners executed. Privileged commands use sudo when needed.'}
