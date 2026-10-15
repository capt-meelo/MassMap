"""Command line interface and reproducible benchmark experiments."""
import argparse
import json
import os
import platform
import random
import uuid
import sys
import time
from pathlib import Path

from . import __version__
from .engine import (ROOT, ScanInterrupted, build_scope, dry_plan, platform_name, prepare_run, run,
                     run_lock, tool_version, validate_options)
from .model import MassMapError, atomic_json, endpoint_key, read_json
from .report import generate

DEFAULTS = {'ports': '1-65535', 'rate': 100000, 'wait': 10, 'interface': None}


def scan_arguments(parser):
    parser.add_argument('targets', help='UTF-8 file of IP addresses/CIDRs, one per line; # comments allowed')
    parser.add_argument('--exclude-file')
    parser.add_argument('--output', help='New run directory (must not already exist)')
    parser.add_argument('--dry-run', action='store_true', help='Validate and show plan without scanning or creating output')
    parser.add_argument('--ports')
    parser.add_argument('--rate', type=int, help='Masscan packets/sec (default 100000; benchmark your network)')
    parser.add_argument('--wait', type=int, help='Masscan receive grace period in seconds (default 10, minimum 1)')
    parser.add_argument('--interface')


def options_for(args):
    options = dict(DEFAULTS)
    for key in DEFAULTS:
        value = getattr(args, key, None)
        if value is not None:
            options[key] = value
    return validate_options(options)


def parser():
    app = argparse.ArgumentParser(description='MassMap: discovery, verification, reproducible offline reports')
    app.add_argument('--version', action='version', version=__version__)
    sub = app.add_subparsers(dest='action', required=True)
    scan_arguments(sub.add_parser('scan', help='Start a new scan'))
    resume = sub.add_parser('resume', help='Skip completed jobs; retry incomplete jobs from their beginning')
    resume.add_argument('run_directory')
    report = sub.add_parser('report', help='Regenerate a run report or import Nmap XML; never scans')
    report.add_argument('source', help='Run directory or Nmap XML file')
    report.add_argument('--output', help='Output directory (required for imported XML)')
    report.add_argument('--baseline', help='Previous run directory or report.json')
    sub.add_parser('doctor', help='Check platform and tooling without scanning')
    benchmark = sub.add_parser('benchmark', help='Repeat explicit scans at chosen rates and measure observed coverage')
    scan_arguments(benchmark)
    benchmark.add_argument('--rates', required=True, help='Comma-separated positive packet rates')
    benchmark.add_argument('--repeats', type=int, default=2)
    return app


def benchmark(args, options, target_scope):
    try:
        rates = sorted(set(int(x) for x in args.rates.split(',')))
    except ValueError as exc:
        raise MassMapError('--rates must contain positive integers') from exc
    if not rates or rates[0] < 1 or not 1 <= args.repeats <= 10 or len(rates) > 10:
        raise MassMapError('Use up to 10 positive rates and 1-10 repeats')
    schedule = [(rate, repeat) for rate in rates for repeat in range(args.repeats)]
    random.Random(options['seed']).shuffle(schedule)
    if args.dry_run:
        print(json.dumps({'schedule': schedule, 'plan': dry_plan(options, target_scope),
                          'note': 'Every trial repeats discovery and verification; no ground-truth accuracy claim.'}, indent=2))
        return
    destination = Path(args.output).resolve() if args.output else ROOT / 'results' / ('benchmark-' + uuid.uuid4().hex[:8])
    destination.mkdir(parents=True, exist_ok=False)
    summary = {'schema': 1, 'seed': options['seed'], 'schedule': schedule, 'trials': [],
               'note': 'Observed endpoint counts and repeatability are not ground-truth recall. Compare against a controlled reference scan.'}
    for index, (rate, repeat) in enumerate(schedule):
        trial_options = dict(options, rate=rate, seed=options['seed'] + repeat)
        trial = prepare_run(trial_options, target_scope, destination / f'trial-{index:03d}-rate-{rate}')
        atomic_json(destination / 'benchmark.json', summary)
        started = time.monotonic()
        try:
            run(trial)
        except MassMapError:
            summary['failed_trial'] = str(trial)
            atomic_json(destination / 'benchmark.json', summary)
            raise
        report = read_json(trial / 'report.json')
        manifest = read_json(trial / 'manifest.json')
        endpoints = [list(endpoint_key(r)) for r in report['observations'] if r['evidence'] == 'confirmed-open']
        summary['trials'].append({'directory': trial.name, 'rate': rate, 'repeat': repeat,
                                  'confirmed_open': len(endpoints), 'endpoints': endpoints,
                                  'wall_seconds': round(time.monotonic() - started, 3),
                                  'scanner_seconds': sum(a['elapsed_seconds'] for j in manifest['jobs'] for a in j['attempts']),
                                  'masscan_observed': sum(r['masscan_observed'] for r in report['observations'])})
        atomic_json(destination / 'benchmark.json', summary)
    by_rate = []
    for rate in rates:
        trials = [t for t in summary['trials'] if t['rate'] == rate]
        sets = [{tuple(e) for e in t['endpoints']} for t in trials]
        union, intersection = set.union(*sets), set.intersection(*sets)
        by_rate.append({'rate': rate, 'repeats': len(trials), 'observed_union': len(union),
                        'observed_intersection': len(intersection),
                        'repeatability': len(intersection) / len(union) if union and len(sets) > 1 else None})
    summary['by_rate'] = by_rate
    atomic_json(destination / 'benchmark.json', summary)
    print(f'Benchmark results: {destination / "benchmark.json"}')


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parser().parse_args(argv)
    try:
        if platform.system() not in ('Darwin', 'Linux'):
            raise MassMapError('Use Linux, macOS, or a Linux distribution inside WSL2 (not native Windows).')
        if args.action == 'doctor':
            tools = {name: tool_version(name) for name in ('python3', 'nmap', 'masscan')}
            print(json.dumps({'platform': platform_name(), 'python': sys.version.split()[0],
                              'tools': tools, 'raw_scan_privileges': 'root' if os.geteuid() == 0 else 'sudo required for raw scans',
                              'note': 'Tool presence does not validate packet delivery. Test a known reachable endpoint.'}, indent=2))
            needed = ('nmap', 'masscan')
            return int(any(not tools[n]['path'] for n in needed))
        if args.action in ('scan', 'benchmark'):
            options = options_for(args)
            target_scope = build_scope(args)
            if args.action == 'benchmark':
                benchmark(args, options, target_scope)
            elif args.dry_run:
                print(json.dumps(dry_plan(options, target_scope), indent=2))
            else:
                # Resolve dependencies before allocating a run directory.
                from .engine import binary
                for tool in ('nmap', 'masscan'):
                    binary(tool)
                directory = prepare_run(options, target_scope, args.output)
                print(f'Run directory: {directory}', flush=True)
                run(directory)
        elif args.action == 'resume':
            run(args.run_directory)
        else:
            source = Path(args.source).resolve()
            if source.is_dir():
                if args.output:
                    raise MassMapError('For a run directory, omit --output; reports are regenerated in that run.')
                from .engine import merge_nmap
                with run_lock(source):
                    manifest = read_json(source / 'manifest.json')
                    if not (source / 'nmap.xml').exists():
                        merge_nmap(source, manifest)
                    generate(source / 'nmap.xml', source, manifest=manifest, baseline=args.baseline)
                output = source
            else:
                if not args.output:
                    raise MassMapError('--output is required when importing XML')
                output = Path(args.output).resolve()
                if output.exists() and any(output.iterdir()):
                    raise MassMapError('Import output must be a new or empty directory')
                generate(source, output, baseline=args.baseline)
            print(f'Report: {output / "report.html"}')
        return 0
    except ScanInterrupted as exc:
        print(str(exc), file=sys.stderr)
        return 130
    except KeyboardInterrupt:
        print('Interrupted.', file=sys.stderr)
        return 130
    except (MassMapError, OSError, ValueError) as exc:
        print(f'MassMap: {exc}', file=sys.stderr)
        return 1
