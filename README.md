# MassMap

MassMap combines **Masscan discovery** with **Nmap verification and service
detection**, then generates a self-contained HTML report, JSON, and CSV.

Based on my research:
[Finding the Balance Between Speed & Accuracy During an Internet-wide Port Scanning](https://captmeelo.com/pentest/research/2019/07/29/port-scanning.html).

## How It Works

1. Masscan scans the target IPv4 addresses/CIDRs for open TCP ports. By default,
   it scans ports **1–65535** with a configured rate of **100,000 packets/sec**.
2. MassMap collects the **union of discovered ports** and checks that same port
   list on **every discovered host** using Nmap SYN scanning and standard `-sV`
   service detection, with **T4** timing.
3. Results are reconciled and exported as HTML, JSON, and CSV.

For example, if Masscan finds port 22 on one host and 443 on another, Nmap checks
both ports on both hosts. This can recover ports missed by discovery on an
individual host. Hosts with no Masscan observations are not verified, and ports
absent from all discovery results are not added to the verification list.

All scans use this **Masscan → Nmap** workflow for **IPv4 TCP**. Existing
Nmap XML can also be imported for reporting without scanning.

## Platform Support

| Platform | Intended Use | Notes |
| --- | --- | --- |
| Linux VPS / dedicated Linux host | Primary deployment | Recommended for sustained scans. Provider policy, NIC limits, and network conditions still matter. |
| macOS, Intel or Apple Silicon | Native desktop use | Homebrew installation. Raw-packet capture depends on the active interface, routing, and VPN configuration. |
| WSL2 with a Linux distribution | Conditional desktop compatibility | Both scanners must work inside WSL2. NAT/mirrored mode, routing, and Windows/Hyper-V firewalls can affect raw packets. |
| Native Windows / WSL1 | Not supported | Use WSL2 or a Linux host. |

All scans require sudo/root for Masscan and Nmap SYN scanning. A VPS does not
guarantee accurate results. Before a large scan, verify a small known port list
against an authorized, reachable host on the machine and network you will use.
If raw-packet scanning does not work on a desktop, use a Linux VPS. MassMap does
not change firewall rules or networking configuration.

## Requirements and Installation

- **Python 3.11+** — standard library only; no pip packages or virtual environment required.
- **Masscan** and **Nmap**, including Nmap's normal service-probe data files.
- **Git** to clone the repository; downloading its ZIP from GitHub is an alternative.
- **sudo/root** for scanning. Keep MassMap unprivileged; it elevates scanner
  processes as needed. Report generation requires only Python.
- Optional: `tmux` or `screen` for long-running sessions.

Install dependencies using the block for your platform:

Check `python3 --version`; your distribution's default Python must be 3.11 or newer.

**Ubuntu / Debian / Kali**, including these distributions inside WSL2:

```bash
sudo apt-get update
sudo apt-get install git python3 nmap masscan
```

**Fedora:**

```bash
sudo dnf install git python3 nmap masscan
```

**Arch Linux**, with an up-to-date package database/system:

```bash
sudo pacman -S --needed git python nmap masscan
```

**macOS:** install [Homebrew](https://brew.sh) first, then run as your normal user:

```bash
brew install python nmap masscan
```

Download MassMap and check tool availability:

```bash
git clone https://github.com/capt-meelo/MassMap.git
cd MassMap
python3 massmap.py doctor
```

`doctor` shows the platform, tool paths/versions, and privilege requirements. It
does not install tools or test packet delivery. There is no setup script or HTML
conversion dependency.
Use `/path/to/python3 massmap.py ...` to select a Python interpreter explicitly.

On WSL2, install tools in the Linux distribution and keep output on the Linux
filesystem, such as `~/MassMap/results`, rather than `/mnt/c`. Run
`wsl --list --verbose` from Windows to confirm version 2.

## Quick Start

Create `targets.txt` with authorized IPv4 addresses or CIDRs, one per line:

```text
# Documentation examples — replace with your own authorized targets
192.0.2.10
192.0.2.16/28
```

Blank lines, `#` comments, UTF-8 BOMs, and Windows line endings are accepted.
Overlapping networks are normalized and deduplicated. Hostnames, Nmap range
expressions, scanner flags, and IPv6 addresses are not accepted as scan targets.

```bash
# Validate targets and preview discovery commands without scanning or writing output
python3 massmap.py scan targets.txt --dry-run

# Full Masscan → Nmap workflow
python3 massmap.py scan targets.txt

# Optional exclusions: first create exclude.txt with one IPv4 address/CIDR per line
python3 massmap.py scan targets.txt --exclude-file exclude.txt --dry-run

# Smaller port list and an explicit NEW output directory
python3 massmap.py scan targets.txt --ports 22,80,443 --output results/assessment

# Adjust discovery rate for your network
python3 massmap.py scan targets.txt --rate 10000
```

The addresses above are documentation examples. Replace them before scanning.
Use a known reachable host within your authorized scope to check the combined
workflow; Masscan is not a reliable loopback test.

## Commands and Options

```text
python3 massmap.py <command> [arguments] [options]
```

| Command | Purpose |
| --- | --- |
| `doctor` | Check the platform and required tools. |
| `scan` | Start the Masscan → Nmap workflow. |
| `resume` | Continue an existing run, skipping completed work. |
| `report` | Generate reports from a run directory or existing Nmap XML. |
| `benchmark` | Repeat the combined workflow at different discovery rates. |

Use `python3 massmap.py --help` for the command list,
`python3 massmap.py --version` for the current version, or
`python3 massmap.py <command> --help` for help on a command.
`-h` is an alias for `--help`. Uppercase names such as `TARGETS`,
`RUN_DIRECTORY`, and `SOURCE` are placeholders for your own files or directories.
Run the examples from the MassMap project directory; replace example paths with
existing inputs and choose unused output paths for new scans.

### Doctor

```bash
python3 massmap.py doctor
```

Reports the operating system, Python version, scanner paths/versions, and whether
sudo is required. Returns exit status 1 if Masscan or Nmap is missing. It does not
install tools, request sudo authorization, or test network connectivity.

| Option | Purpose |
| --- | --- |
| `-h`, `--help` | Show doctor usage. |

### Scan

```text
python3 massmap.py scan TARGETS [options]
```

```bash
python3 massmap.py scan targets.txt --ports 22,80,443 --output results/assessment
```

`TARGETS` is required: a UTF-8 file of authorized IPv4 addresses/CIDRs.

| Option | Default | Purpose |
| --- | --- | --- |
| `--exclude-file FILE` | None | Exclude IPv4 addresses/CIDRs listed in a file. |
| `--output DIRECTORY` | Unique directory under the project's `results/` | Save a new run. The directory must not already exist. |
| `--dry-run` | Off | Validate scope/options and preview discovery commands without scanning or writing output. Nmap commands are derived after discovery. |
| `--ports PORTS` | `1-65535` | TCP ports, as a comma-separated list and/or ranges, such as `22,80,443,8000-8100`. |
| `--rate N` | `100000` | Masscan packets/sec; positive integer. Benchmark the actual network before raising it. |
| `--wait SECONDS` | `10` | Masscan receive-wait period; minimum 1 second. |
| `--interface NAME` | Automatic | Select the network adapter for both scanners. |
| `-h`, `--help` | — | Show scan usage. |

Verification always checks the union of discovered ports on all discovered hosts,
using Nmap SYN scanning and standard service detection (`-sS -sV`). The rate and
T4 timing follow the original tool. Nmap runs one process at a time, with an
internal checkpoint size of 256 discovered addresses. Discovery uses one full
requested port list. MassMap leaves retry behavior to Masscan, without adding an
explicit retry count. The receive wait, resume integrity checks, and failure
handling are retained improvements; timings are not expected to reproduce the
2019 experiment exactly.

### Resume

```text
python3 massmap.py resume RUN_DIRECTORY
```

```bash
python3 massmap.py resume results/assessment
```

`RUN_DIRECTORY` is the required path to an existing run, such as
`results/assessment`, containing `manifest.json` and scanner artifacts. Completed jobs are verified and skipped; incomplete jobs
restart from their beginning. Scan settings come from the saved manifest and
cannot be overridden through this command.

| Option | Purpose |
| --- | --- |
| `-h`, `--help` | Show resume usage. |

### Report

```text
python3 massmap.py report SOURCE [--output DIRECTORY] [--baseline PATH]
```

```bash
# Regenerate a run's reports without scanning
python3 massmap.py report results/assessment

# Compare against a previous run
python3 massmap.py report results/assessment --baseline results/previous

# Import existing Nmap XML
python3 massmap.py report existing-nmap.xml --output results/imported
```

`SOURCE` is required: a MassMap run directory or an Nmap XML file. Generates
`report.html`, `report.json`, and `services.csv`, without running scanners.
For a run directory, these files are regenerated in place.

| Option | Default | Purpose |
| --- | --- | --- |
| `--output DIRECTORY` | Source run directory | Required for XML imports; choose a new or empty directory. Omit when reporting a run directory. |
| `--baseline PATH` | None | Compare with an earlier run directory or MassMap `report.json` file. |
| `-h`, `--help` | — | Show report usage. |

### Benchmark

```text
python3 massmap.py benchmark TARGETS --rates LIST [options]
```

```bash
# Preview the trial schedule without scanning
python3 massmap.py benchmark lab.txt --ports 22,80,443 --rates 1000,5000,10000 --repeats 2 --dry-run

# Run the trials
python3 massmap.py benchmark lab.txt --ports 22,80,443 --rates 1000,5000,10000 --repeats 2 --output results/bench
```

`TARGETS` is required and uses the same IPv4 target-file format as `scan`.
Each trial performs the complete Masscan → Nmap workflow.
All [scan options](#scan) are supported, with these additions and differences:

| Option | Default | Purpose |
| --- | --- | --- |
| `--rates LIST` | Required | Comma-separated positive Masscan rates. Up to 10 distinct rates. Overrides `--rate` for each trial. |
| `--repeats N` | `2` | Trials per rate, from 1 to 10. |
| `--output DIRECTORY` | Unique `results/benchmark-*` directory | Parent directory for all trials and `benchmark.json`; must not already exist. |
| `--dry-run` | Off | Show the trial schedule and a discovery-command template; each trial uses its listed rate. No scans or output files. |
| `-h`, `--help` | — | Show benchmark usage. |

Benchmarks perform real repeated scans. Start with a small, controlled scope.

## Progress, Cancellation, and Resume

In an interactive terminal, **Discovery** and **Service Detection** update one
line with progress, elapsed time, and ETA when available. Estimates apply to the
scanner's current phase. Periodic updates are omitted when output is redirected.

Press **Ctrl+C** to stop and save partial results, or press it again to stop
faster. Resume using the existing run directory:

```bash
python3 massmap.py resume results/assessment
```

Completed work is skipped; interrupted checkpoints restart. Keep the run directory
intact. Changed scanner versions/paths, saved inputs, or incompatible settings
require a fresh scan.

## Reports and Output

Open `report.html` in a browser, including offline. It includes searchable service
and host views, colored states, expandable evidence, theme switching, and Print/PDF.

| File | Contents |
| --- | --- |
| `report.html` | Interactive offline report |
| `report.json` | Observations and optional baseline changes |
| `services.csv` | Service inventory |

Scans also retain raw XML, logs, and metadata for troubleshooting and resume.
Use the [report command](#report) to regenerate reports, import Nmap XML, or compare
runs without scanning. Baseline differences do not prove a port opened or closed.
Clear report filters before printing all results.

## Benchmark Results

Each trial repeats the combined workflow and saves its own run and report.
`benchmark.json` records endpoint counts/sets, wall time, summed scanner time,
and intersection/union repeatability per rate. Trial order is randomized with a
recorded internal seed; seeds are managed automatically across repeats.
Repeatability is undefined (`null`) for an empty union or one trial.
Counts and repeatability are not ground-truth accuracy: compare against a known
service inventory and account for changes during the experiment.

A trial failure stops the benchmark. Resume that individual scan or start a new
benchmark; automatic benchmark continuation is not supported.

## Local Files

Keep output under `results/` (the default), which is ignored by Git, including
reports, logs, raw XML, and resume state. Root-level `targets.txt`, `exclude.txt`,
and `inputs/` are also ignored. Other filenames or output directories need their
own ignore rules to keep them out of commits.

## Credits

- [Masscan](https://github.com/robertdavidgraham/masscan) and [Nmap](https://nmap.org/).
