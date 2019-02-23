# MassMap
[![release](https://img.shields.io/github/release/capt-meelo/MassMap.svg?label=version&style=flat)](https://github.com/capt-meelo/MassMap/releases)
[![license](https://img.shields.io/github/license/capt-meelo/MassMap.svg?style=flat)](https://github.com/capt-meelo/MassMap/blob/master/LICENSE)
[![issues](https://img.shields.io/github/issues-raw/capt-meelo/MassMap.svg?style=flat)](https://github.com/capt-meelo/MassMap/issues?q=is:issue+is:open)

MassMap automates port scanning of large target IP addresses and/or CIDR notations by combining Masscan's speed, and Nmap's detailed scanning features. 


## How it Works
1. MassMap updates the machine, and then checks if it has the latest versions of Masscan and Nmap. If not, MassMap installs them.
2. Masscan then performs a scan on **all 65535 TCP ports** against the list of target IP addresses and/or CIDR notations. The results are stored in an HTML file under the `results` directory. 
3. Using the open ports identified by Masscan, an Nmap version and script scans gets executed against the hosts which have open ports. The results are also written in the `results` diretory. Two HTML files are created: one uses Nmap's default XLS stylesheet, while the other one uses [honze's bootstrap stylesheet](https://github.com/honze-net/nmap-bootstrap-xsl/).


## How to Use
```
git clone https://github.com/capt-meelo/MassMap.git
cd MassMap
chmod +x massmap.sh
./massmap.sh <target_file>
```

## Notes
- It's suggested to run this tool in a VPS, such as [DigitalOcean](https://www.digitalocean.com/?refcode=f7f86614e1b3), for better speed & accuracy.
- Running this tool takes time, thus it's recommended to run it under a **screen** or **tmux** session.
- By default, **Masscan** runs using the option `--rate 1000` for more accurate results (_I prefer accuracy over speed_). If you want **Masscan** to run faster, increase the `--rate` option.


## Contribute
If you identified an issue, or have a new idea, feel free to file an issue, or pull a request.


## Credits
Big thanks to the developers and contributors of [Masscan](https://github.com/robertdavidgraham/masscan) and [Nmap](https://nmap.org/).


## Disclaimer
This tool is written for educational purposes only. You are responsible for your own actions. If you mess something up or break any law while using this tool, it's your fault and your fault only.
