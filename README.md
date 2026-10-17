# PortSpy

A fast, dependency-free TCP port scanner written in Python. Scans ports in parallel, grabs service banners, and exports results to JSON.

Built as a learning project for networking and security.

> **Legal notice:** only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your country. `scanme.nmap.org` is a test target that the Nmap project allows you to scan.

## Features

- Multi-threaded scanning (200 threads by default)
- Banner grabbing, including `Server:` headers on common web ports
- Service name lookup for standard ports
- `--fast` mode for the most common ports
- JSON export for scripting and reports
- No dependencies, just the Python standard library
- Works on Windows, macOS and Linux

## Requirements

Python 3.8 or newer.

## Installation

    git clone https://github.com/EmilZagar1/portspy.git
    cd portspy

## Usage

    python portspy.py                                # scan localhost, ports 1-1024
    python portspy.py 192.168.1.1                    # scan your router
    python portspy.py scanme.nmap.org -p 22,80,443   # specific ports
    python portspy.py 192.168.1.10 -p 1-65535        # all ports
    python portspy.py 192.168.1.10 -F                # fast: common ports only
    python portspy.py 192.168.1.10 -o results.json   # save as JSON

### Options

| Option | Description | Default |
| --- | --- | --- |
| `target` | IP address or hostname | `127.0.0.1` |
| `-p`, `--ports` | Ports, e.g. `1-1024` or `22,80,443` | `1-1024` |
| `-F`, `--fast` | Scan only common ports | off |
| `-t`, `--timeout` | Connection timeout in seconds | `0.5` |
| `-w`, `--workers` | Parallel threads | `200` |
| `-o`, `--output` | Save results to a JSON file | none |
| `-V`, `--version` | Show version | |

## Example output

    PortSpy 0.2.0 - only scan systems you are allowed to test.
    Scanning 127.0.0.1 (127.0.0.1), 3 ports...

    PORT      STATE   SERVICE       BANNER
    2222/tcp  open    unknown       SSH-2.0-dropbear
    8000/tcp  open    unknown       SimpleHTTP/0.6 Python/3.12.3

    Done: 2 open port(s) in 0.0s.

## Roadmap

- [ ] UDP scanning
- [ ] Scan multiple targets and CIDR ranges
- [ ] Optional local AI summary of findings (via Ollama)
- [ ] Unit tests and GitHub Actions CI

## Contributing

Issues and pull requests are welcome.

## License

MIT. See [LICENSE](LICENSE).
