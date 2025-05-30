
# Port Scanner

A fast and configurable TCP port scanner written in C.

## Features

- Scan a range of TCP ports on a target IP address
- Configurable connection timeout per port
- Concurrency control with multithreading
- Verbose output to display open/closed ports
- Uses non-blocking sockets with `select` for efficient scanning

## Requirements

- GCC compiler
- POSIX compatible system (Linux, macOS)

## Build

```bash
gcc -o portscanner portscanner.c -pthread
```

## Usage

```bash
./portscanner -h <ip> -s <start_port> -e <end_port> -t <timeout_sec> -c <concurrency> -v
```

### Options

| Option     | Description                      | Default     |
|------------|---------------------------------|-------------|
| `-h`       | Target IP address                | `127.0.0.1` |
| `-s`       | Start port (1-65535)             | 1           |
| `-e`       | End port (1-65535)               | 1024        |
| `-t`       | Timeout per port in seconds      | 1           |
| `-c`       | Number of concurrent threads    | 50          |
| `-v`       | Verbose output (show open/closed ports) | Off |

### Example

Scan ports 1 to 1024 on 192.168.1.100 with 2 seconds timeout and 50 threads:

```bash
./portscanner -h 192.168.1.100 -s 1 -e 1024 -t 2 -c 50 -v
```

## Packaging

A Debian package is included (`oki-portscanner_1.0.deb`) for easy installation on Debian/Ubuntu:

```bash
sudo dpkg -i oki-portscanner_1.0.deb
```

## License

MIT License

---

Created by Lorenzo Orlando
