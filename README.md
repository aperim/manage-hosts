# Manage Hosts

A robust, concurrent Python application for managing and controlling hosts, PDUs (Power Distribution Units), UPSes (Uninterruptible Power Supplies), routers, switches, firewalls, and more. It supports tag-based filtering, dependency ordering (depth-based), SSH command execution, and network pings. This project is hosted on GitHub at:  
<https://github.com/aperim/manage-hosts>

---

• Author: Troy Kelly  
• Company: Aperim Pty Ltd  
• Date: 18 Jan 2025  
• License: Apache 2.0  

---

## Table of Contents

1. [Overview](#overview)  
2. [Features](#features)  
3. [Installation & Requirements](#installation--requirements)  
4. [Usage](#usage)  
5. [Filter Syntax](#filter-syntax)  
6. [Examples](#examples)  
    - [Basic Checks](#basic-checks)  
    - [Shutdown/Reboot with Default Logic](#shutdownreboot-with-default-logic)  
    - [Command Execution](#command-execution)  
    - [Tag-Based Filtering](#tag-based-filtering)  
    - [Device Type Filtering](#device-type-filtering)  
    - [Combined Examples](#combined-examples)  
    - [Run From a Remote Host (Pipe Method)](#run-from-a-remote-host-pipe-method)  
7. [Configuration File (YAML) Example](#configuration-file-yaml-example)  
8. [Advanced Usage & Environment Variables](#advanced-usage--environment-variables)  
9. [License](#license)  
10. [Contact & Contributing](#contact--contributing)  

---

## Overview

Manage Hosts is a standalone Python 3.9+ script designed to orchestrate and manage diverse endpoints (servers, PDUs, UPSes, routers, switches, firewalls, storage devices) within a hybrid infrastructure. It supports:

• Loading of inline or file-based SSH keys for multiple credentials.  
• Ordered operations, ensuring child dependencies are handled first.  
• Threaded execution, controlling concurrency.  
• Flexible filtering by tags and device type.  
• Actions including ping checks, SSH checks, command execution, system shutdown, and system reboot.  

---

## Features

1. **Dependency Ordering**:  
   Endpoints define dependencies (hosts, UPS, PDU), so the script can operate in correct order: leaf nodes first, then their parents, etc.

2. **Filtering**:  
   The script supports multiple filters like 'location==dc1', 'floor>=3', or 'type is router'. Comparisons can be numeric or string-based.

3. **Threading & Concurrency**:  
   Multi-threaded to handle large inventories quickly. Defaults to (CPU count - 1) threads if not specified.

4. **Supports Power Devices, Network Devices, Storage**:  
   Power, network, or storage devices can be excluded by default from shutdown/reboot, unless explicitly included.

5. **Configurable Command Overrides**:  
   Each endpoint can override the default reboot or shutdown command.  

---

## Installation & Requirements

1. **Python**: Requires Python 3.9+  
2. **Dependencies**:  
   - PyYAML  
   - Paramiko  
   - Requests  
   - colorama (optional, for coloured console output)  

To install dependencies using pip:

```bash
pip install PyYAML paramiko requests colorama
```

---

## Usage

1. **Local file**:  
   » python manage_hosts.py --config /path/to/your/hosts.yaml [other options]

2. **HTTPS URL**:  
   » python manage_hosts.py --config https://example.com/hosts.yaml [other options]

3. **Default configuration**:  
   If you omit --config, it tries the local file “hosts.yaml” in the same directory, or uses the environment variable MANAGE_HOSTS_CONFIG.

Use --help to see all arguments:

```bash
python manage_hosts.py --help
```

Common arguments include:  
• --filter <filter_expr> : For tag- or type-based filtering (can be repeated).  
• --shutdown : Shut down matched endpoints in descending dependency order.  
• --reboot : Reboot matched endpoints in descending dependency order.  
• --command / -x : Execute a custom command for matched endpoints.  
• --threads : Concurrency limit.  
• --test : Dry run mode (will not actually perform destructive actions).  
• --include-network / --include-storage / --include-power : Include these device classes (router, ups, etc.) during shutdown/reboot.  

---

## Filter Syntax

Filters are specified via --filter command-line flags (or MANAGE_HOSTS_FILTER environment variable), and accept these comparators:

• "==", "!=" — Equality / inequality (numeric or string).  
• "<", ">", "<=", ">=" — Less-than, greater-than, etc. If both sides can be parsed as numbers, numeric comparison occurs; else comparison fails.  
• "is", "is not" — String-based strict equality / inequality.  
• "in", "not in" — Substring membership in the endpoint’s tag string.  

Additionally, you can filter by "type", e.g. "type==router".

---

## Examples

### Basic Checks
Without specifying shutdown/reboot/command, the script pings and performs a lightweight SSH check on each endpoint, printing a summary:

```bash
python manage_hosts.py
```

### Shutdown/Reboot with Default Logic
Shut down all matched hosts (descending order), excluding routers/switches, storage, and power devices by default:

```bash
python manage_hosts.py --shutdown
```

Reboot all matched hosts in descending order:

```bash
python manage_hosts.py --reboot
```

To include network and power devices:

```bash
python manage_hosts.py --shutdown --include-network --include-power
```

### Command Execution
Run an arbitrary command across matching hosts in wave order:

```bash
python manage_hosts.py --command "sudo apt-get update && sudo apt-get upgrade -y"
```

### Tag-Based Filtering
Example: Filter by location=“sy3”, and critical endpoints:

```bash
python manage_hosts.py --filter location==sy3 --filter critical==true
```

### Device Type Filtering
Example: Run checks only on routers:

```bash
python manage_hosts.py --filter "type==router"
```

Power devices:

```bash
python manage_hosts.py --filter "type in pdu"  # Substring match: pdu in 'pdu'
```

### Combined Examples
1. Filtering by numeric floor and location:

```bash
python manage_hosts.py \
    --filter floor>=5 \
    --filter location==dc3 \
    --shutdown
```

2. Filtering out a certain substring:

```bash
python manage_hosts.py \
    --filter "rack not in out-of-service" \
    --reboot
```

3. Using multiple comparators on a single run:

```bash
python manage_hosts.py \
    --filter "type!=router" \
    --filter "critical is true" \
    --filter "floor <= 10" \
    --command "echo 'Performing a check on this endpoint'"
```

### Run From a Remote Host (Pipe Method)
You can fetch the script directly from GitHub and run it via a pipe:

```bash
curl -sSL \
  https://raw.githubusercontent.com/aperim/manage-hosts/refs/heads/main/src/manage_hosts.py \
  | python3 - --help
```

Another example:  
```bash
curl -sSL \
  https://raw.githubusercontent.com/aperim/manage-hosts/refs/heads/main/src/manage_hosts.py \
  | python3 - --filter "type==router" --command "echo 'Hello Router!'"
```

Or to shut down only storage devices explicitly included:

```bash
curl -sSL \
  https://raw.githubusercontent.com/aperim/manage-hosts/refs/heads/main/src/manage_hosts.py \
  | python3 - --shutdown --include-storage
```

---

## Configuration File (YAML) Example

Below is a short example of a YAML configuration (commonly named “hosts.yaml”). By default, the script looks for this file locally or you can specify `--config`:

```yaml
keys:
  my_key_1: |
    -----BEGIN OPENSSH PRIVATE KEY-----
    ...
    -----END OPENSSH PRIVATE KEY-----
  my_key_2:
    file: "/home/user/.ssh/id_rsa"
  my_key_3:
    env: "MY_BASE64_KEY"

endpoints:
  - fqdn: server1.local
    type: host
    tags:
      location: sy3
      critical: "true"
      floor: "7"
    credentials:
      - username: root
        key: my_key_2
      - username: admin
        key: my_key_1
    host_dependencies:
      - router1.local
    ups_dependencies:
      - name: ups1.local
        outlet: "outlet3"
    pdu_dependencies: []
    overrides:
      shutdown: "sudo systemctl poweroff"
      reboot: "sudo systemctl reboot"

  - fqdn: router1.local
    type: router
    tags:
      location: sy3
      building: "3"
    credentials:
      - username: admin
        key: my_key_1
    overrides: {}

  - fqdn: ups1.local
    type: ups
    tags:
      location: sy3
    credentials: []
    overrides: {}
```

---

## Advanced Usage & Environment Variables

1. **Environment Variables**  
   • MANAGE_HOSTS_CONFIG : Path or HTTPS URL to config file.  
   • MANAGE_HOSTS_THREADS : Override default thread count.  
   • MANAGE_HOSTS_FILTER : YAML list of filters, e.g. ["floor>=5","type==router"].  
   • MANAGE_HOSTS_TEST : If “true” or “1”, runs in dry-run mode, echoing destructive commands.  
   • MANAGE_HOSTS_TIMEOUT : Timeout for commands (seconds).  
   • MANAGE_HOSTS_INCLUDE_NETWORK : If “true”, includes router, switch, firewall.  
   • MANAGE_HOSTS_INCLUDE_STORAGE : If “true”, includes storage devices.  
   • MANAGE_HOSTS_INCLUDE_POWER : If “true”, includes UPS and PDU devices.

2. **Overriding Commands**  
   For each endpoint, you can set “shutdown” or “reboot” in “overrides” to replace the default `sudo shutdown -h now` or `sudo shutdown -r now`.

3. **Threading**  
   By default, we use up to (CPU count - 1) threads. You can reduce or increase concurrency with `--threads`.

4. **Dry Run Mode**  
   Provide `--test` or set `MANAGE_HOSTS_TEST=true` to simulate commands without performing them.

---

## License

Copyright © 2025  
Aperim Pty Ltd  

Licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). You may not use this file except in compliance with the License.

---

## Contact & Contributing

• Author: Troy Kelly (Aperim Pty Ltd)  
• Repository: <https://github.com/aperim/manage-hosts>  

Issues, feature requests, and pull requests are welcome. Feel free to open a discussion or contact the author for questions.  

To contribute:

1. Fork the project.  
2. Create a new branch (git checkout -b feature/myfeature).  
3. Commit your changes (git commit -am 'Add new feature').  
4. Push your branch (git push origin feature/myfeature).  
5. Create a Pull Request.