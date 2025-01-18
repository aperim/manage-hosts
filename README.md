# Manage Hosts Script

A robust Python script to manage a list of hosts, PDUs, UPS devices, routers, switches, and more. This script supports filtering endpoints by tags or device type, establishing SSH connections with multiple credentials, shutting down endpoints, executing arbitrary commands, and reflecting on dependencies (such as UPS, PDU, host dependencies) with a depth-based approach.

This script is suitable for both macOS (Darwin) and Linux-based operating systems. It uses Python 3.9+ features and is designed following (as closely as possible) the Google Python Style Guide.

--------------------------------------------------------------------------------
## Key Functionality

1. Configuration Loading from YAML:  
   • By default, attempts to load "hosts.yaml" in the same directory.  
   • Can be overridden using the "--config/-c" command-line argument or the MANAGE_HOSTS_CONFIG environment variable.  
   • Can load from a local file path or an HTTPS URL (HTTP is disallowed).

2. SSH Key Management:  
   • Private keys can be provided directly in the YAML, via a file reference, or via an environment variable (assumed base64-encoded).  
   • Multiple SSH credentials can be defined per endpoint, tried in order until one succeeds.

3. Endpoint Inventory:  
   • Endpoints accept a "type" from the set {host, ups, pdu, router, switch, firewall, storage}.  
   • Endpoints can define multiple credentials and multiple tags.  
   • Endpoints can define dependencies on other hosts, UPS systems, and PDUs.  
   • Depth-based ordering ensures leaf nodes (hosts with no dependencies) get actions first, with parents (more central devices) waiting until children are complete.

4. Overrides for Shutdown and Reboot:  
   • If an endpoint has an "overrides" entry with a "shutdown" key, that command is used instead of the default "sudo shutdown -h now".  
   • If an endpoint has an "overrides" entry with a "reboot" key, that command is used instead of the default "sudo shutdown -r now".  

5. Filtering:  
   • Supports multiple --filter arguments like "--filter location=sy3 --filter critical=true --filter type==router --filter floor>=5".  
   • Each --filter is combined with a logical AND.  
   • The following comparators are supported:  
       ==, !=, <, >, <=, >=, is, is not, in, not in  
   • When both sides can be parsed as numeric, <, <=, >, >= become numeric comparisons; otherwise they return no match.  
   • "is" and "is not" act like string equality or inequality.  
   • "in" and "not in" perform substring membership checks on the endpoint’s string value.  
   • If you wish to filter by device type, use "type" as the filter key.

6. Threaded Operations:  
   • The script divides its work among threads, defaulting to (CPU count - 1) or 1 if the CPU count is low.  
   • Can be overridden via --threads or the MANAGE_HOSTS_THREADS environment variable.  
   • Endpoints are processed wave-by-wave, from the greatest depth to zero.

7. Reporting:  
   • By default, output is a colourised, human-friendly ASCII table in the console.  
   • Use --json or --yaml to get structured JSON or YAML output.  

8. Operational Modes:  
   • No options: Perform basic checks (ping + SSH) on each endpoint.  
   • --test / MANAGE_HOSTS_TEST: Dry run mode, substituting destructive commands with echo statements.  
   • --shutdown: Gracefully shut down endpoints in descending dependency order, waiting for them to become unreachable.  
   • --reboot: Gracefully reboot endpoints in descending dependency order, waiting for them to become unreachable.  
   • --command / -x: Executes an arbitrary command on all endpoints, wave-by-wave.  

   Note: --shutdown and --reboot cannot both be used in the same run.

--------------------------------------------------------------------------------
## Example Configuration: hosts.yaml

```yaml
# SSH Keys
keys:
  my_key_1: |
    -----BEGIN OPENSSH PRIVATE KEY-----
    ...
    -----END OPENSSH PRIVATE KEY-----
  my_key_2:
    file: "/home/user/.ssh/id_rsa"
  my_key_3:
    env: "MY_BASE64_ENCODED_KEY"

# Defined Endpoints
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
    host_dependencies: []
    ups_dependencies: []
    pdu_dependencies: []
    overrides:
      # Uses default shutdown and reboot commands

  - fqdn: ups1.local
    type: ups
    tags:
      location: sy3
    credentials: []
    host_dependencies: []
    ups_dependencies: []
    pdu_dependencies: []
    # No overrides, so any shutdown command is a no-op if credentials are missing
```

--------------------------------------------------------------------------------
## Usage Examples

• Default operation (ping + SSH check):  
  python manage_hosts.py

• Override config path (local file) and test run:  
  python manage_hosts.py --config /etc/hostmanage/hosts.yaml --test

• Filtering and threads:  
  python manage_hosts.py --filter location=sy3 --filter critical=true --threads 5

• Filter by device type:  
  python manage_hosts.py --filter "type==router"

• Executing a command on all endpoints (deepest dependencies first):  
  python manage_hosts.py --command "sudo apt-get update && sudo apt-get -y full-upgrade"

• Shutting down all hosts (deepest dependencies first):  
  python manage_hosts.py --shutdown

• Rebooting all hosts:  
  python manage_hosts.py --reboot

• Generating JSON output:  
  python manage_hosts.py --filter critical=true --json

--------------------------------------------------------------------------------
## Notes

• This script assumes the required libraries (paramiko, PyYAML, requests) are installed.  
• In --test mode, no destructive commands (shutdown/reboot) are actually executed.  
• Timeout for remote operations defaults to 300 seconds; can be overridden by --timeout or MANAGE_HOSTS_TIMEOUT.  
• Dependency ordering ensures child endpoints are addressed first.  
• The script is idempotent regarding local file changes.  