# Manage Hosts Script

A robust Python script to manage a list of hosts, PDUs, UPS devices, routers, switches, and more. This script supports filtering endpoints by tags, establishing SSH connections with multiple credentials, shutting down endpoints, executing arbitrary commands, and reflecting on dependencies (such as UPS, PDU, host dependencies) with a depth-based approach.

Updated Features Include:
1. Endpoints may define a "shutdown" override command (shall replace the default "sudo shutdown -h now").  
2. Endpoints may define a "reboot" override command (shall replace the default "sudo shutdown -r now").  
3. A new command-line parameter "--reboot", similar to "--shutdown", to reboot endpoints instead of shutting them down.

This script is suitable for both macOS (Darwin) and Debian (Linux) based operating systems. It uses Python 3.9+ features and is designed following (as closely as possible) the Google Python Style Guide.

--------------------------------------------------------------------------------
## Key Functionality

1. Configuration Loading from YAML:
   • By default, attempts to load "hosts.yaml" in the same directory.  
   • Can be overridden using the "--config/-c" command-line argument or the MANAGE_HOSTS_CONFIG environment variable.  
   • Can load from a local file path or an HTTPS URL (HTTP is disallowed).

2. SSH Key Management:
   • Private keys can be provided directly as a string, via a file reference, or via an environment variable (assumed base64-encoded).  
   • Multiple SSH credentials can be defined per endpoint, tried in order until one succeeds.

3. Endpoint Inventory:
   • Endpoints accept a "type" from the set {host, ups, pdu, router, switch, firewall, storage}.  
   • Endpoints can have zero or more credentials and zero or more tags.  
   • Endpoints can define dependencies on other hosts, UPS systems, and PDUs.  
   • Depth-based ordering ensures that leaf nodes (hosts that depend on nothing else) get actioned first; ancestors (like routers, or more central devices) only get actioned once their children are finished.

4. Overrides for Shutdown and Reboot:
   • If an endpoint has an "overrides" entry with a "shutdown" key, that command is used for shutdown instead of the default "sudo shutdown -h now".  
   • If an endpoint has an "overrides" entry with a "reboot" key, that command is used for reboot instead of the default "sudo shutdown -r now".  
   • For example, an endpoint can specify:  
       overrides:  
         shutdown: "systemctl poweroff -i"  
         reboot: "systemctl reboot"  
   • If no override is defined, the default commands are used.

5. Filtering:
   • Supports multiple --filter arguments like "--filter location=sy3 --filter critical=true --filter building=3 --filter floor>=5".  
   • Entails (tag_key, operator, value).  
   • The environment variable MANAGE_HOSTS_FILTER may also store a YAML array of filter criteria.

6. Threaded Operations:
   • The script divides work among threads.  
   • The default thread count is (CPU count - 1) or 1 if the CPU count is very low.  
   • Can be overridden via --threads or the MANAGE_HOSTS_THREADS environment variable.  
   • Endpoints are processed wave-by-wave, from the greatest depth to zero.

7. Reporting:
   • Output is a colourised, human-friendly ASCII table by default.  
   • Use --json or --yaml to get structured JSON or YAML output.  

8. Operational Modes:
   • No options: Perform basic checks (ping + test SSH) on each endpoint.  
   • --test / MANAGE_HOSTS_TEST: Dry run mode, substituting destructive commands with echo statements.  
   • --shutdown: Gracefully shut down endpoints in dependency order, waiting for them to become unreachable.  
       – If an endpoint has a "shutdown" override, that command is used instead of "sudo shutdown -h now".  
   • --reboot: Gracefully reboot endpoints in dependency order, waiting for them to become unreachable.  
       – If an endpoint has a "reboot" override, that command is used instead of "sudo shutdown -r now".  
   • --command / -x: Executes an arbitrary command on all endpoints, wave-by-wave.  

   NOTE: --shutdown and --reboot cannot be combined in the same operation.  

--------------------------------------------------------------------------------
## Example Configuration: hosts.yaml

Below is an example YAML file supporting all available features:

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
      # This endpoint uses the default shutdown and reboot commands

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

In the above example:
• "server1.local" is a host that depends on "router1.local" being up, and it also depends on "ups1.local" for power.  
• "server1.local" has a custom shutdown or reboot command (via overrides).  
• "router1.local" uses default commands if requested to shut down or reboot.  
• "ups1.local" has no credentials and no shutdown or reboot override.  

--------------------------------------------------------------------------------
## Usage Examples

• Default operation (ping + SSH check):  
  » python manage_hosts.py

• Override config path (local file) and test run:  
  » python manage_hosts.py --config /etc/hostmanage/hosts.yaml --test

• Override config via HTTPS URL (non-SSL is invalid):  
  » export MANAGE_HOSTS_CONFIG="https://example.com/myhosts.yaml"  
  » python manage_hosts.py

• Filtering and threads:  
  » python manage_hosts.py --filter location=sy3 --filter critical=true --threads 5

• Executing a command on all endpoints (deepest dependencies first):  
  » python manage_hosts.py --command "sudo apt-get update && sudo apt-get -y full-upgrade"

• Shutting down all hosts (deeper dependencies shut down first):  
  » python manage_hosts.py --shutdown

• Rebooting all hosts (applies "reboot" logic, if overridden or default):  
  » python manage_hosts.py --reboot

• Generating JSON output:  
  » python manage_hosts.py --filter critical=true --json

--------------------------------------------------------------------------------
## Notes

• This script assumes the required libraries (paramiko, PyYAML, requests) are installed.  
• In --test mode, no destructive commands (shutdown/reboot) are actually executed.  
• Timeout for remote operations defaults to 300 seconds; can be overridden by --timeout or MANAGE_HOSTS_TIMEOUT.  
• Dependency ordering ensures child endpoints are addressed first.  
• The script is idempotent with regard to local file changes; repeated runs do not modify the YAML file.

--------------------------------------------------------------------------------