#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
manage_hosts.py

A robust Python script to manage a list of hosts, PDUs, UPS devices, routers, switches, etc.
It reads configuration from a YAML file or HTTPS URL, applying filters and optionally performing
ping checks, SSH checks, commands, shutdown, or reboot in concurrency with dependency ordering.

Key Features:
    - YAML-based configuration, supporting local file or HTTPS URL.
    - SSH private keys loaded from inline text, file paths, or environment variables (base64-encoded).
    - Endpoints with typed dependencies (hosts, UPS, PDUs), processed in depth-based order.
    - Threaded operations and filtering by tags.
    - Colourised console output or JSON/YAML reports.
    - Per-endpoint overrides for the default shutdown or reboot commands.

This script follows the Google Python Style Guide where possible and includes inline docstrings
for maintainability.

Requires:
    Python 3.9+
    PyYAML (pip install pyyaml)
    Paramiko (pip install paramiko)
    Requests (pip install requests)
    colorama (optional, for coloured console output)

Example:
    python manage_hosts.py --config myhosts.yaml --shutdown
"""

import os
import sys
import argparse
import base64
import subprocess
import tempfile
import time
import threading
import platform
import concurrent.futures
import re
from typing import Dict, List, Optional, Union, Tuple

# Attempt to import third-party libraries, exit if missing.
try:
    import yaml
except ImportError:
    print("Please install PyYAML (pip install pyyaml).")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Please install requests (pip install requests).")
    sys.exit(1)

try:
    import paramiko
except ImportError:
    print("Please install paramiko (pip install paramiko).")
    sys.exit(1)

# Constants for environment variables and defaults.
PROGRAM_NAME = "manage_hosts"
DEFAULT_CONFIG_FILE = "hosts.yaml"
ENV_CONFIG = "MANAGE_HOSTS_CONFIG"
ENV_THREADS = "MANAGE_HOSTS_THREADS"
ENV_FILTER = "MANAGE_HOSTS_FILTER"
ENV_TEST = "MANAGE_HOSTS_TEST"
ENV_TIMEOUT = "MANAGE_HOSTS_TIMEOUT"

# Valid endpoint types enumeration.
VALID_ENDPOINT_TYPES = {
    "host", "ups", "pdu", "router", "switch", "firewall", "storage"
}

# Optional colour codes for improved terminal output.
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

# Optional emojis for user feedback.
CHECK_EMOJI = "✅"
ERROR_EMOJI = "❌"
WARNING_EMOJI = "⚠️"
INFO_EMOJI = "ℹ️"


class KeyDefinition:
    """Represents a definition of an SSH key, which may be inline, file-based, or environment-based."""

    def __init__(self,
                 key_data: Optional[str] = None,
                 file_path: Optional[str] = None,
                 env_var: Optional[str] = None) -> None:
        """Initializes a KeyDefinition.

        Args:
            key_data: The direct inline content of the key, if defined.
            file_path: A path to a local file containing the private key.
            env_var: An environment variable name containing base64-encoded key data.
        """
        self.key_data = key_data
        self.file_path = file_path
        self.env_var = env_var


class Endpoint:
    """Represents a single endpoint (host, ups, pdu, router, switch, etc.) with typed dependencies."""

    def __init__(self,
                 fqdn: str,
                 dev_type: str,
                 tags: Dict[str, str],
                 credentials: List[Dict[str, str]],
                 host_dependencies: List[str],
                 ups_dependencies: List[Union[str, Dict[str, str]]],
                 pdu_dependencies: List[Union[str, Dict[str, str]]],
                 overrides: Dict[str, str]) -> None:
        """Initializes an Endpoint instance.

        Args:
            fqdn: Fully Qualified Domain Name of the endpoint.
            dev_type: Device type (e.g., 'host', 'ups', 'pdu', 'router', etc.).
            tags: A dictionary of string key-value pairs describing the endpoint (e.g. location=sy3).
            credentials: A list of dictionaries specifying SSH credentials, e.g.
                [{"username": "root", "key": "my_key_name"}].
            host_dependencies: A list of FQDN strings that denote which hosts this endpoint depends on.
            ups_dependencies: A list of UPS dependencies, which can be dicts ({"name": "...", "outlet": "..."}).
            pdu_dependencies: A list of PDU dependencies, similar structure to ups_dependencies.
            overrides: A dict of optional command overrides, e.g. {"shutdown": "...", "reboot": "..."}.
        """
        self.fqdn = fqdn
        self.dev_type = dev_type
        self.tags = tags
        self.credentials = credentials
        self.host_dependencies = host_dependencies
        self.ups_dependencies = ups_dependencies
        self.pdu_dependencies = pdu_dependencies
        self.overrides = overrides
        self.depth = 0  # Depth is set by calculate_depths()


def load_yaml_config(config_source: str) -> Dict[str, object]:
    """Loads a YAML configuration from a local file or an HTTPS URL.

    Args:
        config_source: A file path or HTTPS URL.

    Returns:
        A dict representing the parsed YAML data.

    Raises:
        ValueError: If config_source starts with http://.
        OSError: If the local file cannot be opened or does not exist.
        requests.exceptions.RequestException: If an HTTPS URL fails to load.
    """
    if config_source.startswith("http://"):
        raise ValueError("Configuration via HTTP (non-SSL) is not permitted.")

    if config_source.startswith("https://"):
        resp = requests.get(config_source, timeout=10)
        resp.raise_for_status()
        return yaml.safe_load(resp.text)
    else:
        expanded_path = os.path.expanduser(config_source)
        if not os.path.isfile(expanded_path):
            raise OSError(f"Cannot open configuration file: {expanded_path}")
        with open(expanded_path, "r", encoding="utf-8") as file_handle:
            return yaml.safe_load(file_handle)


def parse_keys(key_section: Dict[str, object]) -> Dict[str, KeyDefinition]:
    """Parses the 'keys' section from YAML into a dictionary of KeyDefinition objects.

    Args:
        key_section: A dict where each key is a key name (string), and the value is either
            a YAML inline string, or a dict with "file"/"env"/"inline".

    Returns:
        A dict mapping key_name to KeyDefinition.

    Raises:
        ValueError: If any key definition is invalid.
    """
    results: Dict[str, KeyDefinition] = {}
    for key_name, value in key_section.items():
        if isinstance(value, str):
            # Inline key as a single string
            results[key_name] = KeyDefinition(key_data=value)
        elif isinstance(value, dict):
            # Possibly file-based, environment-based, or inline
            file_path = value.get("file")
            env_var = value.get("env")
            inline = value.get("inline")
            results[key_name] = KeyDefinition(
                key_data=inline,
                file_path=file_path,
                env_var=env_var,
            )
        else:
            raise ValueError(f"Invalid key definition for '{
                             key_name}': {value}")
    return results


def resolve_key(key_def: KeyDefinition) -> str:
    """Resolves the actual private key content from a KeyDefinition.

    Args:
        key_def: The KeyDefinition object specifying how to obtain the key.

    Returns:
        The raw private key content as a string.

    Raises:
        OSError: If a file path is specified but not found or not readable.
        ValueError: If an environment variable is empty or not set, or no key data is found.
    """
    if key_def.file_path:
        expanded_path = os.path.expanduser(key_def.file_path)
        with open(expanded_path, "r", encoding="utf-8") as file_handle:
            return file_handle.read()
    if key_def.env_var:
        env_val = os.environ.get(key_def.env_var)
        if not env_val:
            raise ValueError(f"Environment variable '{
                             key_def.env_var}' not found or empty.")
        return base64.b64decode(env_val).decode("utf-8")
    if key_def.key_data:
        return key_def.key_data
    raise ValueError("No valid key data found in KeyDefinition.")


def build_endpoints(endpoint_section: List[Dict[str, object]]) -> List[Endpoint]:
    """Creates a list of Endpoint objects from a parsed 'endpoints' YAML list.

    Args:
        endpoint_section: A list of dictionaries describing endpoints.

    Returns:
        A list of Endpoint instances.

    Raises:
        ValueError: If any endpoint has an unsupported device type.
    """
    endpoints: List[Endpoint] = []
    for item in endpoint_section:
        fqdn = str(item.get("fqdn", ""))
        dev_type = str(item.get("type", "host"))
        tags = item.get("tags", {})
        credentials = item.get("credentials", [])
        host_deps = item.get("host_dependencies", [])
        ups_deps = item.get("ups_dependencies", [])
        pdu_deps = item.get("pdu_dependencies", [])
        overrides = item.get("overrides", {})

        if dev_type not in VALID_ENDPOINT_TYPES:
            raise ValueError(f"Unsupported endpoint type '{
                             dev_type}' for {fqdn}.")

        # Make sure overrides is a dict
        if not isinstance(overrides, dict):
            overrides = {}

        endpoints.append(
            Endpoint(
                fqdn=fqdn,
                dev_type=dev_type,
                tags=tags if isinstance(tags, dict) else {},
                credentials=credentials if isinstance(
                    credentials, list) else [],
                host_dependencies=host_deps if isinstance(
                    host_deps, list) else [],
                ups_dependencies=ups_deps if isinstance(
                    ups_deps, list) else [],
                pdu_dependencies=pdu_deps if isinstance(
                    pdu_deps, list) else [],
                overrides=overrides,
            )
        )
    return endpoints


def calculate_depths(endpoints: List[Endpoint]) -> None:
    """Assigns a depth value to each endpoint based on host/ups/pdu dependencies.

    The depth is the max distance from an endpoint to a node with no dependencies.
    Leaf nodes have depth 0, their parents have depth 1, etc.

    Args:
        endpoints: A list of Endpoint objects to modify in place.
    """
    endpoint_map = {e.fqdn: e for e in endpoints}

    def get_dependencies(e: Endpoint) -> List[str]:
        """Collect all FQDN-based dependencies for an endpoint."""
        result: List[str] = []
        # Host dependencies are typically strings of FQDNs.
        result.extend(e.host_dependencies)

        # Handle UPS dependencies, which may be a dict (with "name") or a string.
        for ud in e.ups_dependencies:
            if isinstance(ud, dict):
                name = ud.get("name")
                if name:
                    result.append(name)
            elif isinstance(ud, str):
                result.append(ud)

        # Handle PDU dependencies, same logic as UPS.
        for pd in e.pdu_dependencies:
            if isinstance(pd, dict):
                name = pd.get("name")
                if name:
                    result.append(name)
            elif isinstance(pd, str):
                result.append(pd)
        return result

    visited: Dict[str, int] = {}

    def compute_depth(fqdn: str, stack: Optional[set] = None) -> int:
        """Recursively computes the depth of a single endpoint by its FQDN."""
        if stack is None:
            stack = set()
        if fqdn in stack:
            # Cycle detected, return 0
            return 0
        stack.add(fqdn)

        if fqdn in visited:
            stack.remove(fqdn)
            return visited[fqdn]

        endpoint = endpoint_map[fqdn]
        deps = [d for d in get_dependencies(endpoint) if d in endpoint_map]
        if not deps:
            visited[fqdn] = 0
        else:
            visited[fqdn] = max(compute_depth(d, stack) for d in deps) + 1

        stack.remove(fqdn)
        return visited[fqdn]

    # Compute depth for all endpoints
    for e in endpoints:
        e.depth = compute_depth(e.fqdn)


def parse_filters(filter_list: List[str]) -> List[Tuple[str, str, str]]:
    """Parses filters like 'location=sy3' or 'floor>=5' into structured tuples.

    Args:
        filter_list: A list of strings specifying filters, e.g. ["location=sy3", "floor>=5"].

    Returns:
        A list of (key, operator, value) tuples.

    Raises:
        ValueError: If an invalid filter format is encountered.
    """
    result: List[Tuple[str, str, str]] = []
    pattern = re.compile(r"^([^=<>]+)([=<>]+)(.+)$")

    for flt in filter_list:
        match = pattern.match(flt)
        if match:
            key, op, val = match.groups()
            result.append((key.strip(), op.strip(), val.strip()))
        else:
            # If no operator is specified, assume '='
            parts = flt.split("=", maxsplit=1)
            if len(parts) == 2:
                k, v = parts
                result.append((k.strip(), "=", v.strip()))
            else:
                raise ValueError(f"Cannot parse filter: {flt}")
    return result


def endpoint_matches_filters(ep: Endpoint, filters: List[Tuple[str, str, str]]) -> bool:
    """Determines whether an endpoint matches all specified filter criteria.

    Args:
        ep: The Endpoint to test.
        filters: A list of (tag_key, operator, test_value).

    Returns:
        True if the endpoint meets all filter conditions, else False.
    """
    for (fkey, fop, fval) in filters:
        if fkey not in ep.tags:
            return False

        val_str = ep.tags[fkey]
        # Attempt numeric comparison if feasible
        try:
            val_float = float(val_str)
            fval_float = float(fval)
        except ValueError:
            val_float = None
            fval_float = None

        if val_float is not None and fval_float is not None:
            # Numeric comparison
            if fop == "=" and (val_float != fval_float):
                return False
            elif fop == ">" and not (val_float > fval_float):
                return False
            elif fop == "<" and not (val_float < fval_float):
                return False
            elif fop == ">=" and not (val_float >= fval_float):
                return False
            elif fop == "<=" and not (val_float <= fval_float):
                return False
        else:
            # String comparison
            if fop == "=" and (val_str != fval):
                return False
            if fop in [">", "<", ">=", "<="]:
                # No meaningful numeric operation on strings
                return False

    return True


def ping_endpoint(host: str, timeout: int = 1) -> Optional[float]:
    """Pings a given host once and attempts to parse the round-trip time in milliseconds.

    Args:
        host: The hostname or IP address to ping.
        timeout: Timeout in seconds for the ping.

    Returns:
        A float representing the RTT in milliseconds if the ping succeeds,
        or None if the host is unreachable or an error occurs.
    """
    system = platform.system().lower()
    if system == "darwin":
        # On macOS, `-t` sets the hop limit; there's no direct -W on older versions.
        cmd = ["ping", "-c", "1", "-t", str(timeout), host]
    else:
        # On Linux-like systems, `-W` sets the response timeout in seconds.
        cmd = ["ping", "-c", "1", "-W", str(timeout), host]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            # 1) Parse direct single-response line: "time=1.23 ms" or "time<1 ms"
            match = re.search(r"time[=<>]\s?([\d\.]+)\s?ms", result.stdout)
            if match:
                return float(match.group(1))

            # 2) Optionally parse min/avg line, e.g. rtt min/avg/max = 0.042/0.042/0.092/...
            rtt_match = re.search(
                r"rtt min/avg/max/[^\s]+ = [\d\.]+/([\d\.]+)/[\d\.]+/[\d\.]+ ms",
                result.stdout
            )
            if rtt_match:
                return float(rtt_match.group(1))

            # If ping is successful but we couldn't parse a time, return 0.0
            return 0.0

        else:
            # Non-zero exit code => unreachable
            return None
    except Exception:
        return None


def attempt_ssh_command(host: str,
                        credentials: List[Dict[str, str]],
                        keys_map: Dict[str, KeyDefinition],
                        command: str,
                        test_run: bool,
                        timeout: int = 300) -> Tuple[bool, str, Optional[str]]:
    """Attempts to run a command over SSH with multiple credentials.

    Args:
        host: The hostname or IP address to connect via SSH.
        credentials: A list of credential dictionaries, e.g. [{"username": "root", "key": "my_key"}].
        keys_map: A dictionary mapping key names to KeyDefinition objects for resolution.
        command: The command to execute on the remote host.
        test_run: If True, simulates the command without a real SSH connection.
        timeout: Maximum time (in seconds) to allow for the command to complete.

    Returns:
        A tuple (success, output, remote_banner):
            - success: True if authentication succeeded at least once.
            - output: The combined stdout, stderr, and error messages from the attempts.
            - remote_banner: The remote SSH banner (e.g. "SSH-2.0-OpenSSH_8.4"), if retrieved.
    """
    if test_run:
        # Simulate success in test mode
        return True, f"(Test-run) Would execute [{command}] on {host}", None

    saved_output = ""
    remote_banner = None

    for cred in credentials:
        user = cred.get("username", "root")
        keyname = cred.get("key", "")

        # Check if the key is known
        if keyname not in keys_map:
            saved_output += f"\nNo matching key '{
                keyname}' found for {host}. Skipping."
            continue

        # Attempt to load key data
        try:
            key_data = resolve_key(keys_map[keyname])
        except Exception as ex:
            saved_output += f"\nFailed to resolve key {
                keyname} for {host}: {ex}"
            continue

        # Write key to temporary file for Paramiko
        tmpk_name = None
        try:
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmpk:
                tmpk.write(key_data)
                tmpk.flush()
                tmpk_name = tmpk.name

            # Try multiple paramiko key classes
            pkey_obj = None
            for pk_class in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
                try:
                    pkey_obj = pk_class.from_private_key_file(tmpk_name)
                    break
                except paramiko.SSHException:
                    continue
                except Exception as ex_inner:
                    saved_output += f"\nError parsing key with {
                        pk_class.__name__} for {host}: {ex_inner}"

            if pkey_obj is None:
                saved_output += "\nAll key parsers failed. Possibly unsupported key format."
                continue

            # Connect using paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                ssh.connect(
                    hostname=host,
                    username=user,
                    pkey=pkey_obj,
                    timeout=10,
                    look_for_keys=False,
                    allow_agent=False
                )
            except paramiko.AuthenticationException as auth_ex:
                saved_output += f"\nSSH to {
                    host} [user={user}] failed: {auth_ex}"
                ssh.close()
                continue
            except Exception as ex_conn:
                saved_output += f"\nSSH to {
                    host} [user={user}] error: {ex_conn}"
                ssh.close()
                continue

            # Retrieve the banner (e.g. SSH-2.0-OpenSSH_8.4)
            transport = ssh.get_transport()
            if transport:
                try:
                    remote_banner = transport.remote_version
                except Exception as banner_ex:
                    saved_output += f"\nCould not retrieve SSH banner: {
                        banner_ex}\n"

            # If connected, attempt the command
            try:
                chan = ssh.get_transport().open_session()
                chan.settimeout(timeout)
                chan.exec_command(command)

                start_time = time.time()
                output_buffer: List[str] = []
                while True:
                    if chan.recv_ready():
                        data = chan.recv(4096).decode("utf-8", errors="ignore")
                        output_buffer.append(data)
                    if chan.recv_stderr_ready():
                        data = chan.recv_stderr(4096).decode(
                            "utf-8", errors="ignore")
                        output_buffer.append(data)
                    if chan.exit_status_ready():
                        break
                    if (time.time() - start_time) > timeout:
                        output_buffer.append(
                            f"(Timed out after {timeout} seconds)\n")
                        break
                    time.sleep(0.1)

                exit_code = chan.recv_exit_status()
                ssh.close()

                saved_output += "".join(output_buffer)
                if exit_code == 0:
                    # Successful command execution
                    return True, saved_output, remote_banner
                else:
                    # Auth success, but command returned non-zero exit code
                    saved_output += f"\nCommand on {
                        host} [user={user}] exit code={exit_code}."
                    return True, saved_output, remote_banner
            except Exception as ex_run:
                saved_output += f"\nError executing command on {
                    host}: {ex_run}"
                ssh.close()
        finally:
            # Clean up the temporary file
            if tmpk_name and os.path.exists(tmpk_name):
                os.remove(tmpk_name)

    # No credentials succeeded
    return False, saved_output, remote_banner


def wait_until_unpingable(host: str, timeout: int = 300) -> bool:
    """Waits until the given host is no longer reachable via ping or until timeout.

    Args:
        host: The hostname or IP to test.
        timeout: Total number of seconds to wait for the host to become unreachable.

    Returns:
        True if the host became unreachable before the timeout, else False.
    """
    start = time.time()
    while (time.time() - start) < timeout:
        if ping_endpoint(host) is None:
            return True
        time.sleep(2)
    return False


def manage_endpoints(endpoints: List[Endpoint],
                     keys_map: Dict[str, KeyDefinition],
                     filters: List[Tuple[str, str, str]],
                     cmd: Optional[str],
                     do_shutdown: bool,
                     do_reboot: bool,
                     test_run: bool,
                     output_format: str,
                     timeout_sec: int,
                     threads: int) -> Union[str, Dict[str, Dict[str, object]]]:
    """Coordinates the main logic: filter endpoints, order them by depth, and operate in waves.

    Args:
        endpoints: The list of all Endpoint objects parsed from config.
        keys_map: A dictionary mapping key names to KeyDefinition values.
        filters: A list of (tag_key, operator, value) filters to further select endpoints.
        cmd: If not None, an arbitrary command to run on each endpoint in wave order.
        do_shutdown: Whether we're performing a global shutdown across endpoints.
        do_reboot: Whether we're performing a global reboot across endpoints.
        test_run: If True, destructive actions become echo statements.
        output_format: One of "text", "json", or "yaml".
        timeout_sec: Timeout (in seconds) for remote operations (ssh or wait cycles).
        threads: Number of concurrent worker threads to use when operating on a wave.

    Returns:
        Either a string of the final text/JSON/YAML output or a dictionary if further processing is needed.
    """
    # Filter endpoints by tags
    filtered = [
        ep for ep in endpoints if endpoint_matches_filters(ep, filters)]
    # Sort by descending depth to operate on the deepest dependencies (leaf nodes) first
    filtered.sort(key=lambda e: e.depth, reverse=True)

    results: Dict[str, Dict[str, object]] = {}

    def worker(e: Endpoint) -> None:
        """Process a single endpoint in a wave: ping, optional SSH check, then operation."""
        res: Dict[str, object] = {
            "fqdn": e.fqdn,
            "type": e.dev_type,
            "depth": e.depth,
            "ping_rtt_ms": None,
            "ssh_check": False,
            "ssh_version": "",
            "operation_output": "",
            "operation_success": False,
        }

        # Perform a ping test
        rtt = ping_endpoint(e.fqdn, timeout=1)
        if rtt is not None:
            res["ping_rtt_ms"] = rtt

        # If credentials exist, do a lightweight SSH test
        if e.credentials:
            ssh_success, _, ssh_banner = attempt_ssh_command(
                host=e.fqdn,
                credentials=e.credentials,
                keys_map=keys_map,
                command="echo 'SSH Test Connection'",
                test_run=test_run,
                timeout=5
            )
            res["ssh_check"] = ssh_success
            if ssh_banner:
                # If we retrieved the SSH banner, store it
                res["ssh_version"] = ssh_banner

        # If a user command is specified, run it
        if cmd is not None:
            success, out, banner = attempt_ssh_command(
                host=e.fqdn,
                credentials=e.credentials,
                keys_map=keys_map,
                command=cmd,
                test_run=test_run,
                timeout=timeout_sec
            )
            res["operation_success"] = success
            res["operation_output"] = out
            if banner:
                res["ssh_version"] = banner

        elif do_shutdown:
            # Perform a shutdown
            default_shutdown_cmd = "sudo shutdown -h now"
            shutdown_cmd = (
                e.overrides.get("shutdown", default_shutdown_cmd)
                if not test_run
                else "echo 'I would shutdown now'"
            )
            success, out, banner = attempt_ssh_command(
                host=e.fqdn,
                credentials=e.credentials,
                keys_map=keys_map,
                command=shutdown_cmd,
                test_run=False,  # We'll handle "echo" ourselves via test_run
                timeout=15
            )
            res["operation_output"] = out
            res["operation_success"] = success
            if banner:
                res["ssh_version"] = banner

            # Wait until unpingable
            if success and not test_run:
                offline = wait_until_unpingable(e.fqdn, timeout_sec)
                if not offline:
                    res["operation_output"] += f"\nHost still pingable after {
                        timeout_sec}s."
                    res["operation_success"] = False

        elif do_reboot:
            # Perform a reboot
            default_reboot_cmd = "sudo shutdown -r now"
            reboot_cmd = (
                e.overrides.get("reboot", default_reboot_cmd)
                if not test_run
                else "echo 'I would reboot now'"
            )
            success, out, banner = attempt_ssh_command(
                host=e.fqdn,
                credentials=e.credentials,
                keys_map=keys_map,
                command=reboot_cmd,
                test_run=False,
                timeout=15
            )
            res["operation_output"] = out
            res["operation_success"] = success
            if banner:
                res["ssh_version"] = banner

            # Also wait until unpingable, like shutdown
            if success and not test_run:
                offline = wait_until_unpingable(e.fqdn, timeout_sec)
                if not offline:
                    res["operation_output"] += f"\nHost still pingable after {
                        timeout_sec}s."
                    res["operation_success"] = False

        # Save final result
        results[e.fqdn] = res

    # Process endpoints in waves grouped by depth
    distinct_depths = sorted({ep.depth for ep in filtered}, reverse=True)
    for depth_lvl in distinct_depths:
        wave_endpoints = [ep for ep in filtered if ep.depth == depth_lvl]
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(worker, wep) for wep in wave_endpoints]
            concurrent.futures.wait(futures)

    # Return results as JSON, YAML, or text
    if output_format == "json":
        try:
            import json
            return json.dumps(list(results.values()), indent=2)
        except ImportError:
            return str(results)
    elif output_format == "yaml":
        try:
            import yaml
            return yaml.safe_dump(list(results.values()), sort_keys=False)
        except ImportError:
            return str(results)
    else:
        return build_text_report(results)


def build_text_report(results: Dict[str, Dict[str, object]]) -> str:
    """Generates a human-readable text report in table form.

    Args:
        results: A dict of fqdn -> result dict.

    Returns:
        A string containing formatted table output.
    """
    rows = list(results.values())
    # Sort by FQDN alphabetically for stable output
    rows.sort(key=lambda x: str(x["fqdn"]))

    # Determine column widths for alignment
    max_fqdn_len = max((len(str(r["fqdn"])) for r in rows), default=20)
    max_fqdn_len = max(max_fqdn_len, 20)
    max_type_len = max((len(str(r["type"])) for r in rows), default=8)
    max_type_len = max(max_type_len, 8)

    header_fmt = (
        f"{BLUE}{{:<{max_fqdn_len}}} {{:<{
            max_type_len}}} {{:>5}} {{:>8}} {{:>4}} {{:>9}}{RESET}"
    )
    line_fmt = f"{{:<{max_fqdn_len}}} {{:<{
        max_type_len}}} {{:>5}} {{:>8}} {{:>4}} {{:>9}}"

    # Construct the header line
    header = header_fmt.format(
        "FQDN", "TYPE", "DEPTH", "PING(ms)", "SSH", "OPERATION")
    lines = [header]

    # Populate each row
    for r in rows:
        fqdn = str(r["fqdn"])
        dev_type = str(r["type"])
        depth = str(r["depth"])
        ping_ms = r["ping_rtt_ms"]
        ssh_ok = r["ssh_check"]
        op_ok = r["operation_success"]

        # Format each column
        ping_str = f"{ping_ms:.2f}" if ping_ms is not None else "N/A"
        ssh_str = f"{GREEN}OK{RESET}" if ssh_ok else f"{RED}NO{RESET}"
        op_str = f"{GREEN}✓{RESET}" if op_ok else f"{RED}✗{RESET}"

        row_line = line_fmt.format(
            fqdn, dev_type, depth, ping_str, ssh_str, op_str)
        lines.append(row_line)

    return "\n".join(lines)


def main() -> None:
    """Main entry point of the manage_hosts script.

    Parses CLI arguments, loads config, builds endpoints, calculates depths,
    applies filters, and processes to provide checks, commands, or power actions.
    """
    parser = argparse.ArgumentParser(
        description="Manage Hosts Script - controlling endpoints (e.g. host, ups, router...)"
    )
    parser.add_argument(
        "--config", "-c",
        help=(
            "Path or HTTPS URL to YAML config. "
            f"Defaults to '{DEFAULT_CONFIG_FILE}' or env:{ENV_CONFIG}."
        )
    )
    parser.add_argument(
        "--filter", action="append", default=[],
        help="Filter expression (key=value, key>=value, etc.). May be repeated."
    )
    parser.add_argument(
        "--threads", type=int,
        help="Number of threads. Defaults to (#CPUs - 1) or 1."
    )
    parser.add_argument(
        "--test", action="store_true",
        help="Test mode: skip real commands (echo instead)."
    )
    parser.add_argument(
        "--shutdown", action="store_true",
        help="Shut down all filtered endpoints in descending dependency order."
    )
    parser.add_argument(
        "--reboot", action="store_true",
        help="Reboot all filtered endpoints in descending dependency order."
    )
    parser.add_argument(
        "--command", "-x",
        help="Execute a custom command on each endpoint in wave order."
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output final results in JSON format."
    )
    parser.add_argument(
        "--yaml", action="store_true",
        help="Output final results in YAML format."
    )
    parser.add_argument(
        "--timeout", type=int,
        help="Timeout in seconds for commands or shutdown. Defaults to 300."
    )

    args = parser.parse_args()

    # Validate that the user can't specify both shutdown and reboot in one run
    if args.shutdown and args.reboot:
        parser.error(
            "Cannot specify both --shutdown and --reboot at the same time.")

    # Resolve configuration source
    config_source = args.config or os.environ.get(
        ENV_CONFIG, DEFAULT_CONFIG_FILE)

    # Load YAML config
    try:
        config_data = load_yaml_config(config_source)
    except Exception as ex:
        print(f"{ERROR_EMOJI} Cannot load configuration: {ex}")
        sys.exit(1)

    if not config_data:
        print(f"{ERROR_EMOJI} No valid data in config file/URL.")
        sys.exit(1)

    # Parse SSH keys
    raw_keys = config_data.get("keys", {})
    if not isinstance(raw_keys, dict):
        raw_keys = {}
    keys_map = parse_keys(raw_keys)

    # Parse endpoints
    endpoint_section = config_data.get("endpoints", [])
    if not isinstance(endpoint_section, list):
        endpoint_section = []
    endpoints = build_endpoints(endpoint_section)

    # Calculate dependency depths
    calculate_depths(endpoints)

    # Merge filter arguments from CLI and environment
    combined_filters: List[str] = list(args.filter)
    env_filter_str = os.environ.get(ENV_FILTER)
    if env_filter_str:
        try:
            env_filter_list = yaml.safe_load(env_filter_str)
            if isinstance(env_filter_list, list):
                combined_filters.extend(env_filter_list)
        except Exception:
            print(f"{WARNING_EMOJI} Could not parse {
                  ENV_FILTER} as YAML list.")

    parsed_filter_tuples = parse_filters(combined_filters)

    # Determine concurrency
    import multiprocessing
    cpu_count = multiprocessing.cpu_count()
    default_threads = max(cpu_count - 1, 1)
    chosen_threads = args.threads or int(
        os.environ.get(ENV_THREADS, default_threads))

    # Determine test mode
    test_run = args.test or (
        os.environ.get(ENV_TEST, "false").lower() in ["true", "1", "yes"]
    )

    # Determine timeout
    timeout_sec = args.timeout or int(os.environ.get(ENV_TIMEOUT, "300"))

    # Determine output format
    if args.json:
        output_format = "json"
    elif args.yaml:
        output_format = "yaml"
    else:
        output_format = "text"

    # Operations specified by arguments
    user_cmd = args.command
    do_shutdown = args.shutdown
    do_reboot = args.reboot

    # If no operation is specified, we effectively do a "check" (ping + SSH).
    # This is handled in manage_endpoints with cmd=None, do_shutdown=False, do_reboot=False.
    results = manage_endpoints(
        endpoints=endpoints,
        keys_map=keys_map,
        filters=parsed_filter_tuples,
        cmd=user_cmd,
        do_shutdown=do_shutdown,
        do_reboot=do_reboot,
        test_run=test_run,
        output_format=output_format,
        timeout_sec=timeout_sec,
        threads=chosen_threads
    )

    # Print final results
    print(results)


if __name__ == "__main__":
    main()
