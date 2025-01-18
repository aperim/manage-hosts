#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
manage_hosts.py

A robust Python script to manage a list of hosts, PDUs, UPS devices, routers, switches, etc.
Reads configuration from a YAML file or HTTPS URL, applying filters and optionally performing
command execution, shutdown, or reboot in concurrency with dependency ordering.

Requires:
    Python 3.9+
    pyyaml
    paramiko
    requests
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
from typing import Dict, List, Optional, Union, Tuple
import concurrent.futures
import re

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

PROGRAM_NAME = "manage_hosts"
DEFAULT_CONFIG_FILE = "hosts.yaml"
ENV_CONFIG = "MANAGE_HOSTS_CONFIG"
ENV_THREADS = "MANAGE_HOSTS_THREADS"
ENV_FILTER = "MANAGE_HOSTS_FILTER"
ENV_TEST = "MANAGE_HOSTS_TEST"
ENV_TIMEOUT = "MANAGE_HOSTS_TIMEOUT"

VALID_ENDPOINT_TYPES = {
    "host", "ups", "pdu", "router", "switch", "firewall", "storage"
}

# You can adjust or remove these ANSI escapes if you prefer uncoloured output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

# Emojis for optional usage in output
CHECK_EMOJI = "✅"
ERROR_EMOJI = "❌"
WARNING_EMOJI = "⚠️"
INFO_EMOJI = "ℹ️"


class KeyDefinition:
    """Represents a definition of an SSH key (inline, file-based or environment-based)."""

    def __init__(
        self,
        key_data: Optional[str] = None,
        file_path: Optional[str] = None,
        env_var: Optional[str] = None
    ) -> None:
        """
        Initializes a KeyDefinition.

        Args:
            key_data: Direct string containing the key.
            file_path: Path to a file containing the key.
            env_var: Environment variable containing a base64-encoded key.
        """
        self.key_data = key_data
        self.file_path = file_path
        self.env_var = env_var


class Endpoint:
    """Represents a single endpoint (host, ups, pdu, router, switch, etc.) with dependencies."""

    def __init__(
        self,
        fqdn: str,
        dev_type: str,
        tags: Dict[str, str],
        credentials: List[Dict[str, str]],
        host_dependencies: List[str],
        ups_dependencies: List[Dict[str, str]],
        pdu_dependencies: List[Dict[str, str]],
        overrides: Dict[str, str]
    ) -> None:
        """
        Initializes an Endpoint instance.

        Args:
            fqdn: Fully Qualified Domain Name of the endpoint.
            dev_type: Type of device, e.g. 'host', 'ups', 'pdu', 'router'.
            tags: Key-value tags that describe this endpoint (e.g. location=sy3).
            credentials: List of dicts like [{"username": "...", "key": "..."}, ...].
            host_dependencies: List of FQDN strings that must be "up" first.
            ups_dependencies: List of dicts describing UPS dependencies.
            pdu_dependencies: List of dicts describing PDU dependencies.
            overrides: Dict of optional command overrides, e.g. {"shutdown":"...", "reboot":"..."}.
        """
        self.fqdn = fqdn
        self.dev_type = dev_type
        self.tags = tags
        self.credentials = credentials
        self.host_dependencies = host_dependencies
        self.ups_dependencies = ups_dependencies
        self.pdu_dependencies = pdu_dependencies
        self.overrides = overrides
        self.depth = 0  # to be set by calculate_depths()


def load_yaml_config(config_source: str) -> Dict[str, object]:
    """Loads and parses the YAML configuration from a file path or an HTTPS URL.

    Args:
        config_source: A local filesystem path or an HTTPS URL.

    Returns:
        A dictionary representing the parsed YAML configuration.

    Raises:
        ValueError: If the URL is non-SSL or there's an error opening the resource.
        OSError: If local file cannot be opened.
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
    """Parses the 'keys' section of the YAML config into KeyDefinition objects.

    Args:
        key_section: Dict of key_name -> (string or file/env reference).

    Returns:
        A dictionary of key_name -> KeyDefinition.
    """
    results = {}
    for key_name, value in key_section.items():
        if isinstance(value, str):
            # Inline key
            results[key_name] = KeyDefinition(key_data=value)
        elif isinstance(value, dict):
            file_path = value.get("file")
            env_var = value.get("env")
            inline = value.get("inline")
            results[key_name] = KeyDefinition(
                key_data=inline,
                file_path=file_path,
                env_var=env_var,
            )
        else:
            raise ValueError(f"Invalid key definition for {key_name}")
    return results


def resolve_key(key_def: KeyDefinition) -> str:
    """Resolves a private key string from a KeyDefinition.

    Args:
        key_def: The KeyDefinition object.

    Returns:
        The private key text.

    Raises:
        OSError: If a file path cannot be opened.
        ValueError: If environment variable is not set or empty.
    """
    if key_def.file_path:
        expanded_path = os.path.expanduser(key_def.file_path)
        with open(expanded_path, "r", encoding="utf-8") as file_handle:
            return file_handle.read()
    if key_def.env_var:
        env_val = os.environ.get(key_def.env_var)
        if not env_val:
            raise ValueError(
                f"Environment variable '{key_def.env_var}' not found or empty."
            )
        return base64.b64decode(env_val).decode("utf-8")
    if key_def.key_data:
        return key_def.key_data
    raise ValueError("No valid key data found in KeyDefinition.")


def build_endpoints(
    endpoint_section: List[Dict[str, object]]
) -> List[Endpoint]:
    """Creates Endpoint objects from the 'endpoints' list in the YAML config.

    Args:
        endpoint_section: A list of dictionary items describing endpoints.

    Returns:
        A list of Endpoint objects.

    Raises:
        ValueError: If an endpoint type is invalid or data is malformed.
    """
    endpoints = []
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

        # Ensure we only store dict overrides
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
    """Assigns a 'depth' value to each Endpoint based on dependencies.

    Depth is the maximum distance from the endpoint to an ancestor with zero dependencies.
    Higher depth implies a more "leaf-like" node in the dependency tree.

    Args:
        endpoints: A list of Endpoint objects to process.
    """
    endpoint_map = {e.fqdn: e for e in endpoints}

    def get_dependencies(e: Endpoint) -> List[str]:
        """Builds a combined list of dependency FQDNs for the endpoint.

        This function handles both dict-based dependencies (e.g. {"name": "ups1.local"})
        and string-based dependencies (e.g. "ups1.local").
        """
        result: List[str] = []
        # Host dependencies are assumed to be strings (FQDNs).
        result.extend(e.host_dependencies)

        # For ups_dependencies, each entry might be a dict or a plain string.
        for ud in e.ups_dependencies:
            if isinstance(ud, dict):
                name = ud.get("name")
                if name:
                    result.append(str(name))
            elif isinstance(ud, str):
                # handle plain string
                result.append(ud)

        # PDU dependencies likewise might be dicts or strings.
        for pd in e.pdu_dependencies:
            if isinstance(pd, dict):
                name = pd.get("name")
                if name:
                    result.append(str(name))
            elif isinstance(pd, str):
                # handle plain string
                result.append(pd)

        return result

    visited: Dict[str, int] = {}

    def compute_depth(fqdn: str, stack: Optional[set] = None) -> int:
        if stack is None:
            stack = set()
        if fqdn in stack:
            # cycle detected
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

    for e in endpoints:
        e.depth = compute_depth(e.fqdn)


def parse_filters(filter_list: List[str]) -> List[Tuple[str, str, str]]:
    """Parses filter strings (e.g. 'location=sy3', 'floor>=5') into structured tuples.

    Args:
        filter_list: List of filter strings from the command line or environment.

    Returns:
        A list of tuples (tag_key, operator, test_value).
    """
    result: List[Tuple[str, str, str]] = []
    pattern = re.compile(r"^([^=<>]+)([=<>]+)(.+)$")

    for flt in filter_list:
        match = pattern.match(flt)
        if match:
            key, op, val = match.groups()
            result.append((key.strip(), op.strip(), val.strip()))
        else:
            # If no operator is found, assume '='
            parts = flt.split("=", maxsplit=1)
            if len(parts) == 2:
                k, v = parts
                result.append((k.strip(), "=", v.strip()))
            else:
                raise ValueError(f"Cannot parse filter: {flt}")
    return result


def endpoint_matches_filters(ep: Endpoint, filters: List[Tuple[str, str, str]]) -> bool:
    """Checks if an endpoint satisfies all filter criteria.

    Args:
        ep: The endpoint to test.
        filters: A list of (tag_key, operator, test_value).

    Returns:
        True if the endpoint matches all filters, else False.
    """
    for (fkey, fop, fval) in filters:
        if fkey not in ep.tags:
            return False
        val_str = ep.tags[fkey]
        try:
            val_float = float(val_str)
            fval_float = float(fval)
        except ValueError:
            # String comparison instead
            val_float = None
            fval_float = None

        if val_float is not None and fval_float is not None:
            # Numeric comparison
            if fop == "=" and not (val_float == fval_float):
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
            # String-based
            if fop == "=" and val_str != fval:
                return False
            if fop in [">", "<", ">=", "<="]:
                return False
    return True


def ping_endpoint(host: str, timeout: int = 1) -> Optional[float]:
    """Pings an endpoint once and returns round-trip time (RTT) in ms if successful.

    Args:
        host: Hostname or IP to ping.
        timeout: Timeout in seconds for the ping.

    Returns:
        RTT as a float, or None if unreachable.
    """
    system = platform.system().lower()
    if system == "darwin":
        cmd = ["ping", "-c", "1", "-t", str(timeout), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), host]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            match = re.search(r"time[=<]\s?([\d\.]+)\s?ms", result.stdout)
            if match:
                return float(match.group(1))
            return 0.0
        return None
    except Exception:
        return None


def attempt_ssh_command(
    host: str,
    credentials: List[Dict[str, str]],
    keys_map: Dict[str, KeyDefinition],
    command: str,
    test_run: bool,
    timeout: int = 300
) -> Tuple[bool, str]:
    """Attempts to run an SSH command using multiple credentials in order.

    Args:
        host: The hostname to SSH into.
        credentials: A list of {"username":"...", "key":"..."} items in priority order.
        keys_map: A dictionary of key_name -> KeyDefinition.
        command: The command to execute, or an "echo" statement if test_run is True.
        test_run: If True, no real command is run, only a simulated echo.
        timeout: Time in seconds to allow the command to run.

    Returns:
        (success, output) => success is True if at least one SSH credential worked.
                             output is the combined stdout/stderr of the last attempt.
    """
    if test_run:
        return True, f"(Test-run) Would execute [{command}] on {host}"

    saved_output = ""
    for cred in credentials:
        user = cred.get("username", "root")
        keyname = cred.get("key", "")

        if keyname not in keys_map:
            saved_output += (
                f"\nNo matching key '{keyname}' found for {
                    host}. Skipping this credential."
            )
            continue

        try:
            key_data = resolve_key(keys_map[keyname])
        except Exception as ex:
            saved_output += f"\nFailed to resolve key {
                keyname} for {host}: {ex}"
            continue

        tmpk_name = None
        try:
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmpk:
                tmpk.write(key_data)
                tmpk.flush()
                tmpk_name = tmpk.name

            pkey_obj = None
            for pk_class in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
                try:
                    pkey_obj = pk_class.from_private_key_file(tmpk_name)
                    break
                except paramiko.SSHException:
                    continue
                except Exception as ex_inner:
                    saved_output += (
                        f"\nError parsing key with {
                            pk_class.__name__} for {host}: {ex_inner}"
                    )

            if pkey_obj is None:
                saved_output += f"\nAll key parsers failed for {
                    host}. Possibly unsupported key format."
                continue

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

            # If connected, run the command
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
                    return True, saved_output
                else:
                    # Authentication was successful, but command non-zero exit code
                    saved_output += (
                        f"\nCommand on {host} [user={
                            user}] exit code={exit_code}."
                    )
                    return True, saved_output
            except Exception as ex_run:
                saved_output += f"\nError executing command on {
                    host}: {ex_run}"
                ssh.close()
        finally:
            if tmpk_name and os.path.exists(tmpk_name):
                os.remove(tmpk_name)

    return False, saved_output


def wait_until_unpingable(host: str, timeout: int = 300) -> bool:
    """Waits until the host is unreachable by ping or until the timeout elapses.

    Args:
        host: The host to check.
        timeout: How many seconds to wait.

    Returns:
        True if the host became unreachable, otherwise False.
    """
    start = time.time()
    while time.time() - start < timeout:
        if ping_endpoint(host) is None:
            return True
        time.sleep(2)
    return False


def manage_endpoints(
    endpoints: List[Endpoint],
    keys_map: Dict[str, KeyDefinition],
    filters: List[Tuple[str, str, str]],
    cmd: Optional[str],
    do_shutdown: bool,
    do_reboot: bool,
    test_run: bool,
    output_format: str,
    timeout_sec: int,
    threads: int,
) -> Union[str, Dict[str, Dict[str, object]]]:
    """Manages endpoints by performing checks, commands, shutdown, or reboot in wave order.

    Args:
        endpoints: The list of Endpoint objects.
        keys_map: Dictionary of key_name -> KeyDefinition.
        filters: A list of filter tuples (tag_key, operator, test_value).
        cmd: A custom command to run (if any).
        do_shutdown: If True, initiate a shutdown wave in deepest-to-shallowest order.
        do_reboot: If True, initiate a reboot wave in deepest-to-shallowest order.
        test_run: If True, replaces destructive commands with "echo" statements.
        output_format: One of "text", "json", or "yaml".
        timeout_sec: Time in seconds to allow each operation to complete.
        threads: Number of worker threads to use.

    Returns:
        A string representation of the operation results (text, json, yaml)
        or a dictionary if further processing is needed.
    """
    # Filter endpoints
    filtered = [
        ep for ep in endpoints if endpoint_matches_filters(ep, filters)]

    # Sort endpoints by depth descending (deepest first)
    filtered.sort(key=lambda e: e.depth, reverse=True)

    results: Dict[str, Dict[str, object]] = {}

    def worker(e: Endpoint) -> None:
        """Processes a single endpoint in the wave."""
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

        # Ping
        rtt = ping_endpoint(e.fqdn, timeout=1)
        if rtt is not None:
            res["ping_rtt_ms"] = rtt

        # SSH check if credentials
        if e.credentials:
            ssh_success, ssh_output = attempt_ssh_command(
                host=e.fqdn,
                credentials=e.credentials,
                keys_map=keys_map,
                command="echo 'SSH Test Connection'",
                test_run=test_run,
                timeout=5
            )
            res["ssh_check"] = ssh_success
            if ssh_output:
                # Store entire result in 'ssh_version' for visibility
                res["ssh_version"] = ssh_output.replace("\n", " ")

        # Operation
        if cmd is not None:
            # Custom user command
            success, out = attempt_ssh_command(
                host=e.fqdn,
                credentials=e.credentials,
                keys_map=keys_map,
                command=cmd,
                test_run=test_run,
                timeout=timeout_sec
            )
            res["operation_success"] = success
            res["operation_output"] = out

        elif do_shutdown:
            # Shut down using override or default
            default_shutdown_cmd = "sudo shutdown -h now"
            shutdown_cmd = (
                e.overrides.get("shutdown", default_shutdown_cmd)
                if not test_run
                else "echo 'I would shutdown now'"
            )
            success, out = attempt_ssh_command(
                host=e.fqdn,
                credentials=e.credentials,
                keys_map=keys_map,
                command=shutdown_cmd,
                test_run=False,  # We handle "echo" for test_run
                timeout=15
            )
            res["operation_output"] = out
            res["operation_success"] = success

            if success and not test_run:
                # Wait until unreachable
                offline = wait_until_unpingable(e.fqdn, timeout_sec)
                if not offline:
                    res["operation_output"] += f"\nHost still pingable after {
                        timeout_sec}s."
                    res["operation_success"] = False

        elif do_reboot:
            # Reboot using override or default
            default_reboot_cmd = "sudo shutdown -r now"
            reboot_cmd = (
                e.overrides.get("reboot", default_reboot_cmd)
                if not test_run
                else "echo 'I would reboot now'"
            )
            success, out = attempt_ssh_command(
                host=e.fqdn,
                credentials=e.credentials,
                keys_map=keys_map,
                command=reboot_cmd,
                test_run=False,  # We handle "echo" for test_run
                timeout=15
            )
            res["operation_output"] = out
            res["operation_success"] = success

            # For reboot, we also wait until unreachable (mirroring shutdown).
            # This does NOT attempt to see if it comes back up.
            if success and not test_run:
                offline = wait_until_unpingable(e.fqdn, timeout_sec)
                if not offline:
                    res["operation_output"] += f"\nHost still pingable after {
                        timeout_sec}s."
                    res["operation_success"] = False

        results[e.fqdn] = res

    # Process endpoints in waves grouped by depth
    distinct_depths = sorted(set(ep.depth for ep in filtered), reverse=True)
    for depth_lvl in distinct_depths:
        wave_endpoints = [ep for ep in filtered if ep.depth == depth_lvl]
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(worker, wep) for wep in wave_endpoints]
            concurrent.futures.wait(futures)

    # Format output
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
        # Plain-text
        return build_text_report(results)


def build_text_report(results: Dict[str, Dict[str, object]]) -> str:
    """Constructs a human-friendly text table from the results.

    Args:
        results: A dict of fqdn -> result data.

    Returns:
        A multi-line string with columns aligned.
    """
    rows = list(results.values())
    rows.sort(key=lambda x: str(x["fqdn"]))

    # Determine column widths
    max_fqdn_len = max((len(str(r["fqdn"])) for r in rows), default=20)
    max_fqdn_len = max(max_fqdn_len, 20)
    max_type_len = max((len(str(r["type"])) for r in rows), default=8)
    max_type_len = max(max_type_len, 8)

    header_fmt = (
        f"{BLUE}{{:<{max_fqdn_len}}} {{:<{
            max_type_len}}} {{:>5}} {{:>8}} {{:>4}} {{:>9}}{RESET}"
    )
    line_fmt = (
        f"{{:<{max_fqdn_len}}} {{:<{max_type_len}}} {{:>5}} {{:>8}} {{:>4}} {{:>9}}"
    )

    header = header_fmt.format(
        "FQDN", "TYPE", "DEPTH", "PING(ms)", "SSH", "OPERATION")
    lines = [header]

    for r in rows:
        fqdn = str(r["fqdn"])
        dev_type = str(r["type"])
        depth = str(r["depth"])
        ping_ms = r["ping_rtt_ms"]
        ssh_ok = r["ssh_check"]
        op_ok = r["operation_success"]

        ping_str = f"{ping_ms:.2f}" if ping_ms else "N/A"
        ssh_str = f"{GREEN}OK{RESET}" if ssh_ok else f"{RED}NO{RESET}"
        op_str = f"{GREEN}✓{RESET}" if op_ok else f"{RED}✗{RESET}"

        row_line = line_fmt.format(
            fqdn,
            dev_type,
            depth,
            ping_str,
            ssh_str,
            op_str
        )
        lines.append(row_line)

    return "\n".join(lines)


def main() -> None:
    """Main entry point of the manage_hosts script."""
    parser = argparse.ArgumentParser(
        description="Manage Hosts Script - controlling endpoints (host, ups, pdu, router...)"
    )
    parser.add_argument(
        "--config", "-c",
        help=(
            "Path or HTTPS URL to YAML configuration. "
            "Defaults to 'hosts.yaml' or $MANAGE_HOSTS_CONFIG."
        )
    )
    parser.add_argument(
        "--filter", action="append", default=[],
        help="Filter expression in the form key=value or key>value, etc. May be repeated."
    )
    parser.add_argument(
        "--threads",
        type=int,
        help="Override number of threads. Defaults to (#CPUs - 1) or 1."
    )
    parser.add_argument(
        "--test", action="store_true",
        help="Test mode. Replaces actual commands with echo/no-op statements."
    )
    parser.add_argument(
        "--shutdown", action="store_true",
        help="Shut down all filtered endpoints in dependency order."
    )
    parser.add_argument(
        "--reboot", action="store_true",
        help="Reboot all filtered endpoints in dependency order."
    )
    parser.add_argument(
        "--command", "-x",
        help="Execute a command on all filtered endpoints in wave order (deepest first)."
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
        "--timeout",
        type=int,
        help="Timeout in seconds for commands or shutdown. Defaults to 300."
    )

    args = parser.parse_args()

    # If both shutdown and reboot are specified, error out
    if args.shutdown and args.reboot:
        parser.error(
            "Cannot specify both --shutdown and --reboot at the same time.")

    # Determine config source
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

    # Parse keys
    key_section = config_data.get("keys", {})
    if not isinstance(key_section, dict):
        key_section = {}
    keys_map = parse_keys(key_section)

    # Build endpoints
    endpoint_section = config_data.get("endpoints", [])
    if not isinstance(endpoint_section, list):
        endpoint_section = []
    endpoints = build_endpoints(endpoint_section)

    # Calculate dependency depths
    calculate_depths(endpoints)

    # Merge filters from command line + environment
    combined_filters: List[str] = list(args.filter)
    env_filter_str = os.environ.get(ENV_FILTER)
    if env_filter_str:
        try:
            # Expecting a YAML list of strings
            env_filter_list = yaml.safe_load(env_filter_str)
            if isinstance(env_filter_list, list):
                combined_filters.extend(env_filter_list)
        except Exception:
            print(f"{WARNING_EMOJI} Could not parse MANAGE_HOSTS_FILTER as YAML.")

    parsed_filter_tuples = parse_filters(combined_filters)

    # Determine thread count
    import multiprocessing
    cpus = multiprocessing.cpu_count()
    default_threads = max(cpus - 1, 1)
    chosen_threads = args.threads or int(
        os.environ.get(ENV_THREADS, default_threads))

    # Determine test mode
    test_run = args.test or (
        os.environ.get(ENV_TEST, "false").lower() in ["true", "1", "yes"]
    )

    # Determine timeouts
    timeout_sec = args.timeout or int(os.environ.get(ENV_TIMEOUT, "300"))

    # Output format
    if args.json:
        output_format = "json"
    elif args.yaml:
        output_format = "yaml"
    else:
        output_format = "text"

    user_cmd = args.command
    do_shutdown = args.shutdown
    do_reboot = args.reboot

    # If no specific operation is passed, we do a normal check
    # (ping + basic SSH test).
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
        threads=chosen_threads,
    )

    print(results)


if __name__ == "__main__":
    main()
