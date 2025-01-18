"""
Unit tests for manage_hosts.py

This suite uses Python's built-in unittest framework to demonstrate
testing of various functions and classes in manage_hosts.py, including
filter parsing, endpoint building, device-type skip logic, and more.

SSH and network calls are heavily mocked to avoid real external calls.
"""

import unittest
import os
import tempfile
from unittest.mock import patch, MagicMock, mock_open
from typing import List, Dict

# Adjust import paths as appropriate for your project structure:
# from src.manage_hosts import ...
from src.manage_hosts import (
    load_yaml_config,
    parse_keys,
    resolve_key,
    KeyDefinition,
    build_endpoints,
    Endpoint,
    calculate_depths,
    parse_filters,
    endpoint_matches_filters,
    _compare_values,
    manage_endpoints,
)


class TestFilterParsing(unittest.TestCase):
    """Tests for filter parsing and comparisons."""

    def test_parse_filters_basic(self) -> None:
        """Tests basic parsing of filter expressions."""
        filters = [
            "location==sy3",
            "critical != false",
            "floor >= 5",
            "something < 100",
            "type is router"
        ]
        parsed = parse_filters(filters)
        expected_ops = ["==", "!=", ">=", "<", "is"]
        self.assertEqual(len(parsed), len(filters))
        for (k, op, v), eop in zip(parsed, expected_ops):
            self.assertEqual(op, eop)

    def test_compare_values_string_ops(self) -> None:
        """Tests string-based operators (in, not in, is, is not)."""
        self.assertTrue(_compare_values("abc", "in", "b"))
        self.assertFalse(_compare_values("abc", "in", "z"))
        self.assertTrue(_compare_values("abc", "not in", "z"))
        self.assertFalse(_compare_values("abc", "not in", "b"))

        self.assertTrue(_compare_values("router", "is", "router"))
        self.assertFalse(_compare_values("router", "is not", "router"))
        self.assertTrue(_compare_values("switch", "is not", "router"))

    def test_compare_values_numeric_ops(self) -> None:
        """Tests numeric comparison operators."""
        self.assertTrue(_compare_values("3.14", "<", "3.15"))
        self.assertFalse(_compare_values("3.14", ">", "3.15"))
        self.assertTrue(_compare_values("3", ">=", "2.5"))
        self.assertFalse(_compare_values("abc", "<", "123"))


class TestEndpointMatching(unittest.TestCase):
    """Tests endpoint_matches_filters for filtering logic."""

    def setUp(self) -> None:
        self.endpoint1 = Endpoint(
            fqdn="server1",
            dev_type="host",
            tags={"location": "sy3", "critical": "true", "floor": "7"},
            credentials=[],
            host_dependencies=[],
            ups_dependencies=[],
            pdu_dependencies=[],
            overrides={}
        )
        self.endpoint2 = Endpoint(
            fqdn="router1",
            dev_type="router",
            tags={"location": "sy3", "building": "3"},
            credentials=[],
            host_dependencies=[],
            ups_dependencies=[],
            pdu_dependencies=[],
            overrides={}
        )

    def test_endpoint_match(self) -> None:
        """Ensures endpoints match filters on tags or 'type'."""
        flts = parse_filters(["location==sy3"])
        self.assertTrue(endpoint_matches_filters(self.endpoint1, flts))
        self.assertTrue(endpoint_matches_filters(self.endpoint2, flts))

        flts2 = parse_filters(["type is router"])
        self.assertFalse(endpoint_matches_filters(self.endpoint1, flts2))
        self.assertTrue(endpoint_matches_filters(self.endpoint2, flts2))

        flts3 = parse_filters(["floor >= 5"])
        self.assertTrue(endpoint_matches_filters(self.endpoint1, flts3))
        self.assertFalse(endpoint_matches_filters(self.endpoint2, flts3))

    def test_endpoint_no_tag_match(self) -> None:
        """Tests that endpoint fails match if a tag is missing."""
        flts = parse_filters(["rack==12"])
        self.assertFalse(endpoint_matches_filters(self.endpoint1, flts))


class TestLoadYamlConfig(unittest.TestCase):
    """Tests for load_yaml_config."""

    def test_load_local_file(self) -> None:
        """Tests loading a local YAML file."""
        mock_yaml = """
        keys:
          my_key: |
            -----BEGIN KEY-----
            test_data
            -----END KEY-----
        endpoints: []
        """
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(mock_yaml)
            tmp.flush()
            tmp_name = tmp.name
        try:
            config = load_yaml_config(tmp_name)
            self.assertIn("keys", config)
            self.assertIn("endpoints", config)
            text_val = config["keys"]["my_key"].strip()
            self.assertIn("test_data", text_val)
        finally:
            os.remove(tmp_name)

    def test_load_https_url(self) -> None:
        """Tests loading from an https:// URL."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.text = """
        keys:
          dummy_key: "inline_value"
        endpoints: []
        """
        with patch("src.manage_hosts.requests.get", return_value=mock_response) as mock_get:
            config = load_yaml_config("https://example.com/config.yaml")
            mock_get.assert_called_once_with(
                "https://example.com/config.yaml", timeout=10)
            self.assertIn("keys", config)
            self.assertEqual(config["keys"]["dummy_key"], "inline_value")

    def test_load_http_url_raises_error(self) -> None:
        """Ensures that a http:// URL raises ValueError."""
        with self.assertRaises(ValueError):
            load_yaml_config("http://example.com/insecure.yaml")


class TestParseKeys(unittest.TestCase):
    """Tests parse_keys and resolve_key."""

    def test_inline_key(self) -> None:
        """Tests inline key parsing."""
        input_dict = {
            "mykey": "-----BEGIN KEY-----\nSOME_DATA\n-----END KEY-----"
        }
        keys_map = parse_keys(input_dict)
        self.assertIn("mykey", keys_map)
        resolved = resolve_key(keys_map["mykey"])
        self.assertIn("SOME_DATA", resolved)

    def test_dict_key(self) -> None:
        """Tests dict-based key definitions."""
        input_dict = {
            "mykey2": {
                "inline": "inline_data"
            }
        }
        keys_map = parse_keys(input_dict)
        self.assertIn("mykey2", keys_map)
        self.assertEqual(resolve_key(keys_map["mykey2"]), "inline_data")

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data="fake_file_data")
    def test_file_key(self, mock_file: MagicMock, mock_exists: MagicMock) -> None:
        """Ensures file-based key definitions read file content."""
        input_dict = {
            "myfilekey": {
                "file": "/fake/keyfile"
            }
        }
        keys_map = parse_keys(input_dict)
        data = resolve_key(keys_map["myfilekey"])
        self.assertEqual(data, "fake_file_data")

    def test_env_key(self) -> None:
        """Tests env-based key resolution."""
        with patch.dict(os.environ, {"MY_B64": "Zm9vYmFy"}):  # "foobar" in base64
            input_dict = {
                "myenvkey": {
                    "env": "MY_B64"
                }
            }
            keys_map = parse_keys(input_dict)
            self.assertEqual(resolve_key(keys_map["myenvkey"]), "foobar")


class TestBuildEndpoints(unittest.TestCase):
    """Tests build_endpoints and calculate_depths."""

    def test_build_simple_endpoints(self) -> None:
        """Builds endpoints from a minimal YAML-like structure."""
        endpoints_list = [
            {"fqdn": "server1.local", "type": "host", "tags": {"role": "app"}},
            {"fqdn": "router1.local", "type": "router", "tags": {"role": "backbone"}}
        ]
        endpoints = build_endpoints(endpoints_list)
        self.assertEqual(len(endpoints), 2)
        self.assertIsInstance(endpoints[0], Endpoint)
        self.assertIsInstance(endpoints[1], Endpoint)
        self.assertEqual(endpoints[0].fqdn, "server1.local")
        self.assertEqual(endpoints[1].dev_type, "router")

    def test_invalid_type_raises(self) -> None:
        """Raises ValueError for unknown device type."""
        endpoints_list = [
            {"fqdn": "unknown.local", "type": "bogus"}
        ]
        with self.assertRaises(ValueError):
            build_endpoints(endpoints_list)

    def test_calculate_depths(self) -> None:
        """Verifies depth calculation for endpoints."""
        e1 = Endpoint(
            "server1.local",
            "host",
            {},
            [],
            ["router1.local"],
            [],
            [],
            {}
        )
        e2 = Endpoint(
            "router1.local",
            "router",
            {},
            [],
            [],
            [],
            [],
            {}
        )
        endpoints = [e1, e2]
        calculate_depths(endpoints)
        self.assertEqual(e2.depth, 0)
        self.assertEqual(e1.depth, 1)


class TestIncludeDeviceTypes(unittest.TestCase):
    """Tests logic to exclude network/power/storage devices if not requested."""

    def setUp(self) -> None:
        # Basic endpoints of different types
        self.e1 = Endpoint(
            fqdn="server1",
            dev_type="host",
            tags={},
            credentials=[],
            host_dependencies=[],
            ups_dependencies=[],
            pdu_dependencies=[],
            overrides={}
        )
        self.e2 = Endpoint(
            fqdn="router1",
            dev_type="router",
            tags={},
            credentials=[],
            host_dependencies=[],
            ups_dependencies=[],
            pdu_dependencies=[],
            overrides={}
        )
        self.e3 = Endpoint(
            fqdn="filer1",
            dev_type="storage",
            tags={},
            credentials=[],
            host_dependencies=[],
            ups_dependencies=[],
            pdu_dependencies=[],
            overrides={}
        )
        self.e4 = Endpoint(
            fqdn="pdu1",
            dev_type="pdu",
            tags={},
            credentials=[],
            host_dependencies=[],
            ups_dependencies=[],
            pdu_dependencies=[],
            overrides={}
        )
        self.keys_map = {}

    @patch("src.manage_hosts.ping_endpoint", return_value=1.0)
    @patch("src.manage_hosts.attempt_ssh_command", return_value=(True, "test-run", None))
    def test_exclude_network_power_storage(self, mock_ssh: MagicMock, mock_ping: MagicMock) -> None:
        """Ensures that if we do_shutdown or do_reboot without --include-* flags, router, storage, and pdu are excluded."""
        endpoints = [self.e1, self.e2, self.e3, self.e4]
        # No includes => do_shutdown => we only want "server1" to remain
        res_text = manage_endpoints(
            endpoints=endpoints,
            keys_map=self.keys_map,
            filters=[],
            cmd=None,
            do_shutdown=True,
            do_reboot=False,
            test_run=True,
            output_format="text",
            timeout_sec=300,
            threads=1,
            include_network=False,
            include_storage=False,
            include_power=False
        )
        self.assertIsInstance(res_text, str)
        # The text report includes only server1 in the final table
        self.assertIn("server1", res_text)
        self.assertNotIn("router1", res_text)
        self.assertNotIn("filer1", res_text)
        self.assertNotIn("pdu1", res_text)

    @patch("src.manage_hosts.ping_endpoint", return_value=1.0)
    @patch("src.manage_hosts.attempt_ssh_command", return_value=(True, "test-run", None))
    def test_include_network(self, mock_ssh: MagicMock, mock_ping: MagicMock) -> None:
        """Ensures including network devices allows a router to be processed."""
        endpoints = [self.e1, self.e2]
        res = manage_endpoints(
            endpoints=endpoints,
            keys_map=self.keys_map,
            filters=[],
            cmd=None,
            do_shutdown=True,
            do_reboot=False,
            test_run=True,
            output_format="text",
            timeout_sec=300,
            threads=1,
            include_network=True,   # Only difference
            include_storage=False,
            include_power=False
        )
        self.assertIn("server1", res)
        self.assertIn("router1", res)

    @patch("src.manage_hosts.ping_endpoint", return_value=1.0)
    @patch("src.manage_hosts.attempt_ssh_command", return_value=(True, "test-run", None))
    def test_include_storage_power(self, mock_ssh: MagicMock, mock_ping: MagicMock) -> None:
        """Tests that including storage and power devices allows them to be processed."""
        endpoints = [self.e1, self.e3, self.e4]
        res = manage_endpoints(
            endpoints=endpoints,
            keys_map=self.keys_map,
            filters=[],
            cmd=None,
            do_shutdown=True,
            do_reboot=False,
            test_run=True,
            output_format="text",
            timeout_sec=300,
            threads=1,
            include_network=False,
            include_storage=True,
            include_power=True
        )
        self.assertIn("server1", res)
        self.assertIn("filer1", res)
        self.assertIn("pdu1", res)


if __name__ == "__main__":
    unittest.main()
