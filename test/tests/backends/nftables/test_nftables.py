import json
import os
import subprocess
import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path
from time import monotonic, sleep

import yaml

from ..mock_lapi import MockLAPI
from ..utils import generate_n_decisions, new_decision, run_cmd

SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent.parent
BINARY_PATH = PROJECT_ROOT.joinpath("crowdsec-firewall-bouncer")
CONFIG_PATH = SCRIPT_DIR.joinpath("crowdsec-firewall-bouncer.yaml")


class TestNFTables(unittest.TestCase):
    def setUp(self):
        self.fb = subprocess.Popen([BINARY_PATH, "-c", CONFIG_PATH])
        self.lapi = MockLAPI()
        self.lapi.start()
        return super().setUp()

    def tearDown(self):
        self.fb.kill()
        self.fb.wait()
        self.lapi.stop()
        run_cmd("nft", "delete", "table", "ip", "crowdsec", ignore_error=True)
        run_cmd("nft", "delete", "table", "ip6", "crowdsec6", ignore_error=True)

    def test_table_rule_set_are_created(self):
        d1 = generate_n_decisions(3)
        d2 = generate_n_decisions(1, ipv4=False)
        self.lapi.ds.insert_decisions(d1 + d2)
        sleep(1)
        output = json.loads(run_cmd("nft", "-j", "list", "tables"))
        tables = {(node["table"]["family"], node["table"]["name"]) for node in output["nftables"] if "table" in node}
        assert ("ip6", "crowdsec6") in tables
        assert ("ip", "crowdsec") in tables

        # IPV4
        output = json.loads(run_cmd("nft", "-j", "list", "table", "ip", "crowdsec"))
        sets = {
            (node["set"]["family"], node["set"]["name"], node["set"]["type"])
            for node in output["nftables"]
            if "set" in node
        }
        assert ("ip", "crowdsec-blacklists-script", "ipv4_addr") in sets
        rules = {node["rule"]["chain"] for node in output["nftables"] if "rule" in node}  # maybe stricter check ?
        assert "crowdsec-chain-forward" in rules
        assert "crowdsec-chain-input" in rules

        # IPV6
        output = json.loads(run_cmd("nft", "-j", "list", "table", "ip6", "crowdsec6"))
        sets = {
            (node["set"]["family"], node["set"]["name"], node["set"]["type"])
            for node in output["nftables"]
            if "set" in node
        }
        assert ("ip6", "crowdsec6-blacklists-script", "ipv6_addr") in sets

        rules = {node["rule"]["chain"] for node in output["nftables"] if "rule" in node}  # maybe stricter check ?
        assert "crowdsec6-chain-input" in rules
        assert "crowdsec6-chain-forward" in rules

    def test_duplicate_decisions_across_decision_stream(self):
        d1, d2, d3 = generate_n_decisions(3, dup_count=1)
        self.lapi.ds.insert_decisions([d1])
        sleep(1)
        self.assertEqual(
            get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script"),
            {"0.0.0.0"},
        )

        self.lapi.ds.insert_decisions([d2, d3])
        sleep(1)
        assert self.fb.poll() is None
        self.assertEqual(
            get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script"),
            {"0.0.0.0", "0.0.0.1"},
        )

        self.lapi.ds.delete_decision_by_id(d1["id"])
        self.lapi.ds.delete_decision_by_id(d2["id"])
        sleep(1)
        self.assertEqual(get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script"), set())
        assert self.fb.poll() is None

        self.lapi.ds.delete_decision_by_id(d3["id"])
        sleep(1)
        self.assertEqual(get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script"), set())
        assert self.fb.poll() is None

    def test_decision_insertion_deletion_ipv4(self):
        total_decisions, duplicate_decisions = 500, 23
        decisions = generate_n_decisions(total_decisions, dup_count=duplicate_decisions)
        self.lapi.ds.insert_decisions(decisions)
        sleep(1)  # let the bouncer insert the decisions

        set_elements = get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script")
        self.assertEqual(len(set_elements), total_decisions - duplicate_decisions)
        assert {i["value"] for i in decisions} == set_elements
        assert "0.0.0.0" in set_elements

        self.lapi.ds.delete_decisions_by_ip("0.0.0.0")
        sleep(1)

        set_elements = get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script")
        assert {i["value"] for i in decisions if i["value"] != "0.0.0.0"} == set_elements
        assert len(set_elements) == total_decisions - duplicate_decisions - 1
        assert "0.0.0.0" not in set_elements

    def test_decision_insertion_deletion_ipv6(self):
        total_decisions, duplicate_decisions = 500, 23
        decisions = generate_n_decisions(total_decisions, dup_count=duplicate_decisions, ipv4=False)
        self.lapi.ds.insert_decisions(decisions)
        sleep(1)

        set_elements = get_set_elements("ip6", "crowdsec6", "crowdsec6-blacklists-script")
        set_elements = set(map(ip_address, set_elements))
        assert len(set_elements) == total_decisions - duplicate_decisions
        assert {ip_address(i["value"]) for i in decisions} == set_elements
        assert ip_address("::1:0:3") in set_elements

        self.lapi.ds.delete_decisions_by_ip("::1:0:3")
        sleep(1)

        set_elements = get_set_elements("ip6", "crowdsec6", "crowdsec6-blacklists-script")
        set_elements = set(map(ip_address, set_elements))
        self.assertEqual(len(set_elements), total_decisions - duplicate_decisions - 1)
        assert (
            {ip_address(i["value"]) for i in decisions if ip_address(i["value"]) != ip_address("::1:0:3")}
        ) == set_elements
        assert ip_address("::1:0:3") not in set_elements

    def test_timeout_refresh_across_stream_updates(self):
        self.check_timeout_refresh()

    def test_set_only_timeout_refresh_across_stream_updates(self):
        self.fb.kill()
        self.fb.wait()
        config = yaml.safe_load(CONFIG_PATH.read_text())
        for family, table, datatype, blacklist in (("ip", "crowdsec", "ipv4_addr", "crowdsec-blacklists"),
                                                    ("ip6", "crowdsec6", "ipv6_addr", "crowdsec6-blacklists")):
            run_cmd("nft", "add", "table", family, table)
            run_cmd("nft", "add", "set", family, table, blacklist, f"{{ type {datatype}; flags timeout; }}")
        for family in ("ipv4", "ipv6"):
            config["nftables"][family]["set-only"] = True
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "firewall.yaml"
            path.write_text(yaml.safe_dump(config))
            self.fb = subprocess.Popen([BINARY_PATH, "-c", path])
            self.check_timeout_refresh(set_only=True)

    def wait_for_sets(self, addresses, timeout=10):
        deadline = monotonic() + timeout
        for address in addresses:
            command = ("nft", "-j", "list", "set", *address[:3])
            last_error = "query deadline elapsed"
            while monotonic() < deadline:
                self.assertIsNone(self.fb.poll(), "bouncer exited while waiting for nft sets")
                try:
                    result = subprocess.run(command, capture_output=True, text=True, timeout=1)
                except subprocess.TimeoutExpired as error:
                    last_error = str(error)
                else:
                    if result.returncode == 0:
                        break
                    last_error = f"exit code {result.returncode}: {result.stderr}{result.stdout}"
                sleep(0.01)
            else:
                self.fail(f"nft set query did not succeed before deadline: {command}: {last_error}")

    def check_timeout_refresh(self, *, set_only=False):
        suffix = "" if set_only else "-script"
        addresses = (("ip", "crowdsec", "crowdsec-blacklists" + suffix, "192.0.2.1"),
                     ("ip6", "crowdsec6", "crowdsec6-blacklists" + suffix, "2001:db8::1"))

        def wait_for(predicate, timeout=10):
            deadline = monotonic() + timeout
            while monotonic() < deadline:
                assert self.fb.poll() is None
                if predicate():
                    return
                sleep(0.01)
            self.fail("nft timeout update did not converge")

        def insert(duration):
            decisions = [new_decision(address[3]) | {"duration": duration} for address in addresses]
            self.lapi.ds.insert_decisions(decisions)
            return decisions

        def remaining(address):
            return next(iter(get_set_elements(*address[:3], with_expires=True)), (None, 0))[1]

        short = insert("3s")
        original_expiry = monotonic() + 3
        self.wait_for_sets(addresses)
        wait_for(lambda: all(remaining(address) > 0 for address in addresses))
        # This mock does not implement LAPI sibling deduplication. Retire its
        # old selected records without emitting a deletion: the real stream
        # keeps the effective ban while a later longer sibling is active.
        self.lapi.ds.decisions = [d for d in self.lapi.ds.decisions if d not in short]
        long = [new_decision(address[3]) | {"duration": "8s"} for address in addresses]
        # Equivalent textual IPv6 addresses must not produce duplicate keys
        # in the replacement batch; keep the longest timeout for one key.
        long.append(new_decision("2001:db8:0:0:0:0:0:1") | {"duration": "4s"})
        self.lapi.ds.insert_decisions(long)
        wait_for(lambda: all(remaining(address) > 6 for address in addresses))
        refreshed_expiry = monotonic() + min(remaining(address) for address in addresses)
        self.lapi.ds.decisions = [d for d in self.lapi.ds.decisions if d["duration"] != "4s"]

        shorter = insert("1s")
        pull = self.lapi.ds.bouncer_lastpull_by_api_key.copy()
        wait_for(lambda: self.lapi.ds.bouncer_lastpull_by_api_key != pull)
        assert all(remaining(address) > 6 for address in addresses)
        self.lapi.ds.decisions = [d for d in self.lapi.ds.decisions if d not in shorter]

        assert refreshed_expiry > original_expiry
        while monotonic() < refreshed_expiry - 0.2:
            assert all(remaining(address) > 0 for address in addresses)
            sleep(0.02)
        wait_for(lambda: all(not get_set_elements(*address[:3]) for address in addresses))
        # Natural expiration and a repeated explicit removal both remain safe.
        for decision in long:
            self.lapi.ds.delete_decision_by_id(decision["id"])
        sleep(0.1)
        assert self.fb.poll() is None


    def test_longest_decision_insertion(self):
        decisions = [
            {
                "value": "123.45.67.12",
                "scope": "ip",
                "type": "ban",
                "origin": "script",
                "duration": f"{i}h",
                "reason": "for testing",
            }
            for i in range(1, 201)
        ]
        self.lapi.ds.insert_decisions(decisions)
        sleep(1)
        elems = get_set_elements("ip", "crowdsec", "crowdsec-blacklists-script", with_timeout=True)
        assert len(elems) == 1
        elems = list(elems)
        assert elems[0][0] == "123.45.67.12"
        assert abs(elems[0][1] - 200 * 60 * 60) <= 3


def get_set_elements(family, table_name, set_name, with_timeout=False, with_expires=False):
    output = json.loads(run_cmd("nft", "-j", "list", "set", family, table_name, set_name))
    for node in output["nftables"]:
        if "set" not in node or "elem" not in node["set"]:
            continue
        if not isinstance(node["set"]["elem"][0], dict):
            return set(node["set"]["elem"])

        if not with_timeout and not with_expires:
            return {elem["elem"]["val"] for elem in node["set"]["elem"]}
        field = "expires" if with_expires else "timeout"
        return {(elem["elem"]["val"], elem["elem"][field]) for elem in node["set"]["elem"]}
    return set()
