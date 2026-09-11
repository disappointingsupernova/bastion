"""Unit tests for the IP allowlist enforcement module."""

from __future__ import annotations

import json

import pytest

from bastion.ip_allowlist import check_ip_allowed


class TestCheckIpAllowed:
    """Tests for check_ip_allowed."""

    def test_none_allowlist_permits_all(self):
        """A None allowlist must permit any IP."""
        assert check_ip_allowed("1.2.3.4", None) is True

    def test_empty_string_allowlist_permits_all(self):
        """An empty string allowlist must permit any IP."""
        assert check_ip_allowed("1.2.3.4", "") is True

    def test_empty_list_permits_all(self):
        """An empty JSON array allowlist must permit any IP."""
        assert check_ip_allowed("1.2.3.4", "[]") is True

    def test_exact_ip_match_permitted(self):
        """An IP that exactly matches a /32 CIDR must be permitted."""
        allowlist = json.dumps(["192.168.1.5/32"])
        assert check_ip_allowed("192.168.1.5", allowlist) is True

    def test_ip_in_subnet_permitted(self):
        """An IP within a CIDR range must be permitted."""
        allowlist = json.dumps(["10.0.0.0/8"])
        assert check_ip_allowed("10.99.1.200", allowlist) is True

    def test_ip_outside_subnet_denied(self):
        """An IP outside all listed CIDRs must be denied."""
        allowlist = json.dumps(["10.0.0.0/8"])
        assert check_ip_allowed("192.168.1.1", allowlist) is False

    def test_multiple_cidrs_first_matches(self):
        """An IP matching the first of multiple CIDRs must be permitted."""
        allowlist = json.dumps(["10.0.0.0/8", "172.16.0.0/12"])
        assert check_ip_allowed("10.1.2.3", allowlist) is True

    def test_multiple_cidrs_second_matches(self):
        """An IP matching the second of multiple CIDRs must be permitted."""
        allowlist = json.dumps(["10.0.0.0/8", "172.16.0.0/12"])
        assert check_ip_allowed("172.20.0.1", allowlist) is True

    def test_multiple_cidrs_none_match(self):
        """An IP matching none of multiple CIDRs must be denied."""
        allowlist = json.dumps(["10.0.0.0/8", "172.16.0.0/12"])
        assert check_ip_allowed("8.8.8.8", allowlist) is False

    def test_invalid_json_denies(self):
        """Malformed JSON in the allowlist must deny access."""
        assert check_ip_allowed("1.2.3.4", "not-json") is False

    def test_invalid_cidr_in_list_skipped(self):
        """An invalid CIDR entry must be skipped; valid entries still checked."""
        allowlist = json.dumps(["not-a-cidr", "192.168.1.0/24"])
        assert check_ip_allowed("192.168.1.50", allowlist) is True

    def test_invalid_cidr_only_denies(self):
        """If all CIDRs are invalid, access must be denied."""
        allowlist = json.dumps(["not-a-cidr", "also-bad"])
        assert check_ip_allowed("1.2.3.4", allowlist) is False

    def test_invalid_source_ip_denies(self):
        """An unparseable source IP must be denied."""
        allowlist = json.dumps(["10.0.0.0/8"])
        assert check_ip_allowed("not-an-ip", allowlist) is False

    def test_ipv6_address_in_ipv6_subnet(self):
        """An IPv6 address within an IPv6 CIDR must be permitted."""
        allowlist = json.dumps(["2001:db8::/32"])
        assert check_ip_allowed("2001:db8::1", allowlist) is True

    def test_ipv6_address_outside_subnet(self):
        """An IPv6 address outside the listed CIDR must be denied."""
        allowlist = json.dumps(["2001:db8::/32"])
        assert check_ip_allowed("2001:db9::1", allowlist) is False

    def test_loopback_in_loopback_range(self):
        """127.0.0.1 must be permitted when 127.0.0.0/8 is listed."""
        allowlist = json.dumps(["127.0.0.0/8"])
        assert check_ip_allowed("127.0.0.1", allowlist) is True

    def test_host_route_exact_match_only(self):
        """A /32 host route must only match that exact IP."""
        allowlist = json.dumps(["192.168.1.1/32"])
        assert check_ip_allowed("192.168.1.2", allowlist) is False
        assert check_ip_allowed("192.168.1.1", allowlist) is True
