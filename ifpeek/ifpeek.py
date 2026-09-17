#!/usr/bin/env python3

"""
Inspect Linux network interfaces, Wi-Fi state, routes, DNS, and network events from Python.
"""

from typing import Any, Dict, Iterator, List, NamedTuple, Optional

from select import select
from socket import AF_INET, AF_INET6
from pathlib import Path
from time import monotonic, sleep

from pyroute2 import IPRoute
from pyroute2.iwutil import IW
from pyroute2.netlink.rtnl import (
    RTMGRP_IPV4_IFADDR,
    RTMGRP_IPV4_ROUTE,
    RTMGRP_IPV6_IFADDR,
    RTMGRP_IPV6_ROUTE,
    RTMGRP_LINK,
)

# ARPHRD interface hardware types (from linux/if_arp.h).
_ARPHRD_ETHER = 1
_ARPHRD_LOOPBACK = 772

# Netlink multicast groups watch() subscribes to (link, address, route; no neighbour noise).
_WATCH_GROUPS = (
    RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR
    | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE
)


def __get_interface_names() -> List[str]:
    """ Return all network interface names (from pyroute2.IPRoute). """
    with IPRoute() as ipr:
        return [link.get_attr("IFLA_IFNAME") for link in ipr.get_links()]


def __is_wireless(interface: str) -> bool:
    """ True if `interface` is a wireless device (per sysfs). """
    return (
        Path(f"/sys/class/net/{interface}/wireless").exists()
        or Path(f"/sys/class/net/{interface}/phy80211").exists()
    )


def interface_type(interface: str) -> str:
    """
    Classify an interface: "loopback", "ethernet", "wifi", the kernel's kind for
    virtual interfaces ("bridge", "tun", "vlan", "bond", "wireguard", "veth", ...),
    or "unknown".

    :param interface: str: Network interface.

    """
    with IPRoute() as ipr:
        links = ipr.get_links(ifname=interface)
    if not links:
        return "unknown"
    link = links[0]
    linkinfo = link.get_attr("IFLA_LINKINFO")
    if linkinfo is not None:
        kind = linkinfo.get_attr("IFLA_INFO_KIND")
        if kind is not None:
            return kind
    if link["ifi_type"] == _ARPHRD_LOOPBACK:
        return "loopback"
    if link["ifi_type"] == _ARPHRD_ETHER:
        return "wifi" if __is_wireless(interface) else "ethernet"
    return "unknown"


def get_loopback_interface() -> List[str]:
    """ Return a list of loopback interfaces (ideally one). """
    return [i for i in __get_interface_names() if interface_type(i) == "loopback"]


def get_eth_interfaces() -> List[str]:
    """ Return a list of ethernet interfaces (ideally one). """
    return [i for i in __get_interface_names() if interface_type(i) == "ethernet"]


def get_wifi_interfaces() -> List[str]:
    """ Return list of wifi interfaces (ideally one). """
    return [i for i in __get_interface_names() if interface_type(i) == "wifi"]


def __get_associated_station(interface: str) -> Any:
    """
    Return nl80211 station info for the AP `interface` is associated to, or None.

    In managed (client) mode the single station is the access point, so its MAC
    is the BSSID and its signal is the AP signal. Uses nl80211 via pyroute2:
    no external tools, no root.
    """
    ifindex = __get_interface_number(interface)
    if ifindex is None:
        return None
    try:
        with IW() as iw:
            for station in iw.get_stations(ifindex):
                return station
    except Exception:
        # Not wireless, not associated, or nl80211 unavailable.
        return None
    return None


def __winterface_name_to_device_dict(interface: str) -> Any:
    """ Return a dict containing device details (from pyroute2.IW). """
    with IW() as iw:
        for device_dict in iw.list_dev():
            if device_dict.get_attr("NL80211_ATTR_IFNAME") == interface:
                return device_dict
    return None


def __get_interface_number(interface: str) -> Optional[int]:
    """ Return the interface number (from pyroute2.IPRoute). """
    with IPRoute() as ipr:
        interface_number_list = ipr.link_lookup(ifname=interface)
        if len(interface_number_list) > 0:
            return interface_number_list[0]
    return None


def __get_interface_stats(interface: str) -> Any:
    """ Return the interface stats object (from pyroute2.IPRoute), or None. """
    with IPRoute() as ipr:
        links = ipr.get_links(ifname=interface)
    if not links:
        return None
    return links[0].get_attr("IFLA_STATS64") or links[0].get_attr("IFLA_STATS")


def interface_operstate(interface: str) -> Optional[str]:
    """
    Get the operstate of an interface as reported by the kernel: "UP", "DOWN",
    "DORMANT" (e.g. a Wi-Fi association in progress), "LOWERLAYERDOWN",
    "NOTPRESENT", "TESTING" or "UNKNOWN". None if the interface does not exist.

    :param interface: str: Network interface.

    """
    with IPRoute() as ipr:
        links = ipr.get_links(ifname=interface)
    return links[0].get_attr("IFLA_OPERSTATE") if links else None


def interface_mac_address(interface: str) -> Optional[str]:
    """
    Get the MAC address of an interface, or None if it cannot be resolved.

    :param interface: str: Network interface.

    """
    with IPRoute() as ipr:
        links = ipr.get_links(ifname=interface)
    return links[0].get_attr("IFLA_ADDRESS") if links else None


def interface_recv_bytes(interface: str) -> Optional[int]:
    """
    Get the recv bytes of an interface, or None if it cannot be resolved.

    :param interface: str: Network interface.

    """
    stats = __get_interface_stats(interface)
    return stats["rx_bytes"] if stats is not None else None


def interface_sent_bytes(interface: str) -> Optional[int]:
    """
    Get the sent bytes of an interface, or None if it cannot be resolved.

    :param interface: str: Network interface.

    """
    stats = __get_interface_stats(interface)
    return stats["tx_bytes"] if stats is not None else None


def interface_mtu(interface: str) -> Optional[int]:
    """
    Get the MTU of an interface.

    :param interface: str: Network interface.

    """
    with IPRoute() as ipr:
        links = ipr.get_links(ifname=interface)
    if links:
        return links[0].get_attr("IFLA_MTU")
    return None


def interface_has_carrier(interface: str) -> Optional[bool]:
    """
    Whether an interface has a carrier (a physical link / association), or None.

    :param interface: str: Network interface.

    """
    with IPRoute() as ipr:
        links = ipr.get_links(ifname=interface)
    if links:
        carrier = links[0].get_attr("IFLA_CARRIER")
        if carrier is not None:
            return bool(carrier)
    return None


class InterfaceStats(NamedTuple):
    """ Cumulative traffic counters for an interface. """
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errors: int
    tx_errors: int
    rx_dropped: int
    tx_dropped: int


# The sysfs roots rfkill is read from, named so tests can point them at a
# harmless tree instead of this machine's.
_SYSFS_NET = "/sys/class/net"
_SYSFS_RFKILL = "/sys/class/rfkill"


def __read_sysfs(path: Path) -> Optional[str]:
    """ The contents of a sysfs file, stripped, or None if it cannot be read. """
    try:
        return path.read_text().strip()
    except OSError:
        return None


def interface_rfkill(interface: str) -> Optional[str]:
    """
    Whether rfkill has the radio behind `interface` switched off: "hard", "soft",
    or None when nothing is blocking it or the kernel lists no switch for it.

    A soft block is software (an airplane-mode key, `rfkill block wifi`); a hard
    block is a physical switch or the firmware. Either way the radio transmits
    nothing and hears nothing, so a scan comes back empty, which is also what a
    room with no Wi-Fi in it looks like.

    This is deliberately not `interface_operstate` or `interface_has_carrier`.
    Both of those are about the association: a Wi-Fi interface carried around
    with no network joined reads DOWN, with no carrier, while its radio is on
    and hearing dozens of access points. Neither can tell a switched-off radio
    from an empty room. Only rfkill can.

    The switch belongs to the interface's phy, which sysfs links at
    `phy80211`. Some drivers do not expose it there, so a switch registered
    under the phy's own name is looked for as well.

    :param interface: str: Network interface.

    """
    phy = Path(f"{_SYSFS_NET}/{interface}/phy80211")
    switches = sorted(phy.glob("rfkill*"))
    if not switches:
        name = __read_sysfs(phy / "name")
        if name:
            switches = [
                switch
                for switch in sorted(Path(_SYSFS_RFKILL).glob("rfkill*"))
                if __read_sysfs(switch / "name") == name
            ]
    states = [
        (__read_sysfs(switch / "hard"), __read_sysfs(switch / "soft"))
        for switch in switches
    ]
    if any(hard == "1" for hard, _ in states):
        return "hard"
    if any(soft == "1" for _, soft in states):
        return "soft"
    return None


def interface_stats(interface: str) -> Optional[InterfaceStats]:
    """
    Get the full traffic counters of an interface (bytes, packets, errors, dropped).

    :param interface: str: Network interface.

    """
    stats = __get_interface_stats(interface)
    if stats is None:
        return None
    return InterfaceStats(
        rx_bytes=stats["rx_bytes"], tx_bytes=stats["tx_bytes"],
        rx_packets=stats["rx_packets"], tx_packets=stats["tx_packets"],
        rx_errors=stats["rx_errors"], tx_errors=stats["tx_errors"],
        rx_dropped=stats["rx_dropped"], tx_dropped=stats["tx_dropped"],
    )


class InterfaceRate(NamedTuple):
    """ Throughput of an interface, in bytes per second. """
    rx_bytes_per_sec: float
    tx_bytes_per_sec: float


def interface_rate(interface: str, interval: float = 1.0) -> Optional[InterfaceRate]:
    """
    Measure an interface's throughput over `interval` seconds (this blocks for that long).

    :param interface: str: Network interface.
    :param interval: float: Sampling window in seconds.

    """
    first = interface_stats(interface)
    start = monotonic()
    if first is None:
        return None
    sleep(interval)
    second = interface_stats(interface)
    elapsed = monotonic() - start
    if second is None or elapsed <= 0:
        return None
    return InterfaceRate(
        rx_bytes_per_sec=(second.rx_bytes - first.rx_bytes) / elapsed,
        tx_bytes_per_sec=(second.tx_bytes - first.tx_bytes) / elapsed,
    )


def access_point_essid(interface: str) -> Optional[str]:
    """
    Get the AP ESSID.

    :param interface: str: Network interface.

    """
    device_dict = __winterface_name_to_device_dict(interface)
    if device_dict is not None:
        return device_dict.get_attr("NL80211_ATTR_SSID")
    return None


def access_point_signal_dbm(interface: str) -> Optional[int]:
    """
    Get the AP signal strength in dBm (e.g. -30; closer to 0 is stronger).

    :param interface: str: Network interface.

    """
    station = __get_associated_station(interface)
    if station is not None:
        sta_info = station.get_attr("NL80211_ATTR_STA_INFO")
        if sta_info is not None:
            return sta_info.get_attr("NL80211_STA_INFO_SIGNAL")
    return None


def access_point_signal_percent(interface: str) -> Optional[int]:
    """
    Get the AP signal as an approximate 0-100 percentage, derived from the dBm
    reading. Lossy convenience; prefer access_point_signal_dbm().

    :param interface: str: Network interface.

    """
    dbm = access_point_signal_dbm(interface)
    if dbm is None:
        return None
    # Heuristic: -100 dBm -> 0 %, -50 dBm (or stronger) -> 100 %.
    return min(max(2 * (dbm + 100), 0), 100)


def access_point_mac_address(interface: str) -> Optional[str]:
    """
    Get the AP MAC (BSSID) of the access point `interface` is associated to.

    :param interface: str: Network interface.

    """
    station = __get_associated_station(interface)
    if station is not None:
        mac = station.get_attr("NL80211_ATTR_MAC")
        if mac is not None:
            return mac.lower()
    return None


def access_point_frequency(interface: str) -> Optional[int]:
    """
    Get the frequency (MHz) of the access point `interface` is associated to, or None.

    :param interface: str: Network interface.

    """
    device_dict = __winterface_name_to_device_dict(interface)
    if device_dict is not None:
        return device_dict.get_attr("NL80211_ATTR_WIPHY_FREQ")
    return None


def access_point_bitrate(interface: str) -> Optional[float]:
    """
    Get the current tx bitrate (Mbps) to the associated access point, or None.

    :param interface: str: Network interface.

    """
    station = __get_associated_station(interface)
    if station is not None:
        sta_info = station.get_attr("NL80211_ATTR_STA_INFO")
        if sta_info is not None:
            tx = sta_info.get_attr("NL80211_STA_INFO_TX_BITRATE")
            if tx is not None:
                rate = (tx.get_attr("NL80211_RATE_INFO_BITRATE32")
                        or tx.get_attr("NL80211_RATE_INFO_BITRATE"))
                if rate is not None:
                    return rate / 10  # units of 100 kbps -> Mbps
    return None


def __interface_addresses(interface: str, family: int) -> List[str]:
    """ Return the `family` addresses assigned to `interface`, matched by
    ifindex (IFA_LABEL is absent for IPv6, so the label cannot be relied on). """
    ifindex = __get_interface_number(interface)
    if ifindex is None:
        return []
    with IPRoute() as ipr:
        return [
            addr.get_attr("IFA_ADDRESS")
            for addr in ipr.get_addr()
            if addr["index"] == ifindex and addr["family"] == family
        ]


def interface_ipv4_addresses(interface: str) -> List[str]:
    """
    Get the IPv4 addresses assigned to an interface.

    :param interface: str: Network interface.

    """
    return __interface_addresses(interface, AF_INET)


def interface_ipv6_addresses(interface: str) -> List[str]:
    """
    Get the IPv6 addresses assigned to an interface.

    :param interface: str: Network interface.

    """
    return __interface_addresses(interface, AF_INET6)


def __default_gateway(family: int) -> Optional[str]:
    """ Return the default-route gateway for `family`, or None. """
    with IPRoute() as ipr:
        for route in ipr.get_default_routes():
            if route["family"] == family:
                gateway = route.get_attr("RTA_GATEWAY")
                if gateway is not None:
                    return gateway
    return None


def default_gateway_ipv4() -> Optional[str]:
    """ Get the IPv4 default gateway (next hop of the default route), or None. """
    return __default_gateway(AF_INET)


def default_gateway_ipv6() -> Optional[str]:
    """ Get the IPv6 default gateway (next hop of the default route), or None. """
    return __default_gateway(AF_INET6)


def __default_route_oif(routes, family):
    for route in routes:
        if route["family"] == family:
            oif = route.get_attr("RTA_OIF")
            if oif is not None:
                return oif
    return None


def default_interface() -> Optional[str]:
    """ Name of the interface backing the default route (IPv4, else IPv6), or None. """
    with IPRoute() as ipr:
        routes = ipr.get_default_routes()
        oif = __default_route_oif(routes, AF_INET) or __default_route_oif(routes, AF_INET6)
        if oif is None:
            return None
        links = ipr.get_links(oif)
        return links[0].get_attr("IFLA_IFNAME") if links else None


class NetworkEvent(NamedTuple):
    """ A network change reported by the kernel via netlink. """
    kind: str                  # "link" | "address" | "route"
    action: str                # "new" | "del"
    interface: Optional[str]   # interface name (best-effort; None for routes)
    index: int                 # interface index (0 when not applicable)
    detail: Dict[str, Any]     # kind-specific extras


def __to_network_event(msg) -> Optional[NetworkEvent]:
    """ Translate a raw netlink message into a NetworkEvent, or None to skip it. """
    event = msg.get("event")
    if event in ("RTM_NEWLINK", "RTM_DELLINK"):
        return NetworkEvent(
            kind="link",
            action="del" if event == "RTM_DELLINK" else "new",
            interface=msg.get_attr("IFLA_IFNAME"),
            index=msg.get("index", 0),
            detail={"operstate": msg.get_attr("IFLA_OPERSTATE")},
        )
    if event in ("RTM_NEWADDR", "RTM_DELADDR"):
        return NetworkEvent(
            kind="address",
            action="del" if event == "RTM_DELADDR" else "new",
            interface=msg.get_attr("IFA_LABEL"),
            index=msg.get("index", 0),
            detail={
                "address": msg.get_attr("IFA_ADDRESS"),
                "family": "inet6" if msg.get("family") == AF_INET6 else "inet",
            },
        )
    if event in ("RTM_NEWROUTE", "RTM_DELROUTE"):
        return NetworkEvent(
            kind="route",
            action="del" if event == "RTM_DELROUTE" else "new",
            interface=None,
            index=msg.get_attr("RTA_OIF") or 0,
            detail={
                "gateway": msg.get_attr("RTA_GATEWAY"),
                "dst_len": msg.get("dst_len", 0),
                "family": "inet6" if msg.get("family") == AF_INET6 else "inet",
            },
        )
    return None


def __event_matches(
    event: NetworkEvent, interface: str, ifindex: Optional[int]
) -> bool:
    """ True if `event` belongs to `interface`. Matches by interface index when
    it could be resolved (route and IPv6 address events carry no interface
    name), falling back to the name carried by the event. """
    if event.interface == interface:
        return True
    return ifindex is not None and event.index == ifindex


def watch(
    interface: Optional[str] = None,
    timeout: Optional[float] = None,
) -> Iterator[Optional[NetworkEvent]]:
    """
    Yield NetworkEvent objects as the kernel reports link / address / route changes.

    This blocks between events (it is a live monitor). If `interface` is given,
    only that interface's events are yielded, matched by interface index, so
    route and IPv6 address events (which carry no interface name) are included.
    If `timeout` is given, None is yielded whenever that many seconds pass
    without an event, so a caller can run periodic work (e.g. a health check)
    on the same thread. Uses netlink, no root.

    :param interface: str: Limit to this interface (optional).
    :param timeout: float: Idle interval in seconds after which None is
        yielded (optional; without it, the iterator blocks until an event).

    """
    ifindex = __get_interface_number(interface) if interface is not None else None
    with IPRoute() as ipr:
        ipr.bind(_WATCH_GROUPS)
        while True:
            if timeout is not None:
                if not select([ipr], [], [], timeout)[0]:
                    yield None
                    continue
            for msg in ipr.get():
                event = __to_network_event(msg)
                if event is None:
                    continue
                if interface is not None and not __event_matches(
                        event, interface, ifindex):
                    continue
                yield event


# systemd-resolved writes the real upstream servers to the /run file; plain
# /etc/resolv.conf may just be the 127.0.0.53 stub, so prefer /run and fall back.
_RESOLV_CONF_PATHS = (
    "/run/systemd/resolve/resolv.conf",
    "/etc/resolv.conf",
)


def dns_servers() -> List[str]:
    """
    Get the configured DNS nameservers.

    Prefers systemd-resolved's real upstream list, falling back to
    /etc/resolv.conf. Uses only the standard library.
    """
    for path in _RESOLV_CONF_PATHS:
        resolv = Path(path)
        if not resolv.exists():
            continue
        servers = []
        for line in resolv.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                servers.append(parts[1])
        if servers:
            return servers
    return []
