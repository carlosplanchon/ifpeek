#!/usr/bin/env python3

"""
Nearby Wi-Fi access-point scanning via a system Wi-Fi daemon over D-Bus.

Optional feature: needs the ``scan`` extra (``uv add "ifpeek[scan]"``, which pulls
in ``jeepney``). It auto-detects and uses whichever Wi-Fi daemon is running: **iwd**
(``net.connman.iwd``), **NetworkManager** (``org.freedesktop.NetworkManager``) or
**wpa_supplicant** (``fi.w1.wpa_supplicant1``).

Triggering a scan is a privileged operation, so it is delegated to the daemon:
results reflect the daemon's current view, and ``fresh=True`` asks the daemon to
scan first. Neither needs root (the caller must be allowed on the daemon's D-Bus,
e.g. be in the ``wheel``/``network`` group). Per-BSS details a daemon does not
expose (iwd reports one signal per network and no frequency; NetworkManager reports
no dBm) are completed from the kernel's own scan cache, read over nl80211 with
pyroute2, which is unprivileged too.
"""

from time import monotonic, sleep
from typing import NamedTuple

from pyroute2 import IPRoute
from pyroute2.netlink import NLM_F_DUMP, NLM_F_REQUEST
from pyroute2.netlink.nl80211 import NL80211, NL80211_NAMES, nl80211cmd

from ifpeek.ifpeek import access_point_mac_address

try:
    from jeepney import DBusAddress, MessageType, new_method_call
    from jeepney.io.blocking import open_dbus_connection
    _HAVE_JEEPNEY = True
except ImportError:  # pragma: no cover - only without the scan extra
    _HAVE_JEEPNEY = False


_IWD = "net.connman.iwd"
_NM = "org.freedesktop.NetworkManager"
_NM_PATH = "/org/freedesktop/NetworkManager"
_NM_DEVICE_TYPE_WIFI = 2
# NM80211ApSecurityFlags bits used to label a network's security.
_NM_SEC_PSK = 0x100      # NM_802_11_AP_SEC_KEY_MGMT_PSK
_NM_SEC_8021X = 0x200    # NM_802_11_AP_SEC_KEY_MGMT_802_1X

_WPAS = "fi.w1.wpa_supplicant1"
_WPAS_PATH = "/fi/w1/wpa_supplicant1"

_SCAN_TIMEOUT = 15.0   # seconds to wait for a daemon-triggered scan to finish
_POLL_INTERVAL = 0.2   # seconds between polls of the daemon's scanning flag


class AccessPoint(NamedTuple):
    """A nearby Wi-Fi network.

    ``signal_percent`` (0-100) is always present. ``bssid``, ``frequency`` (MHz) and
    ``signal_dbm`` are filled whenever the daemon or the kernel's scan cache knows
    them. iwd reports one signal per network and no frequency: the BSSIDs come from
    its BasicServiceSet objects and the per-BSS frequency and dBm from the kernel
    cache, which holds what the last scan saw (use ``fresh=True`` to make it
    current); without them ``frequency`` is None and ``signal_dbm`` is the network's
    signal. NetworkManager reports no dBm, completed from the kernel cache the same
    way.
    """
    ssid: str
    bssid: str | None
    frequency: int | None
    signal_dbm: int | None
    signal_percent: int
    security: str
    connected: bool


class KernelBss(NamedTuple):
    """One entry of the kernel's scan cache (nl80211 GET_SCAN)."""
    frequency: int | None
    signal_dbm: int | None
    ssid: str | None


def scan_access_points(interface: str | None = None, fresh: bool = False) -> list[AccessPoint]:
    """
    Return the nearby Wi-Fi access points, strongest signal first, from the running
    Wi-Fi daemon (iwd, NetworkManager or wpa_supplicant, auto-detected).

    Reflects the daemon's current view. With ``fresh=True`` the daemon is asked to
    scan first and the call waits, up to 15 s, for that scan to finish. Requires the
    ``scan`` extra and a running daemon.

    :param interface: limit to this wireless interface; None uses the first one.
    :param fresh: trigger a new scan before reading the results.

    """
    if not _HAVE_JEEPNEY:  # pragma: no cover - only without the scan extra
        raise RuntimeError(
            "scan_access_points() needs the 'scan' extra: uv add 'ifpeek[scan]'"
        )

    conn = open_dbus_connection(bus="SYSTEM")
    try:
        if _name_has_owner(conn, _IWD):
            return _scan_iwd(conn, interface, fresh)
        if _name_has_owner(conn, _NM):
            return _scan_networkmanager(conn, interface, fresh)
        if _name_has_owner(conn, _WPAS):
            return _scan_wpa_supplicant(conn, interface, fresh)
        raise RuntimeError(
            "scan_access_points() needs a Wi-Fi daemon on D-Bus, but none of iwd "
            "(net.connman.iwd), NetworkManager (org.freedesktop.NetworkManager), or "
            "wpa_supplicant (fi.w1.wpa_supplicant1) is running."
        )
    finally:
        conn.close()


# --- D-Bus plumbing ---------------------------------------------------------

def _call(conn, msg):
    """ Send `msg` and return its reply body, raising on a D-Bus error reply
    (jeepney returns an error *message* rather than raising, so we check it). """
    reply = conn.send_and_get_reply(msg)
    if reply.header.message_type == MessageType.error:
        detail = reply.body[0] if reply.body else "unknown D-Bus error"
        raise RuntimeError(f"D-Bus call failed: {detail}")
    return reply.body


def _name_has_owner(conn, name):
    """ True if `name` currently owns a D-Bus name (i.e. the daemon is running). """
    dbus = DBusAddress(
        "/org/freedesktop/DBus",
        bus_name="org.freedesktop.DBus",
        interface="org.freedesktop.DBus",
    )
    return _call(conn, new_method_call(dbus, "NameHasOwner", "s", (name,)))[0]


def _get_all_props(conn, bus_name, path, interface):
    """ org.freedesktop.DBus.Properties.GetAll -> {name: (signature, value)}. """
    props = DBusAddress(
        path, bus_name=bus_name, interface="org.freedesktop.DBus.Properties"
    )
    return _call(conn, new_method_call(props, "GetAll", "s", (interface,)))[0]


def _get_prop(conn, bus_name, path, interface, name):
    """ org.freedesktop.DBus.Properties.Get -> the value, variant unwrapped. """
    props = DBusAddress(
        path, bus_name=bus_name, interface="org.freedesktop.DBus.Properties"
    )
    value = _call(conn, new_method_call(props, "Get", "ss", (interface, name)))[0]
    return value[1] if isinstance(value, tuple) else value


def _prop(props, name, default=None):
    """ Read a value from a jeepney {name: (signature, value)} property dict. """
    value = props.get(name)
    return value[1] if value is not None else default


def _dbm_to_percent(dbm):
    """ Rough dBm -> 0-100 %: -100 dBm -> 0, -50 dBm (or stronger) -> 100. """
    return min(max(2 * (dbm + 100), 0), 100)


def _wait_until(done, timeout=_SCAN_TIMEOUT, interval=_POLL_INTERVAL):
    """ Poll `done()` until it is true or `timeout` seconds pass. Returns whether
    it became true. """
    deadline = monotonic() + timeout
    while not done():
        if monotonic() >= deadline:
            return False
        sleep(interval)
    return True


# --- kernel scan cache (nl80211, no root) -----------------------------------

def _kernel_scan_results(interface) -> dict[str, KernelBss]:
    """ {bssid: KernelBss} from the kernel's scan cache for `interface`
    (NL80211_CMD_GET_SCAN, which unlike triggering a scan needs no privilege).
    Empty when the interface is unknown or nl80211 is unavailable. Entries expire
    about 30 s after the scan that produced them. """
    try:
        return _parse_kernel_bss(_kernel_scan_dump(interface))
    except Exception:
        return {}


def _kernel_scan_dump(interface):
    """ The raw NL80211_CMD_GET_SCAN dump for `interface`: a list of nl80211 messages. """
    with IPRoute() as ipr:
        indexes = ipr.link_lookup(ifname=interface)
    if not indexes:
        return []
    request = nl80211cmd()
    request["cmd"] = NL80211_NAMES["NL80211_CMD_GET_SCAN"]
    request["attrs"] = [["NL80211_ATTR_IFINDEX", indexes[0]]]
    nl = NL80211()
    try:
        nl.bind()
        return list(nl.nlm_request(
            request, msg_type=nl.prid, msg_flags=NLM_F_REQUEST | NLM_F_DUMP
        ))
    finally:
        nl.close()


def _parse_kernel_bss(messages) -> dict[str, KernelBss]:
    """ Pick BSSID, frequency, signal and SSID out of GET_SCAN messages. """
    results = {}
    for message in messages:
        bss = message.get_attr("NL80211_ATTR_BSS")
        if bss is None:
            continue
        bssid = bss.get_attr("NL80211_BSS_BSSID")
        if not bssid:
            continue
        results[bssid.lower()] = KernelBss(
            frequency=bss.get_attr("NL80211_BSS_FREQUENCY"),
            signal_dbm=_mbm_to_dbm(bss.get_attr("NL80211_BSS_SIGNAL_MBM")),
            ssid=_ie_ssid(bss.get_attr("NL80211_BSS_INFORMATION_ELEMENTS")),
        )
    return results


def _mbm_to_dbm(value):
    """ NL80211_BSS_SIGNAL_MBM is 100 * dBm; pyroute2 wraps it in a dict. """
    if isinstance(value, dict):
        value = value.get("VALUE")
    return round(value / 100) if isinstance(value, (int, float)) else None


def _ie_ssid(elements):
    """ The SSID from pyroute2's decoded information elements, if any. """
    if not isinstance(elements, dict):
        return None
    ssid = elements.get("SSID")
    if isinstance(ssid, (bytes, bytearray)):
        return bytes(ssid).decode("utf-8", "replace")
    return ssid if isinstance(ssid, str) else None


def _fill_from_kernel(access_points, kernel):
    """ Complete the frequency / dBm a backend left None from the kernel cache,
    matched by BSSID. """
    filled = []
    for ap in access_points:
        cached = kernel.get(ap.bssid.lower()) if ap.bssid else None
        if cached is None:
            filled.append(ap)
            continue
        filled.append(ap._replace(
            frequency=ap.frequency if ap.frequency is not None else cached.frequency,
            signal_dbm=ap.signal_dbm if ap.signal_dbm is not None else cached.signal_dbm,
        ))
    return filled


def _connected_bssid(interface):
    """ BSSID of the access point `interface` is associated to, or None. """
    try:
        return (access_point_mac_address(interface) or "").lower() or None
    except Exception:
        return None


# --- iwd backend ------------------------------------------------------------

def _scan_iwd(conn, interface, fresh=False):
    objects = _get_managed_objects(conn)
    station_path = _select_iwd_station(objects, interface)
    if station_path is None:
        return []
    if fresh:
        _iwd_request_scan(conn, station_path)
        objects = _get_managed_objects(conn)  # BSS objects are rebuilt after a scan
    device = _prop(objects.get(station_path, {}).get(f"{_IWD}.Device", {}), "Name")
    ordered = _get_ordered_networks(conn, station_path)
    return _iwd_access_points(
        ordered,
        objects,
        _iwd_bss_by_network(objects),
        _kernel_scan_results(device) if device else {},
        _connected_bssid(device) if device else None,
    )


def _get_managed_objects(conn):
    manager = DBusAddress(
        "/", bus_name=_IWD, interface="org.freedesktop.DBus.ObjectManager"
    )
    return _call(conn, new_method_call(manager, "GetManagedObjects"))[0]


def _get_ordered_networks(conn, station_path):
    station = DBusAddress(station_path, bus_name=_IWD, interface=f"{_IWD}.Station")
    return _call(conn, new_method_call(station, "GetOrderedNetworks"))[0]


def _iwd_request_scan(conn, station_path):
    """ Ask iwd to scan and wait until its Scanning flag drops (best effort: a
    refused request or a timeout just means the current view is used). """
    station = DBusAddress(station_path, bus_name=_IWD, interface=f"{_IWD}.Station")
    try:
        _call(conn, new_method_call(station, "Scan"))
        _wait_until(lambda: not _get_prop(
            conn, _IWD, station_path, f"{_IWD}.Station", "Scanning"
        ))
    except RuntimeError:
        pass


def _select_iwd_station(objects, interface):
    for path, interfaces in objects.items():
        if f"{_IWD}.Station" not in interfaces:
            continue
        if interface is None:
            return path
        if _prop(interfaces.get(f"{_IWD}.Device", {}), "Name") == interface:
            return path
    return None


def _iwd_bss_by_network(objects):
    """ {network object path: [bssid, ...]} from iwd's BasicServiceSet objects,
    which live right under their network's object path. """
    result = {}
    for path, interfaces in objects.items():
        bss = interfaces.get(f"{_IWD}.BasicServiceSet")
        if bss is None:
            continue
        address = _prop(bss, "Address")
        if address:
            result.setdefault(path.rsplit("/", 1)[0], []).append(address.lower())
    return result


def _iwd_access_points(ordered, objects, bss_by_network=None, kernel=None, connected_bssid=None):
    bss_by_network = bss_by_network or {}
    kernel = kernel or {}
    access_points = []
    for net_path, signal in ordered:
        net = objects.get(net_path, {}).get(f"{_IWD}.Network", {})
        network_dbm = round(signal / 100)  # iwd reports 100 * dBm, per network
        ssid = _prop(net, "Name", "")
        security = _prop(net, "Type", "")
        connected = _prop(net, "Connected", False)
        for bssid in bss_by_network.get(net_path) or [None]:
            cached = kernel.get(bssid) if bssid else None
            dbm = cached.signal_dbm if cached and cached.signal_dbm is not None else network_dbm
            # A connected network with several BSSs: only the associated one is "connected".
            this_one = connected_bssid is None or bssid is None or bssid == connected_bssid
            access_points.append(AccessPoint(
                ssid=ssid,
                bssid=bssid,
                frequency=cached.frequency if cached else None,
                signal_dbm=dbm,
                signal_percent=_dbm_to_percent(dbm),
                security=security,
                connected=connected and this_one,
            ))
    access_points.sort(key=lambda ap: ap.signal_percent, reverse=True)
    return access_points


# --- NetworkManager backend -------------------------------------------------

def _scan_networkmanager(conn, interface, fresh=False):
    access_points = []
    for dev_path in _nm_get_devices(conn):
        dev = _get_all_props(conn, _NM, dev_path, f"{_NM}.Device")
        if _prop(dev, "DeviceType") != _NM_DEVICE_TYPE_WIFI:
            continue
        name = _prop(dev, "Interface")
        if interface is not None and name != interface:
            continue
        if fresh:
            _nm_request_scan(conn, dev_path)
        wireless = _get_all_props(conn, _NM, dev_path, f"{_NM}.Device.Wireless")
        active = _prop(wireless, "ActiveAccessPoint")
        found = []
        for ap_path in _nm_get_access_points(conn, dev_path):
            props = _get_all_props(conn, _NM, ap_path, f"{_NM}.AccessPoint")
            found.append(_nm_access_point(props, ap_path == active))
        access_points.extend(_fill_from_kernel(found, _kernel_scan_results(name) if name else {}))
    access_points.sort(key=lambda ap: ap.signal_percent, reverse=True)
    return access_points


def _nm_get_devices(conn):
    nm = DBusAddress(_NM_PATH, bus_name=_NM, interface=_NM)
    return _call(conn, new_method_call(nm, "GetDevices"))[0]


def _nm_get_access_points(conn, dev_path):
    wireless = DBusAddress(dev_path, bus_name=_NM, interface=f"{_NM}.Device.Wireless")
    return _call(conn, new_method_call(wireless, "GetAllAccessPoints"))[0]


def _nm_request_scan(conn, dev_path):
    """ Ask NetworkManager to scan the device and wait for LastScan to move
    (best effort: NM refuses scans requested too soon after the previous one). """
    iface = f"{_NM}.Device.Wireless"
    wireless = DBusAddress(dev_path, bus_name=_NM, interface=iface)
    try:
        before = _get_prop(conn, _NM, dev_path, iface, "LastScan")
        _call(conn, new_method_call(wireless, "RequestScan", "a{sv}", ({},)))
        _wait_until(lambda: _get_prop(conn, _NM, dev_path, iface, "LastScan") != before)
    except RuntimeError:
        pass


def _nm_access_point(props, connected):
    """ Build an AccessPoint from NetworkManager AccessPoint properties. """
    return AccessPoint(
        ssid=_decode_ssid(_prop(props, "Ssid", b"")),
        bssid=_prop(props, "HwAddress"),
        frequency=_prop(props, "Frequency"),
        signal_dbm=None,  # NM only exposes a percentage; completed from the kernel cache
        signal_percent=int(_prop(props, "Strength", 0)),
        security=_nm_security(_prop(props, "WpaFlags", 0), _prop(props, "RsnFlags", 0)),
        connected=connected,
    )


def _decode_ssid(raw):
    """ NM's Ssid is a byte array (`ay`); decode to text. """
    return bytes(raw).decode("utf-8", "replace")


def _format_mac(raw):
    """ Format a 6-byte MAC (jeepney `ay`) as a lowercase colon-separated string. """
    return ":".join(f"{b:02x}" for b in bytes(raw))


def _nm_security(wpa_flags, rsn_flags):
    flags = wpa_flags | rsn_flags
    if flags == 0:
        return "open"
    if flags & _NM_SEC_8021X:
        return "8021x"
    if flags & _NM_SEC_PSK:
        return "psk"
    return "secured"


# --- wpa_supplicant backend -------------------------------------------------

def _scan_wpa_supplicant(conn, interface, fresh=False):
    root = _get_all_props(conn, _WPAS, _WPAS_PATH, _WPAS)
    access_points = []
    for iface_path in _prop(root, "Interfaces", []):
        iface = _get_all_props(conn, _WPAS, iface_path, f"{_WPAS}.Interface")
        if interface is not None and _prop(iface, "Ifname") != interface:
            continue
        if fresh:
            _wpas_request_scan(conn, iface_path)
            iface = _get_all_props(conn, _WPAS, iface_path, f"{_WPAS}.Interface")  # BSSs refreshed
        current = _prop(iface, "CurrentBSS")
        for bss_path in _prop(iface, "BSSs", []):
            bss = _get_all_props(conn, _WPAS, bss_path, f"{_WPAS}.BSS")
            access_points.append(_wpas_access_point(bss, bss_path == current))
    access_points.sort(key=lambda ap: ap.signal_percent, reverse=True)
    return access_points


def _wpas_request_scan(conn, iface_path):
    """ Ask wpa_supplicant for an active scan and wait for Scanning to drop
    (best effort: a refused request just means the current view is used). """
    interface = f"{_WPAS}.Interface"
    iface = DBusAddress(iface_path, bus_name=_WPAS, interface=interface)
    try:
        _call(conn, new_method_call(iface, "Scan", "a{sv}", ({"Type": ("s", "active")},)))
        _wait_until(lambda: not _get_prop(conn, _WPAS, iface_path, interface, "Scanning"))
    except RuntimeError:
        pass


def _wpas_access_point(bss, connected):
    """ Build an AccessPoint from wpa_supplicant BSS properties (Signal is dBm). """
    dbm = _prop(bss, "Signal")
    dbm = int(dbm) if dbm is not None else None
    bssid = _prop(bss, "BSSID")
    return AccessPoint(
        ssid=_decode_ssid(_prop(bss, "SSID", b"")),
        bssid=_format_mac(bssid) if bssid is not None else None,
        frequency=_prop(bss, "Frequency"),
        signal_dbm=dbm,
        signal_percent=_dbm_to_percent(dbm) if dbm is not None else 0,
        security=_wpas_security(bss),
        connected=connected,
    )


def _wpas_security(bss):
    """ open / wep / psk / 8021x from the BSS's RSN/WPA KeyMgmt and Privacy. """
    key_mgmt = list(_prop(_prop(bss, "RSN", {}), "KeyMgmt", []))
    key_mgmt += list(_prop(_prop(bss, "WPA", {}), "KeyMgmt", []))
    joined = " ".join(key_mgmt).lower()
    if not key_mgmt:
        return "wep" if _prop(bss, "Privacy", False) else "open"
    if "eap" in joined:
        return "8021x"
    if "psk" in joined or "sae" in joined:
        return "psk"
    return "secured"
