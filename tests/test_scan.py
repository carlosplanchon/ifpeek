"""Tests for Wi-Fi scanning (iwd, NetworkManager and wpa_supplicant backends).

The D-Bus and netlink boundaries are mocked at the module's seams, so these run anywhere
jeepney is installed. The NetworkManager and wpa_supplicant backends are unit-tested
against their documented D-Bus shapes (no live daemon here). A skip-guarded smoke test
hits a live daemon if one is reachable.
"""

import pytest

pytest.importorskip("jeepney")  # the `scan` extra

import ifpeek
from ifpeek import scan

from jeepney import MessageType


class _Header:
    def __init__(self, message_type):
        self.message_type = message_type


class _Reply:
    def __init__(self, body, message_type=MessageType.method_return):
        self.body = body
        self.header = _Header(message_type)


class _Conn:
    def __init__(self, reply=None):
        self._reply = reply

    def send_and_get_reply(self, msg):
        return self._reply

    def close(self):
        pass


class _SeqConn:
    """A connection that answers successive calls from a list of replies."""

    def __init__(self, replies):
        self._replies = list(replies)
        self.sent = []

    def send_and_get_reply(self, msg):
        self.sent.append(msg)
        return self._replies.pop(0)

    def close(self):
        pass


class _Msg:
    """A stand-in for a pyroute2 netlink message / nested attribute."""

    def __init__(self, attrs):
        self._attrs = attrs

    def get_attr(self, name):
        return self._attrs.get(name)


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr(scan, "sleep", lambda seconds: None)


# --- backend dispatch / detection -------------------------------------------

class TestDispatch:
    def _detect(self, monkeypatch, iwd=False, nm=False, wpas=False):
        monkeypatch.setattr(scan, "open_dbus_connection", lambda bus=None: _Conn())
        owners = {scan._IWD: iwd, scan._NM: nm, scan._WPAS: wpas}
        monkeypatch.setattr(scan, "_name_has_owner", lambda conn, name: owners[name])

    def test_uses_iwd_when_present(self, monkeypatch):
        self._detect(monkeypatch, iwd=True)
        monkeypatch.setattr(scan, "_scan_iwd", lambda conn, iface, fresh=False: ["iwd-result", fresh])
        assert ifpeek.scan_access_points() == ["iwd-result", False]

    def test_passes_fresh_to_the_backend(self, monkeypatch):
        self._detect(monkeypatch, iwd=True)
        monkeypatch.setattr(scan, "_scan_iwd", lambda conn, iface, fresh=False: [iface, fresh])
        assert ifpeek.scan_access_points("wlan0", fresh=True) == ["wlan0", True]

    def test_uses_networkmanager_when_iwd_absent(self, monkeypatch):
        self._detect(monkeypatch, iwd=False, nm=True)
        monkeypatch.setattr(scan, "_scan_networkmanager", lambda conn, iface, fresh=False: ["nm-result"])
        assert ifpeek.scan_access_points() == ["nm-result"]

    def test_uses_wpa_supplicant_when_others_absent(self, monkeypatch):
        self._detect(monkeypatch, wpas=True)
        monkeypatch.setattr(scan, "_scan_wpa_supplicant", lambda conn, iface, fresh=False: ["wpas-result"])
        assert ifpeek.scan_access_points() == ["wpas-result"]

    def test_raises_when_no_daemon(self, monkeypatch):
        self._detect(monkeypatch, iwd=False, nm=False)
        with pytest.raises(RuntimeError, match="Wi-Fi daemon on D-Bus"):
            ifpeek.scan_access_points()


# --- iwd backend ------------------------------------------------------------

_IWD_OBJECTS = {
    "/iwd/0/4": {
        "net.connman.iwd.Station": {},
        "net.connman.iwd.Device": {"Name": ("s", "wlan0")},
    },
    "/iwd/0/4/rupia": {
        "net.connman.iwd.Network": {
            "Name": ("s", "Rupia-5GHz"), "Type": ("s", "psk"), "Connected": ("b", True),
        },
    },
    "/iwd/0/4/redmi": {
        "net.connman.iwd.Network": {
            "Name": ("s", "Redmi"), "Type": ("s", "psk"), "Connected": ("b", False),
        },
    },
}
_IWD_ORDERED = [("/iwd/0/4/rupia", -2300), ("/iwd/0/4/redmi", -6300)]

# iwd >= 3.x also exposes one BasicServiceSet object per BSS, under the network's path.
_IWD_OBJECTS_BSS = {
    **_IWD_OBJECTS,
    "/iwd/0/4/rupia/aabbccddee01": {
        "net.connman.iwd.BasicServiceSet": {"Address": ("s", "AA:BB:CC:DD:EE:01")},
    },
    "/iwd/0/4/rupia/aabbccddee02": {
        "net.connman.iwd.BasicServiceSet": {"Address": ("s", "aa:bb:cc:dd:ee:02")},
    },
    "/iwd/0/4/redmi/broken": {"net.connman.iwd.BasicServiceSet": {}},  # no Address: ignored
}


class TestIwdBackend:
    def _patch(self, monkeypatch, objects=_IWD_OBJECTS, ordered=_IWD_ORDERED, kernel=None, connected=None):
        monkeypatch.setattr(scan, "_get_managed_objects", lambda conn: objects)
        monkeypatch.setattr(scan, "_get_ordered_networks", lambda conn, path: ordered)
        monkeypatch.setattr(scan, "_kernel_scan_results", lambda iface: kernel or {})
        monkeypatch.setattr(scan, "_connected_bssid", lambda iface: connected)

    def test_parses_and_derives_percent(self, monkeypatch):
        self._patch(monkeypatch)
        assert scan._scan_iwd(None, None) == [
            scan.AccessPoint("Rupia-5GHz", None, None, -23, 100, "psk", True),
            scan.AccessPoint("Redmi", None, None, -63, 74, "psk", False),  # 2*(-63+100)
        ]

    def test_interface_filter(self, monkeypatch):
        self._patch(monkeypatch)
        assert len(scan._scan_iwd(None, "wlan0")) == 2
        assert scan._scan_iwd(None, "wlan9") == []

    def test_no_station(self, monkeypatch):
        self._patch(monkeypatch, objects={"/": {"org.freedesktop.DBus.ObjectManager": {}}})
        assert scan._scan_iwd(None, None) == []

    def test_station_without_device_name(self, monkeypatch):
        self._patch(monkeypatch, objects={"/iwd/0/9": {"net.connman.iwd.Station": {}}}, ordered=[])
        assert scan._scan_iwd(None, None) == []

    def test_one_access_point_per_bss(self, monkeypatch):
        self._patch(
            monkeypatch, objects=_IWD_OBJECTS_BSS,
            kernel={"aa:bb:cc:dd:ee:01": scan.KernelBss(5180, -30, "Rupia-5GHz")},
            connected="aa:bb:cc:dd:ee:01",
        )
        assert scan._scan_iwd(None, "wlan0") == [
            # BSS known to the kernel cache: its own frequency and dBm; the associated one.
            scan.AccessPoint("Rupia-5GHz", "aa:bb:cc:dd:ee:01", 5180, -30, 100, "psk", True),
            # Second BSS of the same network, not in the cache: the network's signal, no frequency.
            scan.AccessPoint("Rupia-5GHz", "aa:bb:cc:dd:ee:02", None, -23, 100, "psk", False),
            # Network without BSS objects: as before.
            scan.AccessPoint("Redmi", None, None, -63, 74, "psk", False),
        ]

    def test_unknown_associated_bssid_marks_every_bss_connected(self, monkeypatch):
        self._patch(monkeypatch, objects=_IWD_OBJECTS_BSS, connected=None)
        aps = scan._scan_iwd(None, None)
        assert [ap.connected for ap in aps] == [True, True, False]

    def test_cached_bss_without_dbm_keeps_network_signal(self, monkeypatch):
        self._patch(
            monkeypatch, objects=_IWD_OBJECTS_BSS,
            kernel={"aa:bb:cc:dd:ee:02": scan.KernelBss(2412, None, None)},
        )
        second = scan._scan_iwd(None, None)[1]
        assert (second.bssid, second.frequency, second.signal_dbm) == ("aa:bb:cc:dd:ee:02", 2412, -23)

    def test_fresh_requests_a_scan_and_rereads_objects(self, monkeypatch):
        self._patch(monkeypatch)
        calls = []
        reads = []
        monkeypatch.setattr(scan, "_iwd_request_scan", lambda conn, path: calls.append(path))
        monkeypatch.setattr(scan, "_get_managed_objects", lambda conn: reads.append(1) or _IWD_OBJECTS)
        assert len(scan._scan_iwd(None, None, fresh=True)) == 2
        assert calls == ["/iwd/0/4"] and len(reads) == 2

    def test_fresh_without_station_does_not_scan(self, monkeypatch):
        self._patch(monkeypatch, objects={})
        monkeypatch.setattr(scan, "_iwd_request_scan", lambda conn, path: pytest.fail("scan requested"))
        assert scan._scan_iwd(None, None, fresh=True) == []

    def test_bss_by_network(self):
        assert scan._iwd_bss_by_network(_IWD_OBJECTS_BSS) == {
            "/iwd/0/4/rupia": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
        }

    def test_request_scan_waits_for_scanning_to_drop(self, no_sleep):
        conn = _SeqConn([_Reply(()), _Reply((("b", True),)), _Reply((("b", False),))])
        scan._iwd_request_scan(conn, "/iwd/0/4")
        assert len(conn.sent) == 3

    def test_request_scan_tolerates_a_refusal(self, no_sleep):
        conn = _SeqConn([_Reply(("net.connman.iwd.Busy",), MessageType.error)])
        scan._iwd_request_scan(conn, "/iwd/0/4")
        assert len(conn.sent) == 1


# --- NetworkManager backend (documented D-Bus shapes; no live NM here) ------

class TestNetworkManagerBackend:
    def _patch(self, monkeypatch, devices, dev_props, wireless_props, ap_lists, ap_props, kernel=None):
        monkeypatch.setattr(scan, "_nm_get_devices", lambda conn: devices)
        monkeypatch.setattr(scan, "_nm_get_access_points", lambda conn, dev: ap_lists.get(dev, []))
        monkeypatch.setattr(scan, "_kernel_scan_results", lambda iface: kernel or {})

        def fake_get_all(conn, bus, path, iface):
            if iface == f"{scan._NM}.Device":
                return dev_props.get(path, {})
            if iface == f"{scan._NM}.Device.Wireless":
                return wireless_props.get(path, {})
            if iface == f"{scan._NM}.AccessPoint":
                return ap_props.get(path, {})
            return {}

        monkeypatch.setattr(scan, "_get_all_props", fake_get_all)

    def test_lists_orders_and_labels(self, monkeypatch):
        self._patch(
            monkeypatch,
            devices=["/dev/wlan0", "/dev/eth0"],
            dev_props={
                "/dev/wlan0": {"DeviceType": ("u", 2), "Interface": ("s", "wlan0")},
                "/dev/eth0": {"DeviceType": ("u", 1), "Interface": ("s", "eth0")},
            },
            wireless_props={"/dev/wlan0": {"ActiveAccessPoint": ("o", "/ap/strong")}},
            ap_lists={"/dev/wlan0": ["/ap/weak", "/ap/strong"]},
            ap_props={
                "/ap/strong": {"Ssid": ("ay", b"MyNet"), "Strength": ("y", 80),
                               "HwAddress": ("s", "aa:bb:cc:dd:ee:ff"), "Frequency": ("u", 5200),
                               "WpaFlags": ("u", 0), "RsnFlags": ("u", 0x100)},
                "/ap/weak": {"Ssid": ("ay", b"Far"), "Strength": ("y", 20),
                             "HwAddress": ("s", "11:22:33:44:55:66"), "Frequency": ("u", 2412),
                             "WpaFlags": ("u", 0), "RsnFlags": ("u", 0)},
            },
        )
        # eth0 skipped (not wifi); ordered by percent desc; strong is the active AP.
        assert scan._scan_networkmanager(None, None) == [
            scan.AccessPoint("MyNet", "aa:bb:cc:dd:ee:ff", 5200, None, 80, "psk", True),
            scan.AccessPoint("Far", "11:22:33:44:55:66", 2412, None, 20, "open", False),
        ]

    def test_interface_filter_excludes_non_matching(self, monkeypatch):
        self._patch(
            monkeypatch,
            devices=["/dev/wlan0"],
            dev_props={"/dev/wlan0": {"DeviceType": ("u", 2), "Interface": ("s", "wlan0")}},
            wireless_props={"/dev/wlan0": {"ActiveAccessPoint": ("o", "/x")}},
            ap_lists={"/dev/wlan0": ["/ap/a"]},
            ap_props={"/ap/a": {"Ssid": ("ay", b"A"), "Strength": ("y", 50),
                                "WpaFlags": ("u", 0), "RsnFlags": ("u", 0)}},
        )
        assert scan._scan_networkmanager(None, "wlan9") == []

    def test_kernel_cache_completes_dbm(self, monkeypatch):
        self._patch(
            monkeypatch,
            devices=["/dev/wlan0"],
            dev_props={"/dev/wlan0": {"DeviceType": ("u", 2), "Interface": ("s", "wlan0")}},
            wireless_props={"/dev/wlan0": {"ActiveAccessPoint": ("o", "/x")}},
            ap_lists={"/dev/wlan0": ["/ap/a"]},
            ap_props={"/ap/a": {"Ssid": ("ay", b"A"), "Strength": ("y", 50), "HwAddress": ("s", "AA:BB:CC:DD:EE:FF"),
                                "Frequency": ("u", 2412), "WpaFlags": ("u", 0), "RsnFlags": ("u", 0)}},
            kernel={"aa:bb:cc:dd:ee:ff": scan.KernelBss(2412, -67, "A")},
        )
        assert scan._scan_networkmanager(None, None) == [
            scan.AccessPoint("A", "AA:BB:CC:DD:EE:FF", 2412, -67, 50, "open", False),
        ]

    def test_device_without_interface_name(self, monkeypatch):
        self._patch(
            monkeypatch,
            devices=["/dev/x"],
            dev_props={"/dev/x": {"DeviceType": ("u", 2)}},
            wireless_props={"/dev/x": {}},
            ap_lists={"/dev/x": []},
            ap_props={},
        )
        assert scan._scan_networkmanager(None, None) == []

    def test_fresh_requests_a_scan_per_wifi_device(self, monkeypatch):
        self._patch(
            monkeypatch,
            devices=["/dev/wlan0", "/dev/eth0"],
            dev_props={
                "/dev/wlan0": {"DeviceType": ("u", 2), "Interface": ("s", "wlan0")},
                "/dev/eth0": {"DeviceType": ("u", 1), "Interface": ("s", "eth0")},
            },
            wireless_props={"/dev/wlan0": {}},
            ap_lists={},
            ap_props={},
        )
        calls = []
        monkeypatch.setattr(scan, "_nm_request_scan", lambda conn, dev: calls.append(dev))
        assert scan._scan_networkmanager(None, None, fresh=True) == []
        assert calls == ["/dev/wlan0"]

    def test_request_scan_waits_for_last_scan_to_move(self, no_sleep):
        conn = _SeqConn([
            _Reply((("x", 10),)),   # LastScan before
            _Reply(()),             # RequestScan
            _Reply((("x", 10),)),   # unchanged
            _Reply((("x", 11),)),   # moved
        ])
        scan._nm_request_scan(conn, "/dev/wlan0")
        assert len(conn.sent) == 4

    def test_request_scan_tolerates_a_refusal(self, no_sleep):
        conn = _SeqConn([_Reply(("nope",), MessageType.error)])
        scan._nm_request_scan(conn, "/dev/wlan0")
        assert len(conn.sent) == 1


# --- wpa_supplicant backend (documented D-Bus shapes; no live wpa_supplicant here) --

class TestWpaSupplicantBackend:
    def _patch(self, monkeypatch, root, iface_props, bss_props):
        def fake_get_all(conn, bus, path, iface):
            if iface == scan._WPAS:
                return root
            if iface == f"{scan._WPAS}.Interface":
                return iface_props.get(path, {})
            if iface == f"{scan._WPAS}.BSS":
                return bss_props.get(path, {})
            return {}

        monkeypatch.setattr(scan, "_get_all_props", fake_get_all)

    def test_lists_orders_and_labels(self, monkeypatch):
        self._patch(
            monkeypatch,
            root={"Interfaces": ("ao", ["/iface/0"])},
            iface_props={"/iface/0": {
                "Ifname": ("s", "wlan0"),
                "CurrentBSS": ("o", "/bss/strong"),
                "BSSs": ("ao", ["/bss/weak", "/bss/strong"]),
            }},
            bss_props={
                "/bss/strong": {"SSID": ("ay", b"MyNet"), "Signal": ("n", -40),
                                "BSSID": ("ay", b"\xaa\xbb\xcc\xdd\xee\xff"), "Frequency": ("q", 5200),
                                "RSN": ("a{sv}", {"KeyMgmt": ("as", ["wpa-psk"])}),
                                "WPA": ("a{sv}", {}), "Privacy": ("b", True)},
                "/bss/weak": {"SSID": ("ay", b"Open"), "Signal": ("n", -80),
                              "BSSID": ("ay", b"\x11\x22\x33\x44\x55\x66"), "Frequency": ("q", 2412),
                              "RSN": ("a{sv}", {}), "WPA": ("a{sv}", {}), "Privacy": ("b", False)},
            },
        )
        # Signal is dBm (like iwd): -40 -> 100%, -80 -> 40%. Strong is CurrentBSS.
        assert scan._scan_wpa_supplicant(None, None) == [
            scan.AccessPoint("MyNet", "aa:bb:cc:dd:ee:ff", 5200, -40, 100, "psk", True),
            scan.AccessPoint("Open", "11:22:33:44:55:66", 2412, -80, 40, "open", False),
        ]

    def test_interface_filter_and_eap(self, monkeypatch):
        self._patch(
            monkeypatch,
            root={"Interfaces": ("ao", ["/iface/0"])},
            iface_props={"/iface/0": {
                "Ifname": ("s", "wlan0"),
                "CurrentBSS": ("o", "/"),  # disconnected
                "BSSs": ("ao", ["/bss/corp"]),
            }},
            bss_props={"/bss/corp": {"SSID": ("ay", b"Corp"), "Signal": ("n", -55),
                                     "RSN": ("a{sv}", {"KeyMgmt": ("as", ["wpa-eap"])}),
                                     "WPA": ("a{sv}", {}), "Privacy": ("b", True)}},
        )
        assert scan._scan_wpa_supplicant(None, "wlan9") == []  # no matching interface
        assert scan._scan_wpa_supplicant(None, "wlan0") == [
            scan.AccessPoint("Corp", None, None, -55, 90, "8021x", False),
        ]

    def test_fresh_requests_a_scan_and_rereads_the_interface(self, monkeypatch):
        reads = []
        root = {"Interfaces": ("ao", ["/iface/0"])}
        iface_props = {"/iface/0": {"Ifname": ("s", "wlan0"), "CurrentBSS": ("o", "/"), "BSSs": ("ao", [])}}

        def fake_get_all(conn, bus, path, iface):
            reads.append(iface)
            return root if iface == scan._WPAS else iface_props.get(path, {})

        monkeypatch.setattr(scan, "_get_all_props", fake_get_all)
        calls = []
        monkeypatch.setattr(scan, "_wpas_request_scan", lambda conn, path: calls.append(path))
        assert scan._scan_wpa_supplicant(None, None, fresh=True) == []
        assert calls == ["/iface/0"]
        assert reads.count(f"{scan._WPAS}.Interface") == 2

    def test_request_scan_waits_for_scanning_to_drop(self, no_sleep):
        conn = _SeqConn([_Reply(()), _Reply((("b", True),)), _Reply((("b", False),))])
        scan._wpas_request_scan(conn, "/iface/0")
        assert len(conn.sent) == 3

    def test_request_scan_tolerates_a_refusal(self, no_sleep):
        conn = _SeqConn([_Reply(("busy",), MessageType.error)])
        scan._wpas_request_scan(conn, "/iface/0")
        assert len(conn.sent) == 1


# --- pure helpers & thin D-Bus adapters -------------------------------------

class TestHelpers:
    def test_nm_security(self):
        assert scan._nm_security(0, 0) == "open"
        assert scan._nm_security(0, 0x100) == "psk"
        assert scan._nm_security(0x200, 0) == "8021x"
        assert scan._nm_security(0x1, 0) == "secured"

    def test_wpas_security(self):
        def bss(rsn=None, wpa=None, privacy=False):
            d = {"Privacy": ("b", privacy)}
            if rsn is not None:
                d["RSN"] = ("a{sv}", {"KeyMgmt": ("as", rsn)})
            if wpa is not None:
                d["WPA"] = ("a{sv}", {"KeyMgmt": ("as", wpa)})
            return d

        assert scan._wpas_security(bss()) == "open"
        assert scan._wpas_security(bss(privacy=True)) == "wep"
        assert scan._wpas_security(bss(rsn=["wpa-psk"])) == "psk"
        assert scan._wpas_security(bss(rsn=["sae"])) == "psk"
        assert scan._wpas_security(bss(rsn=["wpa-eap"])) == "8021x"
        assert scan._wpas_security(bss(rsn=["unknown-x"])) == "secured"

    def test_wpas_access_point_without_signal(self):
        bss = {"SSID": ("ay", b"X"), "RSN": ("a{sv}", {}), "WPA": ("a{sv}", {}), "Privacy": ("b", False)}
        ap = scan._wpas_access_point(bss, False)
        assert ap.signal_dbm is None and ap.signal_percent == 0
        assert ap.bssid is None and ap.frequency is None

    def test_format_mac(self):
        assert scan._format_mac(b"\xaa\xbb\xcc\xdd\xee\xff") == "aa:bb:cc:dd:ee:ff"
        assert scan._format_mac([1, 2, 3, 4, 5, 6]) == "01:02:03:04:05:06"

    def test_decode_ssid(self):
        assert scan._decode_ssid(b"MyNet") == "MyNet"
        assert scan._decode_ssid([104, 105]) == "hi"

    def test_dbm_to_percent(self):
        assert scan._dbm_to_percent(-50) == 100
        assert scan._dbm_to_percent(-100) == 0
        assert scan._dbm_to_percent(-75) == 50

    def test_call_raises_on_dbus_error(self):
        conn = _Conn(_Reply(("boom",), MessageType.error))
        with pytest.raises(RuntimeError, match="D-Bus call failed"):
            scan._call(conn, None)

    def test_name_has_owner(self):
        assert scan._name_has_owner(_Conn(_Reply((True,))), scan._IWD) is True

    def test_get_all_props(self):
        conn = _Conn(_Reply(({"Strength": ("y", 80)},)))
        assert scan._get_all_props(conn, "org.x", "/p", "iface") == {"Strength": ("y", 80)}

    def test_iwd_and_nm_thin_getters(self):
        assert scan._get_managed_objects(_Conn(_Reply(({"/p": {}},)))) == {"/p": {}}
        assert scan._get_ordered_networks(_Conn(_Reply(([("/n", -2300)],))), "/s") == [("/n", -2300)]
        assert scan._nm_get_devices(_Conn(_Reply((["/d"],)))) == ["/d"]
        assert scan._nm_get_access_points(_Conn(_Reply((["/a"],))), "/d") == ["/a"]

    def test_get_prop_unwraps_the_variant(self):
        assert scan._get_prop(_Conn(_Reply((("b", True),))), "org.x", "/p", "iface", "Scanning") is True
        assert scan._get_prop(_Conn(_Reply((7,))), "org.x", "/p", "iface", "Raw") == 7

    def test_wait_until(self, monkeypatch, no_sleep):
        assert scan._wait_until(lambda: True) is True
        clock = iter([0.0, 0.0, 0.1, 100.0])
        monkeypatch.setattr(scan, "monotonic", lambda: next(clock))
        assert scan._wait_until(lambda: False, timeout=1.0) is False

    def test_connected_bssid(self, monkeypatch):
        monkeypatch.setattr(scan, "access_point_mac_address", lambda iface: "AA:BB:CC:DD:EE:FF")
        assert scan._connected_bssid("wlan0") == "aa:bb:cc:dd:ee:ff"
        monkeypatch.setattr(scan, "access_point_mac_address", lambda iface: None)
        assert scan._connected_bssid("wlan0") is None

        def boom(iface):
            raise OSError("no nl80211")

        monkeypatch.setattr(scan, "access_point_mac_address", boom)
        assert scan._connected_bssid("wlan0") is None

    def test_fill_from_kernel(self):
        kernel = {"aa:bb:cc:dd:ee:ff": scan.KernelBss(5180, -40, "X")}
        aps = [
            scan.AccessPoint("X", "AA:BB:CC:DD:EE:FF", None, None, 80, "psk", False),
            scan.AccessPoint("Y", "11:22:33:44:55:66", 2412, None, 20, "open", False),
            scan.AccessPoint("Z", None, None, None, 0, "open", False),
        ]
        filled = scan._fill_from_kernel(aps, kernel)
        assert filled[0] == scan.AccessPoint("X", "AA:BB:CC:DD:EE:FF", 5180, -40, 80, "psk", False)
        assert filled[1:] == aps[1:]
        kept = scan._fill_from_kernel([aps[0]._replace(frequency=2462, signal_dbm=-50)], kernel)[0]
        assert (kept.frequency, kept.signal_dbm) == (2462, -50)


class TestKernelScanCache:
    def test_mbm_to_dbm(self):
        assert scan._mbm_to_dbm({"VALUE": -3300}) == -33
        assert scan._mbm_to_dbm(-3000) == -30
        assert scan._mbm_to_dbm({"VALUE": None}) is None
        assert scan._mbm_to_dbm(None) is None
        assert scan._mbm_to_dbm("x") is None

    def test_ie_ssid(self):
        assert scan._ie_ssid({"SSID": b"Rupia"}) == "Rupia"
        assert scan._ie_ssid({"SSID": bytearray(b"R")}) == "R"
        assert scan._ie_ssid({"SSID": "text"}) == "text"
        assert scan._ie_ssid({"SSID": 5}) is None
        assert scan._ie_ssid({}) is None
        assert scan._ie_ssid(b"\x00\x05Rupia") is None

    def test_parse_kernel_bss(self):
        messages = [
            _Msg({"NL80211_ATTR_BSS": _Msg({
                "NL80211_BSS_BSSID": "FC:40:09:C3:4D:01", "NL80211_BSS_FREQUENCY": 5180,
                "NL80211_BSS_SIGNAL_MBM": {"VALUE": -3300},
                "NL80211_BSS_INFORMATION_ELEMENTS": {"SSID": b"Rupia"},
            })}),
            _Msg({}),                                          # no BSS attribute
            _Msg({"NL80211_ATTR_BSS": _Msg({"NL80211_BSS_BSSID": None})}),  # no BSSID
        ]
        assert scan._parse_kernel_bss(messages) == {
            "fc:40:09:c3:4d:01": scan.KernelBss(5180, -33, "Rupia"),
        }

    def test_kernel_scan_dump(self, monkeypatch):
        class FakeIPRoute:
            def __init__(self, indexes):
                self._indexes = indexes

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def link_lookup(self, ifname):
                return self._indexes if ifname == "wlan0" else []

        class FakeNL:
            prid = 42
            instances = []

            def __init__(self):
                self.bound = self.closed = False
                self.requests = []
                FakeNL.instances.append(self)

            def bind(self):
                self.bound = True

            def nlm_request(self, msg, msg_type, msg_flags):
                self.requests.append((msg["cmd"], msg["attrs"], msg_type, msg_flags))
                return iter(["m1", "m2"])

            def close(self):
                self.closed = True

        monkeypatch.setattr(scan, "IPRoute", lambda: FakeIPRoute([4]))
        monkeypatch.setattr(scan, "NL80211", FakeNL)
        assert scan._kernel_scan_dump("wlan0") == ["m1", "m2"]
        nl = FakeNL.instances[-1]
        assert nl.bound and nl.closed
        assert nl.requests == [(
            scan.NL80211_NAMES["NL80211_CMD_GET_SCAN"], [["NL80211_ATTR_IFINDEX", 4]],
            42, scan.NLM_F_REQUEST | scan.NLM_F_DUMP,
        )]
        assert scan._kernel_scan_dump("nope0") == []
        assert len(FakeNL.instances) == 1  # unknown interface: no netlink socket opened

    def test_kernel_scan_results(self, monkeypatch):
        monkeypatch.setattr(scan, "_kernel_scan_dump", lambda iface: [
            _Msg({"NL80211_ATTR_BSS": _Msg({"NL80211_BSS_BSSID": "aa:bb:cc:dd:ee:ff"})}),
        ])
        assert scan._kernel_scan_results("wlan0") == {"aa:bb:cc:dd:ee:ff": scan.KernelBss(None, None, None)}

        def boom(iface):
            raise PermissionError("netlink")

        monkeypatch.setattr(scan, "_kernel_scan_dump", boom)
        assert scan._kernel_scan_results("wlan0") == {}


# --- real, skip-guarded smoke -----------------------------------------------

class TestScanRealSmoke:
    def test_scan_against_live_daemon(self):
        try:
            aps = ifpeek.scan_access_points()
        except Exception:
            pytest.skip("no reachable Wi-Fi daemon")
        assert isinstance(aps, list)
        for ap in aps:
            assert isinstance(ap.ssid, str)
            assert isinstance(ap.signal_percent, int)
            assert ap.signal_dbm is None or isinstance(ap.signal_dbm, int)
