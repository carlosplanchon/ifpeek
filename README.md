# ifpeek

![ifpeek](https://raw.githubusercontent.com/carlosplanchon/ifpeek/master/assets/banner.jpg)

[![CI](https://github.com/carlosplanchon/ifpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/carlosplanchon/ifpeek/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/ifpeek.svg)](https://pypi.org/project/ifpeek/)
[![Python versions](https://img.shields.io/pypi/pyversions/ifpeek.svg)](https://pypi.org/project/ifpeek/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/carlosplanchon/ifpeek)

*Inspect Linux network interfaces, Wi-Fi state, routes, DNS, and network events from Python.*

> **Linux only.** ifpeek relies on `pyroute2` (netlink), its single runtime dependency.

## Installation

Requires **Python 3.10+** on **Linux**. Install with [uv](https://docs.astral.sh/uv/):

```bash
uv add ifpeek            # core (only dependency: pyroute2)
uv add "ifpeek[scan]"    # + nearby Wi-Fi scanning (iwd / NetworkManager / wpa_supplicant)
```

## Features

Core facts (interfaces, Wi-Fi, routes, events) come from the kernel via `pyroute2` (netlink / nl80211):
no external tools, no root. DNS is read from `resolv.conf`, and the optional Wi-Fi scan uses the running Wi-Fi daemon's D-Bus API plus the kernel's scan cache (nl80211).

**Interfaces**
- List loopback / ethernet / wifi interfaces (classified by kernel type, not by name).
- Per interface: type, operational state, MAC, MTU, carrier, IPv4 / IPv6 addresses, traffic counters (bytes / packets / errors / drops), and throughput rate.
- Whether rfkill has a radio switched off (`"hard"` / `"soft"`). Operational state and carrier cannot answer that: both are about the association, so an interface joined to no network reads `DOWN` with no carrier while its radio is on and hearing everything nearby.

**Access point (Wi-Fi)**
- ESSID, BSSID, signal (dBm + %), plus the frequency and current bitrate of the associated AP.

**Host network**
- The default interface, default gateway (IPv4 / IPv6), and the configured DNS servers.

**Nearby Wi-Fi scan** *(optional, requires `ifpeek[scan]` + a running Wi-Fi daemon)*
- List nearby access points (SSID, BSSID, frequency, signal, security) via **iwd, NetworkManager, or wpa_supplicant** over D-Bus, without root. `fresh=True` asks the daemon to scan first; per-BSS details the daemon does not report are completed from the kernel's scan cache (nl80211, no root either).

**Events**
- `watch()`: a live stream of link / address / route changes (netlink, no root), to react instead of poll.

## Usage

```python
import ifpeek

# --- interfaces ---
ifpeek.get_wifi_interfaces()               # ['wlan0']
ifpeek.interface_type("docker0")           # 'bridge'
ifpeek.interface_operstate("wlan0")        # 'UP'
ifpeek.interface_mac_address("wlan0")      # 'a1:b2:c3:d4:e5:f6'
ifpeek.interface_mtu("wlan0")              # 1500
ifpeek.interface_rfkill("wlan0")           # None  ("soft" or "hard" when blocked)
ifpeek.interface_ipv4_addresses("wlan0")   # ['192.168.1.42']
ifpeek.interface_stats("wlan0").rx_packets # 51702404
ifpeek.interface_rate("wlan0")             # InterfaceRate(rx_bytes_per_sec=…, tx_bytes_per_sec=…)

# --- access point (Wi-Fi) ---
ifpeek.access_point_essid("wlan0")         # 'MyNetwork'
ifpeek.access_point_mac_address("wlan0")   # 'aa:bb:cc:dd:ee:ff'  (BSSID)
ifpeek.access_point_signal_dbm("wlan0")    # -47
ifpeek.access_point_frequency("wlan0")     # 5280   (MHz)
ifpeek.access_point_bitrate("wlan0")       # 866.7  (Mbps)

# --- host network ---
ifpeek.default_interface()                 # 'wlan0'
ifpeek.default_gateway_ipv4()              # '192.168.1.1'
ifpeek.dns_servers()                       # ['192.168.1.1']
```

### Nearby Wi-Fi scan (optional)

Requires the `scan` extra and a running Wi-Fi daemon: [iwd](https://iwd.wiki.kernel.org/),
[NetworkManager](https://networkmanager.dev/), or [wpa_supplicant](https://w1.fi/wpa_supplicant/),
auto-detected. The caller must be allowed on the daemon's D-Bus (e.g. be in the `wheel` / `network` group):

```bash
uv add "ifpeek[scan]"
```

```python
import ifpeek

for ap in ifpeek.scan_access_points():          # the daemon's current view, strongest signal first
    print(ap.ssid, ap.bssid, ap.frequency, ap.signal_dbm, ap.security)
# AccessPoint(ssid='MyNetwork', bssid='aa:bb:cc:dd:ee:ff', frequency=5180,
#             signal_dbm=-47, signal_percent=100, security='psk', connected=True)

ifpeek.scan_access_points("wlan0", fresh=True)  # ask the daemon to scan first (waits up to 15 s)
```

One `AccessPoint` per BSS. `signal_percent` (0-100) is always present; `bssid`, `frequency` and
`signal_dbm` are filled whenever the daemon or the kernel knows them:

- **iwd** reports one signal per network and no frequency. The BSSIDs come from its `BasicServiceSet`
  objects, and the per-BSS frequency and dBm from the kernel's scan cache, which holds what the last
  scan saw (about 30 s). While connected iwd rarely scans, so pass `fresh=True` to get them; otherwise
  `frequency` is `None` and `signal_dbm` is the network's signal.
- **NetworkManager** reports no dBm; it is completed from the kernel cache by BSSID.
- **wpa_supplicant** reports everything itself.

> **Backend status:** the **iwd** backend, `fresh=True` on iwd and the kernel-cache completion are verified
> against a live daemon. The **NetworkManager** and **wpa_supplicant** backends, including their
> `fresh=True`, are implemented against their documented D-Bus APIs and unit-tested, but not yet
> exercised against a live daemon. Bug reports welcome.

### Watch for changes (event stream)

```python
import ifpeek

for event in ifpeek.watch():          # blocks; yields as things change
    print(event.kind, event.action, event.interface, event.detail)
# NetworkEvent(kind='link', action='new', interface='wlan0', index=4, detail={'operstate': 'DOWN'})
```

With `interface=...` only that interface's events are yielded (matched by
interface index, so route and IPv6 address events are included). With
`timeout=...` the iterator yields `None` whenever that many seconds pass
without an event, so periodic work can share the thread:

```python
for event in ifpeek.watch(interface="wlan0", timeout=30.0):
    if event is None:
        run_periodic_health_check()   # idle tick, every <= 30 s
    else:
        react_to(event)
```
