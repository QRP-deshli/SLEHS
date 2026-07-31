# SLEHS — Secure Lightweight Embedded HTTPS Server

A secure HTTPS server for the **RP2350 microcontroller** (Wiznet W6100-EVB-Pico2 board) that provides encrypted web access and actively defends itself against network attacks — all while consuming just **~0.3 W** of power and fitting in **403 kB** of Flash.

> Research paper: *"Secure Lightweight Embedded HTTPS Server: Autonomous Threat Detection and Mitigation at the Edge"* — Kuropatkin & Drutarovsky, Technical University of Košice, 2026.

---

## What It Does

SLEHS exposes a live monitoring web page (sensor readings, uptime, NTP time) over HTTPS. Before any browser session is allowed, the client must pass a **custom cryptographic handshake** using a pre-shared key. This keeps attackers out even if they know port 443 is open.

The server also continuously monitors and blocks network attacks on its own — no external firewall needed.

---

## How the Connection Works

The protocol has two phases:

```
Phase 0 — Anti-SYN Flood Timer
  ↓  TCP SYN / SYN-ACK / ACK
  ↓  Client must send Init Frame immediately after ACK (strict timer)

Phase 1 — Mutual Cryptographic Handshake
  ↓  Client sends:  Init Frame  [client nonce Nc]
  ↓  Server sends:  Nonce Frame [server nonce Ns]
  ↓  Client sends:  Auth Frame  [MAC + HMAC]
     • Ksession  = HMAC_Kshared(Nc ∥ Ns)
     • HMACauth  = HMAC_Ksession(auth data)
  ↓  Server verifies both — proves client knows the pre-shared key
     and prevents replay attacks

  Post-auth commands:
    "stats" → last-hour diagnostics
    "info"  → 2-week history log
    "web"   → whitelist client IP and start Phase 2

Phase 2 — Exclusive HTTPS Session
  • TLS 1.3 — TLS_CHACHA20_POLY1305_SHA256 cipher suite
               x25519 key exchange, ecdsa_secp256r1_sha256 signatures
  • Only the whitelisted IP can connect
  • 15-second window to open the page in a browser
  • Page auto-refreshes every 10 seconds with live sensor data
  • All other Phase 1 attempts are dropped while this session is active
```

---

## Defense Mechanisms

### Anti-SYN Flood (Adaptive Timeouts)
| Failure count | Timeout |
|---|---|
| First attempt | 250 ms |
| 10+ failures | 500 ms |
| 15+ failures | 1 000 ms |
| **18+ failures** | **IP permanently blacklisted** |

The tracking table holds up to **32 IPs** and cleans up hourly. An attack is isolated in ~8 seconds on a single socket, ~2.5 seconds if all 4 sockets are flooded.

### Blacklist
- **64 unified slots** — each entry stores an IP, strike counter, ban flag, and 64-bit timestamp
- Each entry is 14 bytes; the entire table fits in **896 bytes of RAM** (<0.18% of available SRAM)
- 4 strikes → 24-hour ban; entries are cleared hourly
- Every incoming packet is checked against the blacklist first, before any processing

### Frame Validation
Every packet must pass strict checks before anything happens:
- Magic number, protocol version, command sequence order
- Replay counter (rejects any frame with a counter ≤ last seen)
- Payload length ≤ 128 bytes (prevents buffer overflow)
- 8-byte **Chaskey MAC** (ISO/IEC 29192-6) over the entire frame

Fragmented packets and malformed TCP headers (bad window size, zero sequence number, etc.) are dropped instantly at the hardware level.

---

## Performance Under Attack

| Attack | SLEHS | Unprotected server |
|---|---|---|
| SYN flood — 1 000 PPS | **98.0%** (245/250) | 0% (down) |
| SYN flood — 5 000 PPS | **85.2%** (213/250) | 0% (down) |
| SYN flood — 10 000 PPS | **56.0%** (140/250) | 0% (down) |
| SYN flood — 20 000 PPS | **23.2%** (58/250) | 0% (down) |
| 1 000 concurrent HTTPS GET requests | Operational | Unresponsive |
| Slow HTTP connections (slowhttptest) | Operational | Unresponsive |
| ICMP ping sweep | No reply (looks offline) | Replied |
| TLS version/cipher scan | "Service unavailable" | Full info exposed |

Blacklisted IP drop capacity: **~14 000 packets/s** average, up to ~28 500 best-case.

---

## Hardware

| Component | Details |
|---|---|
| Board | Wiznet W6100-EVB-Pico2 |
| MCU | RP2350 (dual-core Cortex-M33/RISC-V, 150 MHz) |
| RAM | 520 kB SRAM |
| Flash | 2 MB (16 kB XIP cache) |
| Network chip | W6100 hardware TCP/IP, 8 sockets, 32 kB buffer |
| Sensor | Sensirion SEN63C (I²C) |
| Power draw | ~0.3 W average |
| Firmware size | 403 kB Flash |

---

## Project Structure

```
server_web/
├── server_web.c          # Main application entry point
├── CMakeLists.txt        # Build configuration
├── keygen.bat            # Certificate generation script (Windows)
├── server_crt.pem        # TLS certificate (generated)
├── server_key.pem        # TLS private key (generated)
├── src/
│   ├── include/          # Header files
│   │   └── sensor/       # Sensor driver headers
│   └── sensor/           # Sensirion SEN63C driver
└── web/                  # Embedded HTML/CSS for the monitoring page
```

Key source modules (in `src/`):

| File | Purpose |
|---|---|
| `crypto.c` | Chaskey MAC, HMAC, key derivation |
| `frame.c` | Packet frame parsing and validation |
| `blacklist.c` | Strike tracking and IP banning |
| `communication.c` | Phase 1 handshake logic |
| `https_handshake.c` | Phase 2 TLS session setup |
| `sntp.c` / `sntp_time.c` | NTP time sync |
| `sen63c_i2c.c` | Sensor driver |
| `debug.c` | UART logging (disable in production) |

---

## Building

This project is part of the [WIZnet RP2350 examples](https://github.com/WIZnet-ioLibrary/WIZnet-PICO-C) SDK. Place the `server_web/` folder inside the appropriate `examples/` directory.

**Toolchain versions used in the paper:**
- [Raspberry Pi Pico SDK](https://github.com/raspberrypi/pico-sdk) v2.2.0
- [WIZnet SDK](https://github.com/WIZnet-ioLibrary/WIZnet-PICO-C) v2.1.0
- [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) v3.6.0 (placed at `libraries/mbedtls/`)
- GNU Arm Embedded Toolchain v15.2.Rel1
- CMake ≥ 3.13 + Ninja

```bash
mkdir build && cd build
cmake .. -DPICO_BOARD=pico2
ninja server_web
```

Flash the resulting `server_web.uf2` onto the board by holding BOOTSEL and dragging the file onto the USB drive.

### ⚠️ Required: Patch `ssl_config.h` in the WIZnet SDK

Before building, you **must** update the Mbed TLS config file provided by the WIZnet SDK port. The file is located at:

```
port/mbedtls/inc/ssl_config.h
```

This file controls which TLS cipher suites and features are compiled into the firmware. SLEHS requires specific options to be enabled (ChaCha20-Poly1305, secp256r1, ECDSA) and others disabled to keep the binary small enough to fit on the RP2350. Without this change the build will either fail or produce a non-functional TLS configuration.

Replace the contents of `ssl_config.h` with the version provided in this repository before running `cmake`.

---

## Generating TLS Certificates

Run `keygen.bat` (Windows) or the equivalent OpenSSL commands:

```bash
# Generate P-256 private key
openssl ecparam -name prime256v1 -genkey -noout -out server_key.pem

# Generate self-signed certificate (valid 10 years)
openssl req -new -x509 -sha256 -key server_key.pem -out server_crt.pem \
    -days 3650 -subj "/CN=pico2-https"
```

Copy the contents of both `.pem` files into the appropriate header files in `src/include/` before building.

---

## Configuration

Key parameters are defined in `src/include/parameters.h`:

| Parameter | Default | Description |
|---|---|---|
| `MAX_SOCKETS` | 4 | Hardware socket limit |
| `MAX_HISTORY_HOURS` | 336 | History log size (2 weeks) |
| Pre-shared key | — | Must match on client and server |
| SYN timeout thresholds | 250/500/1000 ms | Adjustable per deployment |
| Ban duration | 24 hours | Time before a banned IP is unblocked |

### Deployment Mode (`DEPLOYMENT_OPTION`)

At the top of `server_web.c` there is a single switch that controls whether diagnostic commands are compiled in:

```c
#define TESTING 0   // Enables "stats" and "info" commands
#define PROD    1   // Disables them — minimal attack surface

#define DEPLOYMENT_OPTION TESTING  // <-- change this before flashing
```

| Mode | `"stats"` command | `"info"` command | Use when |
|---|---|---|---|
| `TESTING` | ✅ Enabled | ✅ Enabled | Development, evaluation, research |
| `PROD` | ❌ Disabled | ❌ Disabled | Any real deployment |

**Always set `DEPLOYMENT_OPTION PROD` before deploying to a public network.** In `PROD` mode the server only accepts `"web"` as a valid post-auth command, which minimises the amount of behaviour an attacker can probe or fingerprint.

---

## Security Notes

- **Change the pre-shared key** before deploying. It is the root of trust for the entire authentication chain. The current prototype defines it in a header file for convenience — production deployments should store it in **One-Time Programmable eFuse memory** (with read/write locking) or a dedicated hardware secure element to prevent firmware extraction.
- **Set `DEPLOYMENT_OPTION` to `PROD`** to disable the `"stats"` and `"info"` diagnostic commands. These exist only for evaluation and expose internal metrics to anyone who authenticates.
- The server uses a **self-signed certificate**. Clients must either accept it manually or have the certificate pre-installed.
- The blacklist is **volatile** (RAM only). It resets on power loss or reboot.

---

## Citation

If you use SLEHS in your research, please cite:

> N. Kuropatkin and M. Drutarovsky, "Secure Lightweight Embedded HTTPS Server: Autonomous Threat Detection and Mitigation at the Edge," Technical University of Košice, 2026.

## Acknowledgements

Co-financed by the **European Union** through the Slovakia Programme under project No. NFP401101C360 (*Research and development of advanced AI solutions for detection of cyber threats and defense against sophisticated attacks*) and by the **Slovak Cultural and Educational Grant Agency (KEGA)** under Contract No. 041TUKE-4/2025. Hardware provided by **SOS Electronic**.
