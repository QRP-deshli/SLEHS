# SLEHS — Secure Lightweight Embedded HTTPS Server

A secure HTTPS server for the **RP2350 microcontroller** (Wiznet W6100-EVB-Pico2 board) that provides encrypted web access and actively defends itself against network attacks — all while consuming just **0.25 W** of power.

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
  • TLS 1.3, ECDSA + ChaCha20-Poly1305 / NIST P-256
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
- **64 strike slots** for temporary violations (reset hourly)
- **64 ban slots** for serious offenders — 4 strikes = 24-hour ban
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
| SYN flood — 1 000 PPS | **98%** success rate | 0% (down) |
| SYN flood — 5 000 PPS | **85%** success rate | 0% (down) |
| SYN flood — 10 000 PPS | **56%** success rate | 0% (down) |
| SYN flood — 20 000 PPS | **23%** success rate | 0% (down) |
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
| Power draw | ~0.25 W average |

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

**Prerequisites:**
- [Raspberry Pi Pico SDK](https://github.com/raspberrypi/pico-sdk)
- [WIZnet ioLibrary](https://github.com/WIZnet-ioLibrary/WIZnet-PICO-C)
- [mbedTLS](https://github.com/Mbed-TLS/mbedtls) (placed at `libraries/mbedtls/`)
- CMake ≥ 3.13, ARM GCC toolchain

```bash
mkdir build && cd build
cmake .. -DPICO_BOARD=pico2
make server_web
```

Flash the resulting `server_web.uf2` onto the board by holding BOOTSEL and dragging the file onto the USB drive.

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

---

## Security Notes

- **Change the pre-shared key** before deploying. It is the root of trust for the entire authentication chain.
- The `"stats"` and `"info"` diagnostic commands are intended for evaluation only. Disable them in production by removing them from the command handler to reduce attack surface.
- The server uses a **self-signed certificate**. Clients must either accept it manually or have the certificate pre-installed.
- The blacklist is **volatile** (RAM only). It resets on power loss or reboot.

---

## Acknowledgements

Funded in part by **EU NextGenerationEU** through the Recovery and Resilience Plan for Slovakia (project No. 09I05-03-V02-00019) and by **KEGA** under Contract No. 041TUKE-4/2025. Hardware provided by **SOS Electronic**.
