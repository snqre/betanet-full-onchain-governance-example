# Betanet Version 1.0 – Official Implementation Specification

> **Normative document.**  All requirements marked **MUST**, **MUST NOT**, or **SHALL** are mandatory for compliance.

---

## 0  Status & Scope

Betanet is a fully decentralised, censorship-resistant network intended to replace the public Internet.
The design eliminates single points of failure, disguises itself as ordinary HTTPS, and makes selective blocking economically or politically prohibitive.

---

## 1  General Encoding Rules

* Multi-byte integers: **unsigned big-endian**.
* `varint`: QUIC variable-length integer (RFC 9000 §16).
* Unless stated, all sizes are in bytes.
* Binary examples use hexadecimal.

---

## 2  Cryptography

| Purpose                         | Primitive                                          |
| ------------------------------- | -------------------------------------------------- |
| Hash                            | **SHA-256** (32 B)                                 |
| AEAD                            | **ChaCha20-Poly1305** (IETF, 12-B nonce, 16-B tag) |
| KDF                             | **HKDF-SHA256**                                    |
| Signatures                      | **Ed25519**                                        |
| Diffie–Hellman                  | **X25519**                                         |
| Post-quantum hybrid<sup>†</sup> | **X25519-Kyber768** (draft-ietf-pqtls-00)          |

> † Offering the hybrid ciphersuite is **MUST** after *2027-01-01*.

---

## 3  Layer Model

| Layer  | Function                                                    |
| ------ | ----------------------------------------------------------- |
| **L0** | Access media (any IP bearer: fibre, 5 G, sat, LoRa, etc.)   |
| **L1** | Path selection & routing (SCION + IP-transition header)     |
| **L2** | Cover transport (HTX over TCP-443 / QUIC-443)               |
| **L3** | Overlay mesh (libp2p-v2 object relay)                       |
| **L4** | Optional privacy hop (Nym mixnet)                           |
| **L5** | Naming & trust (self-certifying IDs + 3-chain alias ledger) |
| **L6** | Payments (federated Cashu + Lightning)                      |
| **L7** | Applications                                                |

---

## 4  Path Layer (L1)

### 4.1 SCION Packet Header

```
0       1       2       3
+-------+-------+-------+-------+
|Ver=0x2|Reserved|  Type        |
+-------------------------------+
|     Total Header Length       |
+-------------------------------+
|       Payload Length          |
+-------------------------------+
|      Path Segment 0 …         |
+-------------------------------+
```

* **Ver** MUST be `0x02`.
* **Type** MUST be `0x01` (single path) or `0x03` (path list).
* Each AS-hop signature in every segment **MUST** verify before forwarding; otherwise drop.

### 4.2 IP-Transition Header

For links without native SCION support, prepend:

```
+-------+-------------------------------------------------+
| ID=0xF1 | 64-B Ed25519 sig over (prev-AS ‖ next-AS)     |
+-------+-------------------------------------------------+
```

Gateways **MUST** verify and strip this header when re-entering a SCION-capable segment.

### 4.3 Path Maintenance

End hosts **MUST** maintain **≥ 3** disjoint validated paths to every peer and switch within **300 ms** of failure detection.

---

## 5  Cover Transport (L2) — HTX

### 5.1 Outer TLS 1.3 Handshake

* Client **MUST** mimic Chrome Stable (N-2) using uTLS rules.
* **ECH** is attempted first; fallback is silent.
* ALPN probabilities: `h3` 70 %, `h2` 25 %, `http/1.1` 5 %.
* Hybrid ciphersuite (Kyber768) **MUST** be present once the date criterion is met.

### 5.2 Access-Ticket Bootstrap

1. The server’s decoy site embeds `ticketPub` (32-B X25519 public key, Base64URL).
2. Client generates `ticketPriv`, computes `sharedSecret = X25519(ticketPriv, ticketPub)`.
3. Client picks 32-B random `nonce32`.
4. `accessTicket = HKDF(sharedSecret, "betanet-ticket", nonce32, 32)`.
5. Client sends

   ```
   GET /bootstrap HTTP/1.1
   Host: <front-domain>
   x-px-ticket: <Base64URL(accessTicket)>
   ```
6. If ticket matches current UTC hour, server proceeds; else serves only decoy content.

### 5.3 Noise *XK* Handshake & Inner Keys

Unchanged from §2 .3 of prior draft: derive `K_inner = HKDF-Expand-Label(TLS-Exporter, "htx inner", "", 32)`.
AEAD nonce: **96-bit little-endian counter** (wrap ≈2⁹⁶-1 frames).

### 5.4 Inner Frame Format

```c
struct Frame {
  uint24  length;     // ciphertext length (excl. tag)
  uint8   type;       // 0=STREAM, 1=PING, 2=CLOSE
  varint  stream_id;  // present if type==STREAM
  uint8[] ciphertext;
}
```

* Client streams use **odd** `stream_id`; server streams **even**.
* Flow-control window: **65 535 B**; `WINDOW_UPDATE` frames substitute when 50 % consumed.

### 5.5 HTTP/2 Behaviour Emulation

| Frame          | Requirement                   |
| -------------- | ----------------------------- |
| SETTINGS       | Within 30 ms of stream 0 open |
| WINDOW\_UPDATE | When ≥ 50 % of window used    |
| PING           | Every 15 s ± 3 s              |
| PRIORITY       | On ≈1 % of connections        |

Idle padding: if no DATA for 512 ± 128 ms, send dummy 1 KiB encrypted DATA.

### 5.6 UDP Variant

* Attempt QUIC v1 on UDP-443 + MASQUE `CONNECT-UDP`.
* On failure, retry TCP within **500 ms**.

---

## 6  Overlay Mesh (L3)

### 6.1 Peer Identity

`PeerID =` multihash `0x12 0x20 || SHA-256(pubkey)`.

### 6.2 Transports

```
/betanet/htx/1.0.0      (TCP-443)
/betanet/htxquic/1.0.0  (QUIC-443)
/betanet/webrtc/1.0.0   (optional)
```

### 6.3 Bootstrap Discovery

The client **MUST** keep trying methods **a → e** until ≥ 5 peers respond:

| Order | Method                                                             | Central infra?      |
| ----- | ------------------------------------------------------------------ | ------------------- |
| a     | **Deterministic DHT**: 32 synthetic IDs `SHA256("betanet-seed-i")` | No                  |
| b     | **mDNS** service `_betanet._udp`                                   | No                  |
| c     | **Bluetooth LE** UUID `0xB7A7`                                     | No                  |
| d     | Onion v3 list (signed, mirrored via IPFS)                          | Minimal             |
| e     | DNS fallback list                                                  | Yes (fallback only) |

### 6.4 Block Exchange

* CID =`multihash(SHA-256(content))`.
* Bitswap-v2 on `/betanet/bitswap/2.1.0`.
* Requester **SHOULD** open ≥ 3 parallel streams on distinct SCION paths.

---

## 7  Privacy Layer (L4)

### 7.1 Modes

| Mode                   | Requirement                           |
| ---------------------- | ------------------------------------- |
| **strict**             | Every stream through ≥ 3 Nym hops     |
| **balanced** (default) | ≥ 1 hop until peer-trust ≥ 0.8        |
| **performance**        | No mixnet unless dest label `.mixreq` |

### 7.2 Mixnode Selection

`seed = SHA256(srcPeerID || dstPeerID || unixHour)`
— used as VRF input to pick hops.

---

## 8  Naming & Trust (L5)

### 8.1 Self-Certifying ID

```
betanet://<hex SHA-256(service-pubkey)>[/resource]
```

Verify that the peer’s presented pubkey hashes to the ID.

### 8.2 Human-Readable Alias Ledger

A record is valid **only if** identical payload appears at the same height on at least **2 of 3** chains:

* **Handshake** Layer-1
* **Filecoin FVM**
* **Ethereum L2 “Raven-Names”**

Re-orgs deeper than 12 blocks are ignored.

Record format (UTF-8):

```
betanet1 pk=<hex32> sig=<base64sig> exp=<unixSec>
```

---

## 9  Payment System (L6)

### 9.1 Federated Cashu Mints

* Each mint = FROST-Ed25519 **(n ≥ 5, t = 3)** group.
* Keyset ID =`SHA-256(sorted pubkeys)`.
* Relays **MUST** accept vouchers from any announced keyset (topic `betanet.mints`).

Voucher (64 B): `secret32 || aggregatedSig32`.

### 9.2 Settlement

Relays **MAY** redeem ≥ 10 000 sat via their own Lightning node or swap with peers.
Vouchers never leave encrypted streams.

---

## 10  Governance & Versioning (L7)

### 10.1 Node Uptime Score

```
score = log2(1 + seconds_uptime / 86 400)   // capped at 16
```

### 10.2 Voting Power

```
vote_weight = uptime_score + log10(total_ecash_staked / 1 000 sat + 1)
```

A version proposal passes when

```
Σ weight(ACK) ≥ 0.67 × Σ weight(all_reachable_nodes)
```

### 10.3 Upgrade Delay

After threshold reached, activation waits **≥ 30 days**.
Raven Development Team publishes a time-lock hash of the final spec text.

---

## 11  Compliance Summary

An implementation is **compliant** if it:

1. Implements HTX over TCP-443 **and** QUIC-443 with TLS 1.3 mimic + ECH.
2. Uses rotating access tickets (§5.2).
3. Encrypts inner frames with ChaCha20-Poly1305, 24-bit length, 96-bit nonce.
4. Maintains ≥ 3 signed SCION paths **or** attaches a valid IP-transition header.
5. Offers `/betanet/htx/1.0.0` **and** `/betanet/htxquic/1.0.0` transports.
6. Implements deterministic DHT seed bootstrap.
7. Verifies alias ledger with 2-of-3 chain consensus.
8. Accepts Cashu vouchers from federated mints & supports Lightning settlement.
9. Builds reproducibly and publishes **SLSA 3** provenance.
10. Presents X25519-Kyber768 suites once the mandatory date is reached.

---

## 12  End of Betanet Specification 1.0
