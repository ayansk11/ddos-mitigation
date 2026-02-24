# Multi-Layer DDoS Detection and Mitigation

### XDP/eBPF | P4 Programmable Switches | BGP FlowSpec & RTBH

![C](https://img.shields.io/badge/C-XDP%2FeBPF-blue)
![P4](https://img.shields.io/badge/P4-BMv2-green)
![Python](https://img.shields.io/badge/Python-Mininet-yellow)
![BGP](https://img.shields.io/badge/BGP-FRR-orange)
![Platform](https://img.shields.io/badge/Tested%20on-Jetstream2-purple)

A defense-in-depth DDoS mitigation system that operates across three layers of the network stack, from kernel-level packet filtering to ISP-scale upstream traffic suppression. Built and tested on **Jetstream2 cloud VMs** with real packet flows.

---

## Problem

Distributed Denial-of-Service (DDoS) attacks flood networks with millions of packets per second. Traditional firewalls and routers can't keep up. A single point of defense is never enough; attackers adapt, and volumetric floods can saturate any single chokepoint.

## Solution

This project implements **three independent, complementary defense tiers** using programmable networking technologies:

```
                    ┌─────────────────────────────────────────────┐
                    │              INTERNET / ATTACKER            │
                    └──────────────────┬──────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │  TIER 3: BGP FlowSpec / RTBH                 │
                    │  ISP upstream filtering                      │
                    │  → Discard traffic before it reaches network │
                    │  → Remote Triggered Black Hole routing       │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │  TIER 2: P4 Programmable Switch              │
                    │  In-network detection (BMv2)                 │
                    │  → Per-flow counters with threshold          │
                    │  → Drop + mirror suspect traffic             │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │  TIER 1: XDP/eBPF (Linux Kernel)             │
                    │  Earliest possible interception              │
                    │  → Per-source-IP rate limiting               │
                    │  → ~10M packets/sec on bare metal            │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────────┐
                    │              PROTECTED SERVER               │
                    └─────────────────────────────────────────────┘
```

---

## Architecture

### Tier 1: XDP DDoS Filter (Linux Kernel)

The first line of defense runs **before** the Linux TCP/IP stack even processes the packet.

- **Technology:** XDP (eXpress Data Path) + eBPF
- **Mechanism:** Per-source-IP sliding window rate limiting using BPF hash maps
- **Threshold:** 5,000 packets/sec per source IP (configurable)
- **Action:** `XDP_DROP` for offending sources, with per-CPU drop counters
- **Performance:** ~10 million packets/sec on bare metal

```c
// Rate check in the XDP program
if (st->pkt_count > THRESHOLD_PKTS) {
    count_drop();
    return XDP_DROP;  // Dropped before TCP/IP stack
}
```

### Tier 2: P4-Based Detection (BMv2 Switch)

In-network detection at the switch dataplane catches what gets past Tier 1.

- **Technology:** P4 (v1model) on BMv2 behavioral model
- **Mechanism:** Per-flow packet counters using P4 registers (1024 flows)
- **Threshold:** 10,000 packets per flow
- **Action:** Flag as suspect → mirror to CPU port + drop in dataplane
- **Simulation:** Mininet with BMv2 `simple_switch`

### Tier 3: BGP FlowSpec + RTBH Simulation

When local defenses are overwhelmed, push filtering upstream to the ISP.

- **Technology:** BGP with FRR (Free Range Routing)
- **FlowSpec:** ISP advertises fine-grained drop rules (match on dst IP + protocol + port)
- **RTBH:** Customer signals victim prefix with community `65535:666` → ISP null-routes attack traffic
- **Simulation:** Mininet topology with two FRR routers (AS 65001 ↔ AS 65002)

---

## Project Structure

```
ddos-mitigation/
├── xdp/
│   ├── xdp_ddos_filter.c      # eBPF/XDP rate-limiting program
│   ├── xdp_ddos_filter.o       # Compiled eBPF object
│   └── README.md
├── p4/
│   └── ddos_detect.p4          # P4 switch program with per-flow detection
├── bgp/
│   ├── topo_flowspec.py        # Mininet topology with FRR routers
│   ├── flowspec.rules          # BGP FlowSpec configuration
│   └── rtbh.rules              # RTBH (Remote Triggered Black Hole) config
├── SNS_Project.pdf             # Detailed project report
└── README.md
```

---

## Getting Started

### Prerequisites

- Linux kernel 4.18+ (for XDP support)
- `clang` and `llvm` (to compile eBPF programs)
- BMv2 (`simple_switch`) and P4 compiler (`p4c`)
- Mininet and FRR (for BGP simulation)
- Jetstream2 VM or similar cloud environment (recommended)

### Tier 1: XDP Filter

```bash
# Compile the XDP program
clang -O2 -target bpf -c xdp/xdp_ddos_filter.c -o xdp/xdp_ddos_filter.o

# Attach to a network interface
sudo ip link set dev eth0 xdp obj xdp/xdp_ddos_filter.o sec xdp

# Monitor drops via trace pipe
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Tier 2: P4 Switch

```bash
# Compile the P4 program
p4c --target bmv2 --arch v1model p4/ddos_detect.p4

# Run in Mininet with BMv2
sudo simple_switch --interface 0@veth0 --interface 1@veth1 ddos_detect.json

# Check counters
simple_switch_CLI <<< "register_read src_ip_counter"
```

### Tier 3: BGP FlowSpec / RTBH

```bash
# Start the Mininet topology with FRR routers
sudo python3 bgp/topo_flowspec.py

# Apply FlowSpec rules on Router 1
vtysh -f bgp/flowspec.rules

# Apply RTBH rules on Router 2
vtysh -f bgp/rtbh.rules
```

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| XDP over iptables | XDP processes packets before the kernel network stack, achieving 10x+ throughput |
| Per-source-IP tracking (Tier 1) | Identifies individual attackers in volumetric floods |
| Per-flow tracking (Tier 2) | Catches coordinated attacks from varying sources targeting the same destination |
| BGP community 65535:666 for RTBH | Industry-standard trigger community recognized by major ISPs |
| Three independent tiers | Defense-in-depth — each tier operates independently, no single point of failure |

---

## Testing Environment

- **Platform:** Jetstream2 Cloud (Indiana University)
- **Traffic Generation:** Real packet flows with controlled attack patterns
- **Validation:** Packet counters, trace logs, and BGP route table verification
- **Report:** See [`SNS_Project.pdf`](SNS_Project.pdf) for full methodology, results, and analysis

---

## Technologies

| Component | Technology | Language |
|-----------|-----------|----------|
| Kernel filter | XDP / eBPF | C |
| Switch detection | P4 / BMv2 | P4 |
| Network simulation | Mininet | Python |
| BGP routing | FRR (Free Range Routing) | Config |
| Cloud platform | Jetstream2 | — |

---

## Course Context

Developed as a project for the **Security for Networked Systems** Course at **Indiana University Bloomington**.

---

## License

This project is open source and available for educational and research purposes.
