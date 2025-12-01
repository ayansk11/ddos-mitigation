# Multi-Layer DDoS Detection and Mitigation using XDP, P4, and BGP Flowspec

This project implements a realistic, multi-layer DDoS detection and mitigation pipeline combining:

- **XDP/eBPF** — kernel-level early packet filtering  
- **P4 programmable switch** — in-network detection using counters and custom drop rules  
- **BGP Flowspec / RTBH simulation** — upstream traffic suppression (ISP-style mitigation)

The system was implemented and tested on **Jetstream2 cloud VMs**, with traffic and results captured from real packet flows.

---

## 🚀 Project Overview

A Distributed Denial-of-Service (DDoS) attack overwhelms networks with excessive traffic.  
Traditional firewalls and routers cannot keep up at high packet rates.  
This project uses *programmability* across the network stack to defend against such attacks.

### Architecture Layers

1. **Tier 1: XDP DDoS Filter (Linux kernel)**
   - Runs before the Linux TCP/IP stack
   - Tracks packet counts per source IP using a BPF map
   - Drops malicious traffic using `XDP_DROP`
   - Fastest possible mitigation (~10M packets/sec on bare metal)

2. **Tier 2: P4-Based Detection (BMv2 Mininet)**
   - P4 switch maintains per-flow counters
   - When threshold is exceeded, flow is marked as DDoS
   - All further traffic from attacker is dropped in-switch
   - CLI can read counters via `simple_switch_CLI`

3. **Tier 3: BGP Flowspec + RTBH Simulation**
   - Simulated ISP upstream filtering
   - Flowspec rule discards traffic to a target prefix + port
   - RTBH (Remote Triggered Blackholing) simulates “sinkholing” attack traffic upstream

---

## 🗂 Directory Structure

