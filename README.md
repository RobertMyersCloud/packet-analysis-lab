# Packet Analysis Lab

Hands-on packet analysis with **tcpdump** and **Wireshark**, combining networking fundamentals, troubleshooting, and security-oriented traffic analysis.

This project was built in a controlled home lab to move beyond command memorization and answer a practical question:

> Can I capture traffic, explain what the network is doing, recognize when behavior is abnormal, and support conclusions with packet-level evidence?

The lab progresses from normal traffic to troubleshooting and finally to controlled suspicious patterns. The goal is not to label every anomaly as malicious. It is to understand what the packets actually support.

---

## What This Project Demonstrates

### Network fundamentals
- ARP request/reply behavior
- ICMP echo request/reply analysis
- TCP three-way handshake
- TCP sequence and acknowledgment numbers
- Source and destination ports
- Routed Layer 2 vs Layer 3 behavior
- TTL behavior across a routed hop
- SSH protocol negotiation and encrypted traffic
- DNS queries, responses, record types, transaction IDs, and TTLs

### Troubleshooting
- Working vs failed DNS resolution
- Open vs closed vs filtered TCP ports
- SYN, SYN/ACK, ACK, RST/ACK, and retransmission behavior
- Distinguishing service failure from path or policy failure
- Using tcpdump for remote command-line triage
- Using Wireshark for deeper packet inspection

### Security analysis
- Controlled reconnaissance / port-enumeration pattern
- One-source / one-target / many-port behavior
- Repeated SYN activity
- Periodic beacon-like traffic
- Metadata visible in encrypted SSH
- Separating suspicious indicators from proof of compromise

---

## Lab Context

| System | Role | Address |
|---|---|---|
| Windows 11 workstation | Wireshark analysis / traffic generation | 10.10.20.102 |
| Fedora workstation | tcpdump capture / protected lab host | 10.10.30.100 |
| ER605 | Inter-network routing / policy boundary | 10.10.20.1 / 10.10.30.1 |
| Fedora gateway segment | Protected lab network | 10.10.30.0/24 |
| Management segment | Management / test network | 10.10.20.0/24 |

The Windows workstation also had normal internet access through its household network. Fedora's lab-side network was intentionally restricted from normal internet egress during part of the testing, which became useful for DNS failure analysis.

Raw PCAP files are retained locally and excluded from the public repository. Public evidence uses sanitized screenshots.

---

# Part 1 — Network Fundamentals

## 1. ARP and ICMP Baseline

The first capture established a basic local-network baseline between Fedora and its gateway.

A tcpdump capture showed ARP resolution followed by ICMP echo requests and replies.

![tcpdump ARP and ICMP capture](evidence/01-tcpdump-arp-icmp-capture.png)

Key observations:

- ARP resolves an IPv4 address to a Layer 2 MAC address on the local broadcast domain.
- The ARP cache and the switch CAM/MAC table are different:
  - ARP maps **IP address → MAC address**.
  - A switch CAM table maps **MAC address → switch port**.
- ICMP echo requests and replies can be paired by identifier and sequence number.
- The identifier helps associate packets with the same echo session/process.
- The sequence number distinguishes individual requests within that session.

Wireshark provided the same ICMP exchange in a more visual form.

![Wireshark ICMP baseline](evidence/02-wireshark-icmp-baseline.png)

The four request/reply pairs show a clean baseline with matching echo sequence numbers.

---

## 2. TCP Three-Way Handshake over SSH

A fresh Windows-to-Fedora SSH session was captured with tcpdump.

![tcpdump SSH three-way handshake](evidence/03-tcpdump-ssh-three-way-handshake.png)

The connection began with:

```text
Windows 10.10.20.102:<ephemeral> -> Fedora 10.10.30.100:22  SYN
Fedora  10.10.30.100:22         -> Windows <ephemeral>     SYN, ACK
Windows <ephemeral>              -> Fedora :22              ACK
```

Important points:

- The Windows client used an ephemeral source port.
- Fedora listened on TCP/22.
- The SYN consumes one sequence number.
- Each side maintains its own independent TCP sequence space.
- Wireshark relative sequence numbering makes the stream easier to follow than raw 32-bit values.

---

## 3. Routed Layer 2 vs Layer 3 Behavior

A routed SSH packet showed one of the most useful networking concepts in the project.

![Wireshark routed SSH frame](evidence/04-wireshark-routed-ssh-frame.png)

The packet showed:

```text
Layer 2:
ER605 MAC -> Fedora MAC

Layer 3:
10.10.20.102 -> 10.10.30.100

TCP:
ephemeral port -> 22
```

Because Windows and Fedora were on different subnets, the ER605 routed the packet into the Fedora network.

The IP source and destination remained:

```text
10.10.20.102 -> 10.10.30.100
```

while the Ethernet header represented the final local hop:

```text
ER605 -> Fedora
```

The captured packet also showed a TTL of 127, consistent with a packet that likely started at a common Windows default of 128 and crossed one routed hop.

---

## 4. SSH Metadata and Encryption

The SSH session demonstrated that encryption protects the interactive session but does not make all metadata disappear.

![Wireshark SSH metadata and encryption](evidence/05-wireshark-ssh-metadata-and-encryption.png)

Visible information included:

- SSHv2
- key-exchange algorithms
- host-key algorithms
- encryption algorithms
- integrity/authentication options
- compression options
- direction of traffic

A Follow TCP Stream view showed the readable client and server banners before the stream became largely opaque.

![Wireshark Follow TCP Stream SSH](evidence/06-wireshark-follow-tcp-stream-ssh.png)

The key lesson:

> TCP stream reconstruction can rebuild the byte stream, but it does not decrypt an SSH session.

Even with encryption, an analyst can still observe endpoints, ports, timing, packet sizes, TCP state, software banners, key-exchange behavior, and traffic direction.

---

# Part 2 — Troubleshooting

## 5. DNS Failure: Queries Without Responses

Fedora had a DNS server configured, but the lab policy prevented the expected upstream communication path from working.

![tcpdump DNS blocked retries](evidence/07-tcpdump-dns-blocked-retries.png)

The capture showed the same DNS transaction retried multiple times:

```text
10.10.30.100:53000 -> 10.10.31.1:53  A? example.com
```

with no response packets.

This proved:

- the client generated valid DNS queries
- the queries left the Fedora host
- the client retried the same unresolved transaction
- the failure was farther down the path than the application simply "not trying"

---

## 6. Working DNS Query and Response

A healthy DNS exchange was captured on the Windows workstation using `1.1.1.1`.

![Wireshark working DNS query response](evidence/08-wireshark-dns-working-query-response.png)

The query and response for `www.googleapis.com` demonstrated:

- client-to-resolver query
- resolver-to-client response
- matching DNS transaction IDs
- A record resolution
- normal request/response behavior

The detailed response showed the DNS answer structure.

![Wireshark DNS response details](evidence/09-wireshark-dns-response-details.png)

The response included:

- standard query response
- no error
- one question
- multiple answer resource records
- Type A
- Class IN
- IPv4 addresses
- DNS TTL values

| Field | Purpose |
|---|---|
| IP TTL | Limits how many routed hops a packet can cross |
| DNS TTL | Controls how long a DNS answer can be cached |

---

## 7. Open, Closed, and Filtered TCP States

### Open port

The working SSH service on TCP/22 showed:

```text
SYN -> SYN/ACK -> ACK
```

Interpretation: host reachable, service listening, TCP connection established.

### Closed port

A controlled connection attempt to TCP/65000 produced an immediate reset.

![tcpdump closed port RST](evidence/10-tcpdump-closed-port-rst.png)

![Wireshark closed port RST](evidence/11-wireshark-closed-port-rst.png)

Pattern:

```text
SYN -> RST/ACK
```

Interpretation: the target host was reachable, but nothing was listening on that destination port.

### Filtered / dropped port

A temporary host firewall drop rule was used on TCP/65001.

![tcpdump filtered port timeout](evidence/12-tcpdump-filtered-port-timeout.png)

![Wireshark filtered port retransmissions](evidence/13-wireshark-filtered-port-retransmissions.png)

Pattern:

```text
SYN -> no response
SYN retransmission -> no response
SYN retransmission -> no response
```

The retransmission timing increased approximately 1, 2, 4, and 8 seconds.

| State | Packet Pattern | Likely Interpretation |
|---|---|---|
| Open | SYN → SYN/ACK → ACK | Host reachable, service listening |
| Closed | SYN → RST/ACK | Host reachable, service not listening |
| Filtered / dropped | SYN → retries → silence | Traffic being dropped or path/policy issue |

---

# Part 3 — Security Analysis

## 8. Controlled Reconnaissance Pattern

A bounded test generated connection attempts from one source against multiple service ports on the Fedora target.

![tcpdump controlled recon pattern](evidence/14-tcpdump-controlled-recon-pattern.png)

Ports included examples such as:

```text
21
22
23
25
53
80
110
443
445
3389
65000
```

Wireshark made the pattern more obvious by filtering for SYN packets.

![Wireshark controlled recon SYN pattern](evidence/15-wireshark-controlled-recon-syn-pattern.png)

What made the activity stand out was the behavior:

```text
one source
+
one target
+
many destination ports
+
short time interval
```

The observed pattern was **consistent with reconnaissance or port enumeration**.

It was not treated as proof of malicious intent or compromise.

---

## 9. Controlled Periodic Beacon-Like Traffic

A temporary HTTP service was started on Fedora, and the Windows host made repeated requests at approximately ten-second intervals.

![tcpdump periodic traffic pattern](evidence/16-tcpdump-periodic-traffic-pattern.png)

The activity occurred at approximately:

```text
22:59:43
22:59:53
23:00:03
23:00:13
23:00:23
23:00:33
```

Wireshark showed repeated connection bursts to the same destination and service.

![Wireshark periodic beacon-like pattern](evidence/17-wireshark-periodic-beacon-like-pattern.png)

Each burst included:

- TCP handshake
- HTTP request
- HTTP response
- connection teardown

Consistent periodic communication can be an indicator of beacon-like behavior.

However:

> Periodicity alone is not proof of command-and-control activity.

Legitimate systems can also communicate at regular intervals, including monitoring agents, health checks, scheduled jobs, polling applications, and management tools.

---

# Analysis Workflow

```text
Capture
  ↓
Identify endpoints
  ↓
Identify protocol / ports
  ↓
Establish normal behavior
  ↓
Find deviation
  ↓
Measure timing / repetition / responses
  ↓
Form a packet-supported conclusion
  ↓
State what the evidence does NOT prove
```

Packet analysis can identify strong indicators and narrow an investigation, but a suspicious pattern should not automatically be presented as proof of compromise.

---

# Tools Used

- **tcpdump**
  - interface selection
  - capture filters
  - host filters
  - protocol filters
  - port filters
  - bounded captures
  - PCAP creation
  - offline PCAP reading

- **Wireshark**
  - display filters
  - packet dissection
  - protocol fields
  - TCP sequence and acknowledgment analysis
  - TCP flag analysis
  - DNS inspection
  - SSH metadata
  - Follow TCP Stream
  - retransmission identification
  - timing analysis

- **PowerShell**
  - connection testing
  - traffic generation
  - controlled port probes
  - periodic HTTP requests

- **Linux / Fedora**
  - tcpdump capture point
  - SSH service
  - temporary HTTP service
  - controlled firewall testing

---

# Key Takeaways

1. **Packet capture separates symptoms from causes.**  
   A failed connection can mean an unreachable path, a silent firewall drop, or a closed service. Those conditions look different on the wire.

2. **tcpdump and Wireshark serve different purposes.**  
   tcpdump is effective for remote capture and fast command-line triage. Wireshark is better for deep visual analysis.

3. **Layer 2 and Layer 3 tell different parts of the path.**  
   Routed packets keep their Layer 3 endpoints while Ethernet headers change for the local hop.

4. **Encryption does not eliminate metadata.**  
   SSH protects the interactive contents, but endpoint, timing, protocol, version, size, and negotiation metadata remain observable.

5. **Patterns matter more than isolated packets.**  
   One SYN is normal. One source probing many ports quickly is more interesting. Repeated communication at fixed intervals is more interesting. Context determines whether those indicators are expected or suspicious.

6. **An indicator is not the same thing as proof.**  
   Recon-like and beacon-like traffic should trigger investigation, not automatic claims of compromise.

---

# Evidence Index

| # | Evidence |
|---|---|
| 01 | [tcpdump ARP and ICMP capture](evidence/01-tcpdump-arp-icmp-capture.png) |
| 02 | [Wireshark ICMP baseline](evidence/02-wireshark-icmp-baseline.png) |
| 03 | [tcpdump SSH three-way handshake](evidence/03-tcpdump-ssh-three-way-handshake.png) |
| 04 | [Wireshark routed SSH frame](evidence/04-wireshark-routed-ssh-frame.png) |
| 05 | [Wireshark SSH metadata and encryption](evidence/05-wireshark-ssh-metadata-and-encryption.png) |
| 06 | [Wireshark Follow TCP Stream SSH](evidence/06-wireshark-follow-tcp-stream-ssh.png) |
| 07 | [tcpdump blocked DNS retries](evidence/07-tcpdump-dns-blocked-retries.png) |
| 08 | [Wireshark working DNS query and response](evidence/08-wireshark-dns-working-query-response.png) |
| 09 | [Wireshark DNS response details](evidence/09-wireshark-dns-response-details.png) |
| 10 | [tcpdump closed-port RST](evidence/10-tcpdump-closed-port-rst.png) |
| 11 | [Wireshark closed-port RST](evidence/11-wireshark-closed-port-rst.png) |
| 12 | [tcpdump filtered-port timeout](evidence/12-tcpdump-filtered-port-timeout.png) |
| 13 | [Wireshark filtered-port retransmissions](evidence/13-wireshark-filtered-port-retransmissions.png) |
| 14 | [tcpdump controlled recon pattern](evidence/14-tcpdump-controlled-recon-pattern.png) |
| 15 | [Wireshark controlled recon SYN pattern](evidence/15-wireshark-controlled-recon-syn-pattern.png) |
| 16 | [tcpdump periodic traffic pattern](evidence/16-tcpdump-periodic-traffic-pattern.png) |
| 17 | [Wireshark periodic beacon-like pattern](evidence/17-wireshark-periodic-beacon-like-pattern.png) |

---

# Public Evidence and Sanitization

The public repository contains screenshots rather than raw packet captures.

Raw PCAP files are intentionally retained locally and excluded through `.gitignore`.

Before publication, screenshots were reviewed to remove or avoid:

- MAC addresses where unnecessary
- credentials
- passwords
- private keys
- authentication tokens
- unrelated browsing history
- unnecessary system identifiers

RFC1918 lab IP addresses, test ports, protocol metadata, and controlled test traffic remain visible because they are necessary to explain the network behavior demonstrated by the project.

---

# Result

This lab started as practice with tcpdump and Wireshark and developed into a compact packet-analysis investigation.

The final project demonstrates the ability to:

- capture traffic remotely
- analyze packets at multiple protocol layers
- explain TCP and DNS behavior
- distinguish open, closed, and filtered services
- recognize recon-like patterns
- recognize periodic beacon-like patterns
- work with encrypted-session metadata
- troubleshoot from packet evidence
- make conclusions that stay within what the traffic actually proves
