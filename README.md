# Passive-Network-Scanning
Passive Network Probe → Neo4j Attack Path Graph

This project provides a PowerShell script (passive_probing_v2.ps1) that passively enumerates a host’s network context — including interfaces, subnets, gateways, routing tables, listening services, and DNS cache — without generating active traffic.

The output is a graph-ready JSON (csam_snapshot_graph.json) designed for direct ingestion into Neo4j.
Once imported, it allows security analysts to:

Visualize host-to-subnet and service reachability

Model attack paths and lateral movement possibilities

Score and filter edges by evidence and confidence

Use Neo4j Bloom to explore relationships interactively

🧩 Key Features

Passive enumeration (no packet generation)

Rich metadata capture: IPs, routes, gateways, listening ports, binaries

Evidence-backed graph edges (each relationship has supporting artifacts)

Built-in confidence scoring for edges (score: 0–10)

Easy Neo4j import — nodes and relationships are pre-labeled

🕸️ Graph Model Overview

Node types:
Host, Interface, Subnet, Gateway, Neighbor, Service, DNSName, ProcessArtifact

Edge types:
HAS_INTERFACE, IN_SUBNET, CONNECTED_TO_GATEWAY, EXPOSES, CAN_REACH,
RESOLVES_TO, IS_HOST, RUNS_AS, ON_SUBNET

🚀 How to Use

Run passive_probing_v2.ps1 on a Windows host.

.\passive_probing_v2.ps1 -OutputFile .\csam_snapshot_graph.json


Import the generated JSON into Neo4j using your preferred loader (Python or Cypher script).

Explore relationships in Neo4j Bloom using search phrases like:

Subnet CAN_REACH Service

Host EXPOSES Service

Gateway CONNECTED_TO Subnet

📈 Example Visualization

The Bloom graph reveals subnet-to-service reachability and potential pivot paths, helping analysts see network exposure the way an attacker would.

🧠 Use Cases

Internal attack path analysis

Exposure and lateral movement mapping

Integration with security posture or asset intelligence syste
