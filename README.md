# Bye — Polymorphic Pipeline Obfuscation (PPO)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Chrome](https://img.shields.io/badge/Platform-Chrome%20MV3-blue.svg)](https://chrome.google.com/webstore)

**Bye** is a next-generation transport-layer traffic obfuscator designed to defeat Deep Packet Inspection (DPI) and protocol fingerprinting. It implements a multi-layer pipeline that transforms network streams into stochastic noise, making them indistinguishable from random data or standard encrypted traffic.

## 🚀 Key Features

- **Stochastic SNI Fragmentation**: Breaks TLS ClientHello packets into variable-sized fragments to evade SNI-based filtering.
- **Polymorphic Markov Engine**: A Go-powered Wasm engine that uses Markov Chains to determine optimal evasion strategies (Split, Disorder, Chaff) in real-time.
- **Mesh Intelligence**: Decentralized P2P coordination (via WebRTC) between extension instances to share real-time DPI detection telemetry.
- **Fail-Open Architecture**: Uses a transparent PAC script strategy to ensure zero connectivity disruption, falling back to direct connection if the obfuscation layer is unreachable.
- **Censorship Probes**: Active canary monitoring to detect and adapt to regional network interference automatically.

## 🛠 Architecture

Bye operates on three distinct layers:

1.  **Layer 1 (TypeScript / Service Worker)**: Orchestrates the browser's network stack, manages proxy configurations, and coordinates the P2P mesh.
2.  **Layer 2 (Go / WebAssembly)**: A high-performance binary engine that performs low-level packet analysis and mathematical obfuscation.
3.  **Layer 3 (WebRTC / Mesh)**: An ephemeral, decentralized signaling layer for cross-instance coordination without central servers.

## 🔮 Future Vision: OS Integration

While currently implemented as a Chrome Extension, the Bye PPO engine is designed to be protocol-agnostic. The roadmap includes:

- **ByeOS Daemon**: A system-level background process (written in Rust/Go) to provide PPO protection for all OS-level traffic (VPN-like behavior).
- **ByeVPN Gateway**: Integration with decentralized relay networks (like VPN Gate) to provide stealthy exit points for obfuscated traffic.
- **Hardware Acceleration**: Offloading packet fragmentation and noise generation to specialized hardware for ultra-low latency.

## 📦 Build & Installation

### Requirements
- Go 1.21+
- Node.js 18+
- Chrome 110+

### Setup
```bash
# Install dependencies
npm install

# Build the Wasm engine
npm run build:wasm

# Build the Extension
npm run build
```

### Loading the Extension
1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `dist/` directory.

## 📜 Project Documentation
Visit our [Landing Page & Documentation](https://bye.endev.us/) for detailed architecture diagrams, privacy policy, and terms of service.

---
*Built with ❤️ for a free and open internet.*
