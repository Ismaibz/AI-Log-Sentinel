# AI-Log-Sentinel: Autonomous Log Threat Hunter

## Project Overview
AI-Sentinel is an experimental security agent designed for **Information Security Architects**. It bridges the gap between traditional log management and AI-driven threat hunting. The system monitors web server logs in real-time, uses **Gemini 1.5 Flash/Pro** to identify complex attack patterns, and suggests (or executes) mitigation strategies.

## Architecture
The system is designed with a **three-tier security-first approach**:
1.  **Ingestion Layer:** Local Python service monitoring log files (Nginx/Apache/Syslog).
2.  **Anonymization & Filter Engine:** Pre-processing to remove PII (IPs, Emails) and filter noise before sending data to the Cloud API (Cost & Privacy optimization).
3.  **Reasoning Engine (The Brain):** Uses Gemini 1.5 to perform behavioral analysis, going beyond simple Regex to detect multi-stage attacks.

## Core Features
- **Contextual Threat Analysis:** Identifies intent behind 403/404/500 spikes (e.g., distinguishing a broken link from a directory traversal attempt).
- **Proactive Mitigation:** Generates UFW/Iptables rules or Nginx deny directives automatically.
- **Security-First Design:** Anonymizes data before processing and includes a 'Human-in-the-loop' mode for critical actions.
- **Hybrid LLM Usage:** Uses Gemini 1.5 Flash for high-speed analysis and escalates complex cases to Gemini 1.5 Pro.

## Tech Stack
- **Language:** Python 3.10+
- **LLM API:** Google Gemini (Generative AI SDK)
- **Deployment:** VPS (Ubuntu/Linux)
- **Monitoring:** Tail-based log tracking

## Roadmap
- [ ] Phase 1: Implementation of the Anonymization layer.
- [ ] Phase 2: Real-time log ingestion and basic Gemini categorization.
- [ ] Phase 3: Integration with Telegram/Slack for real-time alerting.
- [ ] Phase 4: LangGraph implementation for autonomous incident response.

---
*Developed by a Security Architect for the next generation of AI-integrated security.*
