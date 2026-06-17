# agentproof-scan

Pre-deployment security scanner for self-hosted AI agents.

## What it does
- Probes an AI agent to detect system-prompt / secret leakage
- Two-stage detection: leak (secret exposed) + prompt_disclosure (prompt content exposed)
- --handoff generates a masked report you can paste into an AI to get a fix

## Note
victim_agent.py and *_canary.py adapters contain intentional vulnerabilities for testing the scanner. They are not exploits.

## Status
Early WIP. Validation in progress.
