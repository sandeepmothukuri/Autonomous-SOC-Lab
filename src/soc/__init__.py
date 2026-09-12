"""Autonomous-SOC-Lab package.

A research and engineering platform for AI-assisted Security Operations.

Layers (see docs/architecture.md for full details):

    Telemetry
      -> Detection (deterministic; authoritative)
      -> Enrichment
      -> AI analysis (assistive; NOT authoritative)
      -> Confidence score
      -> Policy engine (deterministic)
      -> Human approval / Autonomous action
      -> Response (simulated or real)
      -> Verification
      -> Audit
"""
__version__ = "0.1.0"
__author__ = "Sandeep Mothukuri"
