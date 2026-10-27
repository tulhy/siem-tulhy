"""Offline state remains derived from heartbeats; no lost-telemetry alerts."""

def check_telemetry(sessions, settings, now=None):
    """Administrator disabled TELEMETRY_LOST creation; leave history untouched."""
    return 0
