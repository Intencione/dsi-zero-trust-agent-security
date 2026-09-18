"""Compatibility entry point: incident after the first authorized document read.

Uses the shared LangGraph/runtime path; telemetry is scheduled by the demo host.
"""

from demos.finance_agent import main


if __name__ == "__main__":
    main(default_scenario="after-read")
