"""The model surface cannot ingest, clear, register, or self-label telemetry."""

import unittest

from pydantic import ValidationError

from demos.finance_agent import build_finance_demo


class TelemetryAgentBoundaryTests(unittest.TestCase):
    def test_finance_agent_exposes_no_telemetry_authority(self):
        demo = build_finance_demo(scenario="none", clock=lambda: 1000,
                                  review=lambda details: True, log=lambda message: None)
        self.assertEqual({tool.name for tool in demo.tools}, {"read_document", "generate_report", "send_email"})
        with self.assertRaises(PermissionError):
            demo.dsi_service.ingest_signals(network_anomaly=100)
        with self.assertRaises(PermissionError):
            demo.dsi_service.set_emergency(True)
        read = next(tool for tool in demo.tools if tool.name == "read_document")
        for key in ("telemetry", "source_id", "event_type", "severity", "proof", "received_at"):
            with self.subTest(key=key), self.assertRaises(ValidationError):
                read.invoke({"path": "/finance/monthly.csv", key: "forged"})
        self.assertEqual(demo.dsi_service.status()["score"], 0)
        self.assertEqual(demo.dsi_service.audit, ())
        self.assertFalse(demo.setup.effects)
