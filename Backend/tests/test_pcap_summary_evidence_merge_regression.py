import sys
import unittest
from pathlib import Path

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as backend_app


class PcapSummaryEvidenceMergeRegressionTests(unittest.TestCase):
    def test_http_summary_merge_aggregates_across_client_source_ports(self):
        base = pd.DataFrame(
            [
                {
                    "src_ip": "172.16.0.1",
                    "dst_ip": "192.168.10.50",
                    "src_port": 39780,
                    "dst_port": 80,
                    "ip_prot": 6,
                    "time_bucket": 100,
                    "service": "http",
                },
                {
                    "src_ip": "172.16.0.1",
                    "dst_ip": "192.168.10.50",
                    "src_port": 39782,
                    "dst_port": 80,
                    "ip_prot": 6,
                    "time_bucket": 100,
                    "service": "http",
                },
                {
                    "src_ip": "172.16.0.1",
                    "dst_ip": "192.168.10.50",
                    "src_port": 39784,
                    "dst_port": 443,
                    "ip_prot": 6,
                    "time_bucket": 100,
                    "service": "ssl",
                },
            ]
        )

        http_log = pd.DataFrame(
            [
                {
                    "ts": 6000.1,
                    "id.orig_h": "172.16.0.1",
                    "id.orig_p": 39780,
                    "id.resp_h": "192.168.10.50",
                    "id.resp_p": 80,
                    "host": "victim.local",
                    "uri": "/dv/login.php",
                    "status_code": 200,
                },
                {
                    "ts": 6001.1,
                    "id.orig_h": "172.16.0.1",
                    "id.orig_p": 39780,
                    "id.resp_h": "192.168.10.50",
                    "id.resp_p": 80,
                    "host": "victim.local",
                    "uri": "/dv/login.php",
                    "status_code": 200,
                },
                {
                    "ts": 6002.1,
                    "id.orig_h": "172.16.0.1",
                    "id.orig_p": 39782,
                    "id.resp_h": "192.168.10.50",
                    "id.resp_p": 80,
                    "host": "victim.local",
                    "uri": "/dv/login.php",
                    "status_code": 200,
                },
                {
                    "ts": 6003.1,
                    "id.orig_h": "172.16.0.1",
                    "id.orig_p": 39782,
                    "id.resp_h": "192.168.10.50",
                    "id.resp_p": 80,
                    "host": "victim.local",
                    "uri": "/dv/login.php",
                    "status_code": 404,
                },
            ]
        )

        http_summary = backend_app.summarize_http_evidence(http_log)
        merged = backend_app.merge_summary_evidence(base, http_summary)

        port_80_rows = merged[merged["dst_port"] == 80]
        port_443_rows = merged[merged["dst_port"] == 443]

        self.assertEqual(len(port_80_rows), 2)
        self.assertTrue(port_80_rows["has_http_evidence"].all())
        self.assertTrue((port_80_rows["http_request_count"] == 4).all())
        self.assertTrue((port_80_rows["http_status_4xx_5xx_count"] == 1).all())
        self.assertTrue((port_80_rows["http_top_host"] == "victim.local").all())
        self.assertTrue((port_80_rows["http_top_uri"] == "/dv/login.php").all())
        self.assertTrue((port_443_rows["http_request_count"].fillna(0) == 0).all())


if __name__ == "__main__":
    unittest.main()
