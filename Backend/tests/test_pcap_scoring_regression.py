import sys
import unittest
from pathlib import Path

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from pcap_engine.scorer import fuse_scores


def _score_single_row(row: dict) -> pd.Series:
    result = fuse_scores(pd.DataFrame([row]))
    return result.iloc[0]


class PcapScoringRegressionTests(unittest.TestCase):
    def test_benign_dns_ddos_false_positive_is_demoted_to_normal(self):
        row = {
            "src_ip": "192.168.10.9",
            "dst_ip": "192.168.10.3",
            "src_port": 55123,
            "dst_port": 53,
            "ml_label": "ddos",
            "ml_confidence": 0.96,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "dns",
            "dns_query_count": 1,
            "dns_unique_queries": 1,
            "dns_top_query": "time.windows.com",
            "src_conn_count": 30,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 24,
            "src_dst_conn_share": 0.80,
            "src_dst_port_conn_count": 24,
            "src_dst_port_conn_share": 0.80,
            "src_short_ratio": 0.30,
            "src_failed_ratio": 0.0,
            "src_dst_failed_ratio": 0.0,
            "src_dst_port_failed_ratio": 0.0,
            "flow_pkts_per_sec": 18827.30,
            "bytes_per_s": 280000.0,
            "flow_SYN_flag_count": 0,
            "flow_ACK_flag_count": 18,
            "duration": 0.4,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertEqual(float(scored["final_score"]), 0.0)

    def test_benign_web_ddos_false_positive_is_demoted_to_normal(self):
        row = {
            "src_ip": "203.0.113.8",
            "dst_ip": "10.0.0.10",
            "src_port": 49000,
            "dst_port": 80,
            "ml_label": "ddos",
            "ml_confidence": 1.00,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "http",
            "http_request_count": 1,
            "http_status_4xx_5xx_count": 0,
            "src_conn_count": 52,
            "src_unique_ports": 2,
            "src_unique_targets": 1,
            "src_dst_conn_count": 46,
            "src_dst_conn_share": 0.88,
            "src_dst_port_conn_count": 46,
            "src_dst_port_conn_share": 0.88,
            "src_short_ratio": 0.22,
            "src_failed_ratio": 0.02,
            "src_dst_failed_ratio": 0.02,
            "src_dst_port_failed_ratio": 0.02,
            "flow_pkts_per_sec": 79.13,
            "bytes_per_s": 92000.0,
            "flow_SYN_flag_count": 1,
            "flow_ACK_flag_count": 12,
            "duration": 3.0,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertEqual(float(scored["final_score"]), 0.0)

    def test_aggregated_benign_http_browsing_ddos_false_positive_is_demoted(self):
        row = {
            "src_ip": "192.168.10.17",
            "dst_ip": "23.50.69.138",
            "src_port": 47758,
            "dst_port": 80,
            "ml_label": "ddos",
            "ml_confidence": 1.00,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "http",
            "http_request_count": 44,
            "http_status_4xx_5xx_count": 0,
            "http_top_host": "www.kakaocorp.com",
            "http_top_uri": "/",
            "src_conn_count": 1142,
            "src_unique_ports": 29,
            "src_unique_targets": 33,
            "src_dst_conn_count": 46,
            "src_dst_conn_share": 0.040280210157618214,
            "src_dst_port_conn_count": 46,
            "src_dst_port_conn_share": 0.040280210157618214,
            "src_short_ratio": 0.17,
            "src_failed_ratio": 0.02,
            "src_dst_failed_ratio": 0.02,
            "src_dst_port_failed_ratio": 0.02,
            "flow_pkts_per_sec": 48.0,
            "bytes_per_s": 15201.5,
            "flow_SYN_flag_count": 2,
            "flow_ACK_flag_count": 43,
            "conn_state": "SF",
            "duration": 4.0,
            "orig_bytes": 76660.0,
            "resp_bytes": 58585086.0,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertEqual(scored["support_level"], "none")
        self.assertEqual(float(scored["final_score"]), 0.0)

    def test_generic_http_ddos_with_flood_signals_is_not_caught_by_browsing_guard(self):
        row = {
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "src_port": 49100,
            "dst_port": 80,
            "ml_label": "ddos",
            "ml_confidence": 0.98,
            "heuristic_score": 0.30,
            "heuristic_type": "FocusedBurst",
            "service": "http",
            "http_request_count": 30,
            "http_status_4xx_5xx_count": 6,
            "http_top_host": "victim.local",
            "http_top_uri": "/login",
            "src_conn_count": 130,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 120,
            "src_dst_conn_share": 0.92,
            "src_dst_port_conn_count": 120,
            "src_dst_port_conn_share": 0.92,
            "src_short_ratio": 0.55,
            "src_failed_ratio": 0.80,
            "src_dst_failed_ratio": 0.80,
            "src_dst_port_failed_ratio": 0.80,
            "flow_pkts_per_sec": 180.0,
            "bytes_per_s": 420000.0,
            "flow_SYN_flag_count": 12,
            "flow_ACK_flag_count": 4,
            "duration": 1.8,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["verdict"], {"Medium", "High", "Critical"})

    def test_internal_kerberos_ddos_chatter_is_demoted_to_normal(self):
        row = {
            "src_ip": "172.16.0.1",
            "dst_ip": "172.16.0.2",
            "src_port": 44000,
            "dst_port": 88,
            "ml_label": "ddos",
            "ml_confidence": 0.99,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "krb_tcp",
            "src_conn_count": 15,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 11,
            "src_dst_conn_share": 0.73,
            "src_dst_port_conn_count": 11,
            "src_dst_port_conn_share": 0.73,
            "src_short_ratio": 0.10,
            "src_failed_ratio": 0.0,
            "src_dst_failed_ratio": 0.0,
            "src_dst_port_failed_ratio": 0.0,
            "flow_pkts_per_sec": 16334.37,
            "bytes_per_s": 14000.0,
            "bytes_total": 4096.0,
            "flow_SYN_flag_count": 0,
            "flow_ACK_flag_count": 12,
            "duration": 0.01,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertIn("auth chatter", str(scored["validation_reason"]).lower())

    def test_strong_concentrated_syn_heavy_ddos_surfaces_without_http_context(self):
        row = {
            "src_ip": "198.51.100.50",
            "dst_ip": "10.0.0.50",
            "src_port": 53000,
            "dst_port": 443,
            "ml_label": "ddos",
            "ml_confidence": 0.98,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "ssl",
            "src_conn_count": 1800,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 1515,
            "src_dst_conn_share": 0.97,
            "src_dst_port_conn_count": 1515,
            "src_dst_port_conn_share": 0.97,
            "src_short_ratio": 0.92,
            "src_failed_ratio": 1.0,
            "src_dst_failed_ratio": 1.0,
            "src_dst_port_failed_ratio": 1.0,
            "flow_pkts_per_sec": 950.0,
            "bytes_per_s": 600000.0,
            "flow_SYN_flag_count": 26,
            "flow_ACK_flag_count": 3,
            "duration": 1.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["verdict"], {"High", "Critical"})

    def test_strong_http_backed_dos_hulk_still_surfaces(self):
        row = {
            "src_ip": "198.51.100.20",
            "dst_ip": "10.0.0.20",
            "src_port": 40000,
            "dst_port": 80,
            "ml_label": "dos_hulk",
            "ml_confidence": 0.98,
            "heuristic_score": 0.35,
            "heuristic_type": "FocusedBurst",
            "service": "http",
            "http_request_count": 40,
            "http_status_4xx_5xx_count": 8,
            "http_top_host": "victim.local",
            "http_top_uri": "/login",
            "src_conn_count": 180,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 160,
            "src_dst_conn_share": 0.89,
            "src_dst_port_conn_count": 150,
            "src_dst_port_conn_share": 0.83,
            "src_short_ratio": 0.25,
            "src_failed_ratio": 0.05,
            "src_dst_failed_ratio": 0.05,
            "src_dst_port_failed_ratio": 0.05,
            "flow_pkts_per_sec": 140.0,
            "bytes_per_s": 350000.0,
            "flow_SYN_flag_count": 4,
            "flow_ACK_flag_count": 25,
            "duration": 18.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["verdict"], {"Medium", "High", "Critical"})

    def test_long_lived_http_dos_slowloris_still_surfaces(self):
        row = {
            "src_ip": "198.51.100.22",
            "dst_ip": "10.0.0.22",
            "src_port": 40020,
            "dst_port": 80,
            "ml_label": "dos_slowloris",
            "ml_confidence": 0.97,
            "heuristic_score": 0.15,
            "heuristic_type": "ConnectionPressure",
            "service": "http",
            "http_request_count": 5,
            "http_status_4xx_5xx_count": 1,
            "http_top_host": "victim.local",
            "http_top_uri": "/hold",
            "src_conn_count": 28,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 22,
            "src_dst_conn_share": 0.79,
            "src_dst_port_conn_count": 22,
            "src_dst_port_conn_share": 0.79,
            "src_short_ratio": 0.08,
            "src_failed_ratio": 0.05,
            "src_dst_failed_ratio": 0.05,
            "src_dst_port_failed_ratio": 0.05,
            "flow_pkts_per_sec": 6.0,
            "bytes_per_s": 18000.0,
            "flow_SYN_flag_count": 2,
            "flow_ACK_flag_count": 16,
            "duration": 24.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["verdict"], {"Medium", "High", "Critical"})

    def test_slowhttptest_with_prolonged_http_pressure_still_surfaces(self):
        row = {
            "src_ip": "198.51.100.23",
            "dst_ip": "10.0.0.23",
            "src_port": 40030,
            "dst_port": 80,
            "ml_label": "dos_slowhttptest",
            "ml_confidence": 0.96,
            "heuristic_score": 0.10,
            "heuristic_type": "HttpPressure",
            "service": "http",
            "http_request_count": 8,
            "http_status_4xx_5xx_count": 1,
            "http_top_host": "victim.local",
            "http_top_uri": "/slow",
            "src_conn_count": 18,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 14,
            "src_dst_conn_share": 0.78,
            "src_dst_port_conn_count": 14,
            "src_dst_port_conn_share": 0.78,
            "src_short_ratio": 0.12,
            "src_failed_ratio": 0.06,
            "src_dst_failed_ratio": 0.06,
            "src_dst_port_failed_ratio": 0.06,
            "flow_pkts_per_sec": 5.0,
            "bytes_per_s": 14000.0,
            "flow_SYN_flag_count": 2,
            "flow_ACK_flag_count": 12,
            "duration": 18.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["verdict"], {"Medium", "High", "Critical"})

    def test_ddos_slowloris_with_sustained_http_pressure_still_surfaces(self):
        row = {
            "src_ip": "198.51.100.24",
            "dst_ip": "10.0.0.24",
            "src_port": 40040,
            "dst_port": 80,
            "ml_label": "ddos_slowloris",
            "ml_confidence": 0.97,
            "heuristic_score": 0.20,
            "heuristic_type": "ConnectionPressure",
            "service": "http",
            "http_request_count": 7,
            "http_status_4xx_5xx_count": 1,
            "http_top_host": "victim.local",
            "http_top_uri": "/keepalive",
            "src_conn_count": 42,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 30,
            "src_dst_conn_share": 0.71,
            "src_dst_port_conn_count": 30,
            "src_dst_port_conn_share": 0.71,
            "src_short_ratio": 0.06,
            "src_failed_ratio": 0.04,
            "src_dst_failed_ratio": 0.04,
            "src_dst_port_failed_ratio": 0.04,
            "flow_pkts_per_sec": 7.0,
            "bytes_per_s": 16000.0,
            "flow_SYN_flag_count": 3,
            "flow_ACK_flag_count": 18,
            "duration": 26.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["verdict"], {"High", "Critical"})

    def test_http_subtype_shadows_generic_ddos_on_same_target_window(self):
        subtype_row = {
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "src_port": 40100,
            "dst_port": 80,
            "time_bucket": 100,
            "ml_label": "dos_slowhttptest",
            "ml_confidence": 0.96,
            "heuristic_score": 0.10,
            "heuristic_type": "HttpPressure",
            "service": "http",
            "http_request_count": 8,
            "http_status_4xx_5xx_count": 1,
            "http_top_host": "victim.local",
            "http_top_uri": "/slow",
            "src_conn_count": 18,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 14,
            "src_dst_conn_share": 0.78,
            "src_dst_port_conn_count": 14,
            "src_dst_port_conn_share": 0.78,
            "src_short_ratio": 0.12,
            "src_failed_ratio": 0.06,
            "src_dst_failed_ratio": 0.06,
            "src_dst_port_failed_ratio": 0.06,
            "flow_pkts_per_sec": 5.0,
            "bytes_per_s": 14000.0,
            "flow_SYN_flag_count": 2,
            "flow_ACK_flag_count": 12,
            "duration": 18.0,
        }
        generic_row = dict(subtype_row)
        generic_row["ml_label"] = "ddos"
        generic_row["ml_confidence"] = 0.98

        scored = fuse_scores(pd.DataFrame([subtype_row, generic_row]))
        subtype = scored[scored["ml_label"].astype(str) == "dos_slowhttptest"].iloc[0]
        generic = scored[scored["ml_label"].astype(str) == "ddos"].iloc[0]

        self.assertIn(subtype["verdict"], {"Medium", "High", "Critical"})
        self.assertEqual(generic["verdict"], "Normal")
        self.assertTrue(bool(generic["suppressed"]))

    def test_diluted_internal_http_hulk_victim_path_is_recovered(self):
        row = {
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "src_port": 40000,
            "dst_port": 80,
            "ml_label": "dos_hulk",
            "ml_confidence": 0.96,
            "heuristic_score": 0.25,
            "heuristic_type": "FocusedBurst",
            "service": "http",
            "http_request_count": 18,
            "http_status_4xx_5xx_count": 3,
            "http_top_host": "victim.local",
            "http_top_uri": "/login",
            "src_conn_count": 70,
            "src_unique_ports": 1,
            "src_unique_targets": 2,
            "src_dst_conn_count": 12,
            "src_dst_conn_share": 0.17,
            "src_dst_port_conn_count": 12,
            "src_dst_port_conn_share": 0.17,
            "src_short_ratio": 0.18,
            "src_failed_ratio": 0.06,
            "src_dst_failed_ratio": 0.06,
            "src_dst_port_failed_ratio": 0.06,
            "flow_pkts_per_sec": 55.0,
            "bytes_per_s": 210000.0,
            "flow_SYN_flag_count": 3,
            "flow_ACK_flag_count": 23,
            "duration": 14.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["suppressed"]))
        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["support_level"], {"moderate", "strong"})
        self.assertIn(scored["verdict"], {"Medium", "High", "Critical"})

    def test_diluted_internal_http_slowloris_victim_path_is_recovered(self):
        row = {
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "src_port": 40020,
            "dst_port": 80,
            "ml_label": "dos_slowloris",
            "ml_confidence": 0.95,
            "heuristic_score": 0.12,
            "heuristic_type": "ConnectionPressure",
            "service": "http",
            "http_request_count": 4,
            "http_status_4xx_5xx_count": 0,
            "http_top_host": "victim.local",
            "http_top_uri": "/hold",
            "src_conn_count": 44,
            "src_unique_ports": 1,
            "src_unique_targets": 2,
            "src_dst_conn_count": 9,
            "src_dst_conn_share": 0.20,
            "src_dst_port_conn_count": 9,
            "src_dst_port_conn_share": 0.20,
            "src_short_ratio": 0.05,
            "src_failed_ratio": 0.03,
            "src_dst_failed_ratio": 0.03,
            "src_dst_port_failed_ratio": 0.03,
            "flow_pkts_per_sec": 4.5,
            "bytes_per_s": 15000.0,
            "flow_SYN_flag_count": 2,
            "flow_ACK_flag_count": 16,
            "duration": 26.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["suppressed"]))
        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["support_level"], {"moderate", "strong"})
        self.assertIn(scored["verdict"], {"Medium", "High", "Critical"})

    def test_external_browsing_like_hulk_shape_stays_suppressed(self):
        row = {
            "src_ip": "192.168.10.17",
            "dst_ip": "23.50.69.138",
            "src_port": 46000,
            "dst_port": 80,
            "ml_label": "dos_hulk",
            "ml_confidence": 0.97,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "http",
            "http_request_count": 18,
            "http_status_4xx_5xx_count": 0,
            "http_top_host": "www.kakaocorp.com",
            "http_top_uri": "/",
            "src_conn_count": 72,
            "src_unique_ports": 2,
            "src_unique_targets": 6,
            "src_dst_conn_count": 12,
            "src_dst_conn_share": 0.17,
            "src_dst_port_conn_count": 12,
            "src_dst_port_conn_share": 0.17,
            "src_short_ratio": 0.12,
            "src_failed_ratio": 0.02,
            "src_dst_failed_ratio": 0.02,
            "src_dst_port_failed_ratio": 0.02,
            "flow_pkts_per_sec": 48.0,
            "bytes_per_s": 180000.0,
            "flow_SYN_flag_count": 1,
            "flow_ACK_flag_count": 14,
            "conn_state": "SF",
            "duration": 4.0,
            "orig_bytes": 3200.0,
            "resp_bytes": 28000.0,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertIn("focused target concentration", str(scored["validation_reason"]))

    def test_broad_portscan_still_surfaces(self):
        row = {
            "src_ip": "198.51.100.20",
            "dst_ip": "10.0.0.10",
            "src_port": 42000,
            "dst_port": 445,
            "ml_label": "portscan",
            "ml_confidence": 0.91,
            "heuristic_score": 0.2,
            "heuristic_type": "PortFanout",
            "service": "unknown",
            "proto": "tcp",
            "src_conn_count": 120,
            "src_unique_ports": 30,
            "src_unique_targets": 12,
            "src_short_ratio": 0.82,
            "src_failed_ratio": 0.46,
            "src_dst_conn_count": 10,
            "src_dst_conn_share": 0.08,
            "src_dst_port_conn_count": 1,
            "src_dst_port_conn_share": 0.01,
            "flow_SYN_flag_count": 6,
            "flow_RST_flag_count": 14,
            "flow_ACK_flag_count": 2,
            "duration": 0.3,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["support_level"], "strong")
        self.assertEqual(scored["verdict"], "Medium")

    def test_nmap_fin_single_target_port_fanout_surfaces(self):
        row = {
            "src_ip": "198.51.100.30",
            "dst_ip": "10.0.0.20",
            "src_port": 41001,
            "dst_port": 22,
            "ml_label": "NMAP_FIN_SCAN",
            "ml_confidence": 0.92,
            "heuristic_score": 0.1,
            "heuristic_type": "PortFanout",
            "service": "unknown",
            "proto": "tcp",
            "src_conn_count": 14,
            "src_unique_ports": 14,
            "src_unique_targets": 1,
            "src_short_ratio": 0.42,
            "src_failed_ratio": 0.36,
            "src_dst_conn_count": 14,
            "src_dst_conn_share": 1.0,
            "src_dst_port_conn_count": 1,
            "src_dst_port_conn_share": 0.07,
            "flow_SYN_flag_count": 0,
            "flow_FIN_flag_count": 1,
            "flow_RST_flag_count": 1,
            "flow_ACK_flag_count": 1,
            "duration": 0.01,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["confidence_tier"], "suspicious")
        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["support_level"], "strong")
        self.assertEqual(scored["verdict"], "Medium")

    def test_nmap_os_detection_single_target_port_fanout_surfaces(self):
        row = {
            "src_ip": "198.51.100.31",
            "dst_ip": "10.0.0.21",
            "src_port": 41002,
            "dst_port": 135,
            "ml_label": "NMAP_OS_DETECTION",
            "ml_confidence": 0.93,
            "heuristic_score": 0.08,
            "heuristic_type": "PortFanout",
            "service": "unknown",
            "proto": "tcp",
            "src_conn_count": 16,
            "src_unique_ports": 16,
            "src_unique_targets": 1,
            "src_short_ratio": 0.18,
            "src_failed_ratio": 0.62,
            "src_dst_conn_count": 16,
            "src_dst_conn_share": 1.0,
            "src_dst_port_conn_count": 1,
            "src_dst_port_conn_share": 0.06,
            "flow_SYN_flag_count": 0,
            "flow_FIN_flag_count": 0,
            "flow_RST_flag_count": 1,
            "flow_ACK_flag_count": 1,
            "duration": 0.00001,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["support_level"], {"moderate", "strong"})
        self.assertEqual(scored["verdict"], "Medium")

    def test_nmap_tcp_scan_single_target_port_fanout_surfaces(self):
        row = {
            "src_ip": "198.51.100.32",
            "dst_ip": "10.0.0.22",
            "src_port": 41003,
            "dst_port": 3389,
            "ml_label": "NMAP_TCP_scan",
            "ml_confidence": 0.90,
            "heuristic_score": 0.1,
            "heuristic_type": "PortFanout",
            "service": "unknown",
            "proto": "tcp",
            "src_conn_count": 16,
            "src_unique_ports": 16,
            "src_unique_targets": 1,
            "src_short_ratio": 0.56,
            "src_failed_ratio": 0.50,
            "src_dst_conn_count": 16,
            "src_dst_conn_share": 1.0,
            "src_dst_port_conn_count": 1,
            "src_dst_port_conn_share": 0.06,
            "flow_SYN_flag_count": 1,
            "flow_FIN_flag_count": 0,
            "flow_RST_flag_count": 1,
            "flow_ACK_flag_count": 1,
            "duration": 0.00001,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["support_level"], {"moderate", "strong"})
        self.assertEqual(scored["verdict"], "Medium")

    def test_nmap_udp_scan_single_target_port_fanout_surfaces(self):
        row = {
            "src_ip": "198.51.100.33",
            "dst_ip": "10.0.0.23",
            "src_port": 41004,
            "dst_port": 161,
            "ml_label": "NMAP_UDP_SCAN",
            "ml_confidence": 0.91,
            "heuristic_score": 0.05,
            "heuristic_type": "PortFanout",
            "service": "unknown",
            "proto": "udp",
            "src_conn_count": 20,
            "src_unique_ports": 20,
            "src_unique_targets": 1,
            "src_short_ratio": 0.10,
            "src_failed_ratio": 0.0,
            "src_dst_conn_count": 20,
            "src_dst_conn_share": 1.0,
            "src_dst_port_conn_count": 1,
            "src_dst_port_conn_share": 0.05,
            "flow_SYN_flag_count": 0,
            "flow_FIN_flag_count": 0,
            "flow_RST_flag_count": 0,
            "flow_ACK_flag_count": 0,
            "duration": 0.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["support_level"], {"moderate", "strong"})
        self.assertEqual(scored["verdict"], "Medium")

    def test_nmap_xmas_scan_single_target_port_fanout_surfaces(self):
        row = {
            "src_ip": "198.51.100.34",
            "dst_ip": "10.0.0.24",
            "src_port": 41005,
            "dst_port": 80,
            "ml_label": "NMAP_XMAS_TREE_SCAN",
            "ml_confidence": 0.90,
            "heuristic_score": 0.1,
            "heuristic_type": "PortFanout",
            "service": "unknown",
            "proto": "tcp",
            "src_conn_count": 14,
            "src_unique_ports": 14,
            "src_unique_targets": 1,
            "src_short_ratio": 0.40,
            "src_failed_ratio": 0.34,
            "src_dst_conn_count": 14,
            "src_dst_conn_share": 1.0,
            "src_dst_port_conn_count": 1,
            "src_dst_port_conn_share": 0.07,
            "flow_SYN_flag_count": 0,
            "flow_FIN_flag_count": 1,
            "flow_RST_flag_count": 1,
            "flow_ACK_flag_count": 1,
            "duration": 0.00001,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["support_level"], {"moderate", "strong"})
        self.assertEqual(scored["verdict"], "Medium")

    def test_rpc_like_nmap_tcp_chatter_stays_suppressed(self):
        row = {
            "src_ip": "192.168.10.5",
            "dst_ip": "192.168.10.3",
            "src_port": 42100,
            "dst_port": 49671,
            "ml_label": "NMAP_TCP_scan",
            "ml_confidence": 0.93,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "dce_rpc",
            "proto": "tcp",
            "src_conn_count": 90,
            "src_unique_ports": 15,
            "src_unique_targets": 19,
            "src_short_ratio": 0.50,
            "src_failed_ratio": 0.40,
            "src_dst_conn_count": 71,
            "src_dst_conn_share": 0.79,
            "src_dst_port_conn_count": 1,
            "src_dst_port_conn_share": 0.01,
            "flow_SYN_flag_count": 0,
            "flow_RST_flag_count": 0,
            "flow_ACK_flag_count": 4,
            "conn_state": "SF",
            "duration": 0.2,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertIn("RPC-like chatter", str(scored["validation_reason"]))

    def test_ftp_patator_with_repeated_failed_attempts_still_surfaces(self):
        row = {
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "src_port": 57726,
            "dst_port": 21,
            "ml_label": "ftp_patator",
            "ml_confidence": 0.96,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "ftp",
            "src_conn_count": 12,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 9,
            "src_dst_conn_share": 0.75,
            "src_dst_port_conn_count": 9,
            "src_dst_port_conn_share": 0.75,
            "src_short_ratio": 0.68,
            "src_failed_ratio": 0.88,
            "src_dst_failed_ratio": 0.88,
            "src_dst_port_failed_ratio": 0.88,
            "flow_SYN_flag_count": 2,
            "flow_ACK_flag_count": 1,
            "flow_RST_flag_count": 6,
            "duration": 0.4,
            "flow_pkts_per_sec": 30.0,
            "bytes_per_s": 32.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertIn(scored["support_level"], {"moderate", "strong"})
        self.assertIn(scored["verdict"], {"Medium", "High"})

    def test_ssh_patator_with_repeated_reset_heavy_attempts_surfaces(self):
        row = {
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "src_port": 48702,
            "dst_port": 22,
            "ml_label": "ssh_patator",
            "ml_confidence": 0.95,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "ssh",
            "src_conn_count": 20,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 19,
            "src_dst_conn_share": 0.95,
            "src_dst_port_conn_count": 19,
            "src_dst_port_conn_share": 0.95,
            "src_short_ratio": 0.82,
            "src_failed_ratio": 0.18,
            "src_dst_failed_ratio": 0.18,
            "src_dst_port_failed_ratio": 0.18,
            "flow_SYN_flag_count": 2,
            "flow_ACK_flag_count": 31,
            "flow_RST_flag_count": 16,
            "duration": 0.7,
            "flow_pkts_per_sec": 24.0,
            "bytes_per_s": 415.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["confidence_tier"], "confirmed")
        self.assertIn(scored["support_level"], {"moderate", "strong"})
        self.assertIn(scored["verdict"], {"Medium", "High"})
        self.assertGreater(float(scored["final_score"]), 0.0)

    def test_metasploit_ssh_bruteforce_with_repeated_reset_heavy_attempts_surfaces(self):
        row = {
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "src_port": 48000,
            "dst_port": 22,
            "ml_label": "Metasploit_Brute_Force_SSH",
            "ml_confidence": 0.83,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "ssh",
            "src_conn_count": 14,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 12,
            "src_dst_conn_share": 0.86,
            "src_dst_port_conn_count": 12,
            "src_dst_port_conn_share": 0.86,
            "src_short_ratio": 0.78,
            "src_failed_ratio": 0.17,
            "src_dst_failed_ratio": 0.17,
            "src_dst_port_failed_ratio": 0.17,
            "flow_SYN_flag_count": 2,
            "flow_ACK_flag_count": 18,
            "flow_RST_flag_count": 10,
            "duration": 0.8,
            "flow_pkts_per_sec": 20.0,
            "bytes_per_s": 380.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["confidence_tier"], "suspicious")
        self.assertEqual(scored["support_level"], "strong")
        self.assertEqual(scored["verdict"], "Medium")
        self.assertGreater(float(scored["final_score"]), 0.0)

    def test_single_failed_ssh_login_noise_stays_suppressed(self):
        row = {
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.10",
            "src_port": 51000,
            "dst_port": 22,
            "ml_label": "ssh_patator",
            "ml_confidence": 0.93,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "ssh",
            "src_conn_count": 2,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 1,
            "src_dst_conn_share": 0.50,
            "src_dst_port_conn_count": 1,
            "src_dst_port_conn_share": 0.50,
            "src_short_ratio": 0.50,
            "src_failed_ratio": 0.50,
            "src_dst_failed_ratio": 0.50,
            "src_dst_port_failed_ratio": 0.50,
            "flow_SYN_flag_count": 1,
            "flow_ACK_flag_count": 0,
            "flow_RST_flag_count": 1,
            "duration": 0.2,
            "flow_pkts_per_sec": 12.0,
            "bytes_per_s": 150.0,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertEqual(float(scored["final_score"]), 0.0)

    def test_repeated_successful_ssh_chatter_stays_suppressed(self):
        row = {
            "src_ip": "192.168.10.20",
            "dst_ip": "192.168.10.5",
            "src_port": 52100,
            "dst_port": 22,
            "ml_label": "ssh_patator",
            "ml_confidence": 0.94,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "ssh",
            "src_conn_count": 15,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 12,
            "src_dst_conn_share": 0.80,
            "src_dst_port_conn_count": 12,
            "src_dst_port_conn_share": 0.80,
            "src_short_ratio": 0.18,
            "src_failed_ratio": 0.0,
            "src_dst_failed_ratio": 0.0,
            "src_dst_port_failed_ratio": 0.0,
            "flow_SYN_flag_count": 2,
            "flow_ACK_flag_count": 20,
            "flow_RST_flag_count": 0,
            "conn_state": "SF",
            "duration": 3.0,
            "flow_pkts_per_sec": 18.0,
            "bytes_per_s": 6400.0,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["support_level"], "none")
        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertEqual(float(scored["final_score"]), 0.0)

    def test_webattack_bruteforce_login_path_with_repeated_target_activity_surfaces(self):
        row = {
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "src_port": 39780,
            "dst_port": 80,
            "ml_label": "webattack_bruteforce",
            "ml_confidence": 0.91,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "http",
            "http_request_count": 1,
            "http_status_4xx_5xx_count": 1,
            "http_top_host": "victim.local",
            "http_top_uri": "/dv/login.php",
            "src_conn_count": 8,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 6,
            "src_dst_conn_share": 0.75,
            "src_dst_port_conn_count": 6,
            "src_dst_port_conn_share": 0.75,
            "src_short_ratio": 0.40,
            "src_failed_ratio": 0.05,
            "src_dst_failed_ratio": 0.05,
            "src_dst_port_failed_ratio": 0.05,
            "flow_SYN_flag_count": 1,
            "flow_ACK_flag_count": 6,
            "duration": 2.5,
            "flow_pkts_per_sec": 18.0,
            "bytes_per_s": 2200.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["support_level"], "moderate")
        self.assertEqual(scored["verdict"], "Medium")
        self.assertGreater(float(scored["final_score"]), 0.0)

    def test_webattack_sql_injection_clear_payload_surfaces_from_suspicious_tier(self):
        row = {
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "src_port": 36198,
            "dst_port": 80,
            "ml_label": "webattack_sql_injection",
            "ml_confidence": 0.91,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "http",
            "http_request_count": 1,
            "http_status_4xx_5xx_count": 1,
            "http_top_host": "victim.local",
            "http_top_uri": "/dv/vulnerabilities/sqli/?id=1%27+or+1%3D1--&Submit=Submit",
            "src_conn_count": 3,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 2,
            "src_dst_conn_share": 0.67,
            "src_dst_port_conn_count": 2,
            "src_dst_port_conn_share": 0.67,
            "src_short_ratio": 0.30,
            "src_failed_ratio": 0.0,
            "src_dst_failed_ratio": 0.0,
            "src_dst_port_failed_ratio": 0.0,
            "flow_SYN_flag_count": 1,
            "flow_ACK_flag_count": 4,
            "duration": 3.0,
            "flow_pkts_per_sec": 8.0,
            "bytes_per_s": 3200.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["confidence_tier"], "suspicious")
        self.assertEqual(scored["support_level"], "strong")
        self.assertEqual(scored["verdict"], "Medium")
        self.assertGreater(float(scored["final_score"]), 0.0)

    def test_webattack_xss_clear_payload_surfaces(self):
        row = {
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "src_port": 35682,
            "dst_port": 80,
            "ml_label": "webattack_xss",
            "ml_confidence": 0.90,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "http",
            "http_request_count": 1,
            "http_status_4xx_5xx_count": 0,
            "http_top_host": "victim.local",
            "http_top_uri": "/dv/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "src_conn_count": 3,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 2,
            "src_dst_conn_share": 0.67,
            "src_dst_port_conn_count": 2,
            "src_dst_port_conn_share": 0.67,
            "src_short_ratio": 0.35,
            "src_failed_ratio": 0.0,
            "src_dst_failed_ratio": 0.0,
            "src_dst_port_failed_ratio": 0.0,
            "flow_SYN_flag_count": 1,
            "flow_ACK_flag_count": 3,
            "duration": 2.5,
            "flow_pkts_per_sec": 7.0,
            "bytes_per_s": 2800.0,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["support_level"], "moderate")
        self.assertEqual(scored["verdict"], "Medium")
        self.assertGreater(float(scored["final_score"]), 0.0)

    def test_normal_login_page_browsing_stays_suppressed_for_webattack_bruteforce(self):
        row = {
            "src_ip": "203.0.113.20",
            "dst_ip": "198.51.100.25",
            "src_port": 49800,
            "dst_port": 80,
            "ml_label": "webattack_bruteforce",
            "ml_confidence": 0.92,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "http",
            "http_request_count": 1,
            "http_status_4xx_5xx_count": 0,
            "http_top_host": "portal.example.com",
            "http_top_uri": "/login",
            "src_conn_count": 2,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 1,
            "src_dst_conn_share": 0.50,
            "src_dst_port_conn_count": 1,
            "src_dst_port_conn_share": 0.50,
            "src_short_ratio": 0.20,
            "src_failed_ratio": 0.0,
            "src_dst_failed_ratio": 0.0,
            "src_dst_port_failed_ratio": 0.0,
            "flow_SYN_flag_count": 1,
            "flow_ACK_flag_count": 2,
            "conn_state": "SF",
            "duration": 1.2,
            "flow_pkts_per_sec": 5.0,
            "bytes_per_s": 1800.0,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertEqual(float(scored["final_score"]), 0.0)

    def test_plain_query_stays_suppressed_for_webattack_sql_injection(self):
        row = {
            "src_ip": "203.0.113.30",
            "dst_ip": "198.51.100.35",
            "src_port": 49820,
            "dst_port": 80,
            "ml_label": "webattack_sql_injection",
            "ml_confidence": 0.91,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "http",
            "http_request_count": 1,
            "http_status_4xx_5xx_count": 0,
            "http_top_host": "shop.example.com",
            "http_top_uri": "/products?id=10&view=full",
            "src_conn_count": 2,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 1,
            "src_dst_conn_share": 0.50,
            "src_dst_port_conn_count": 1,
            "src_dst_port_conn_share": 0.50,
            "src_short_ratio": 0.20,
            "src_failed_ratio": 0.0,
            "src_dst_failed_ratio": 0.0,
            "src_dst_port_failed_ratio": 0.0,
            "flow_SYN_flag_count": 1,
            "flow_ACK_flag_count": 2,
            "duration": 1.0,
            "flow_pkts_per_sec": 4.0,
            "bytes_per_s": 1700.0,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertEqual(float(scored["final_score"]), 0.0)

    def test_plain_form_submission_stays_suppressed_for_webattack_xss(self):
        row = {
            "src_ip": "203.0.113.40",
            "dst_ip": "198.51.100.45",
            "src_port": 49840,
            "dst_port": 80,
            "ml_label": "webattack_xss",
            "ml_confidence": 0.90,
            "heuristic_score": 0.0,
            "heuristic_type": "None",
            "service": "http",
            "http_request_count": 1,
            "http_status_4xx_5xx_count": 0,
            "http_top_host": "portal.example.com",
            "http_top_uri": "/dv/vulnerabilities/xss_r/?name=alice",
            "src_conn_count": 2,
            "src_unique_ports": 1,
            "src_unique_targets": 1,
            "src_dst_conn_count": 1,
            "src_dst_conn_share": 0.50,
            "src_dst_port_conn_count": 1,
            "src_dst_port_conn_share": 0.50,
            "src_short_ratio": 0.20,
            "src_failed_ratio": 0.0,
            "src_dst_failed_ratio": 0.0,
            "src_dst_port_failed_ratio": 0.0,
            "flow_SYN_flag_count": 1,
            "flow_ACK_flag_count": 2,
            "duration": 1.0,
            "flow_pkts_per_sec": 4.0,
            "bytes_per_s": 1700.0,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertEqual(float(scored["final_score"]), 0.0)

    def test_heartbleed_with_tls_evidence_surfaces(self):
        row = {
            "src_ip": "10.0.0.5",
            "dst_ip": "203.0.113.9",
            "src_port": 51515,
            "dst_port": 443,
            "ml_label": "heartbleed",
            "ml_confidence": 0.97,
            "service": "ssl",
            "ssl_event_count": 4,
            "ssl_top_sni": "vulnerable.example",
            "ssl_top_cipher": "TLS_RSA_WITH_AES_128_CBC_SHA",
            "src_conn_count": 6,
            "src_dst_conn_count": 4,
            "src_dst_port_conn_count": 4,
            "src_dst_conn_share": 0.66,
            "src_dst_port_conn_share": 0.66,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["support_level"], "strong")
        self.assertEqual(scored["verdict"], "Critical")
        self.assertGreater(float(scored["final_score"]), 0.0)

    def test_bot_with_repeated_failed_short_behavior_surfaces(self):
        row = {
            "src_ip": "192.168.1.30",
            "dst_ip": "198.51.100.77",
            "src_port": 41000,
            "dst_port": 23,
            "ml_label": "bot",
            "ml_confidence": 0.82,
            "service": "telnet",
            "src_conn_count": 48,
            "src_unique_ports": 3,
            "src_unique_targets": 9,
            "src_dst_conn_count": 11,
            "src_dst_port_conn_count": 11,
            "src_dst_conn_share": 0.23,
            "src_dst_port_conn_share": 0.23,
            "src_short_ratio": 0.82,
            "src_failed_ratio": 0.34,
            "src_dst_failed_ratio": 0.34,
            "src_dst_port_failed_ratio": 0.34,
            "flow_RST_flag_count": 6,
            "duration": 0.3,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["support_level"], "strong")
        self.assertEqual(scored["verdict"], "Medium")
        self.assertGreater(float(scored["final_score"]), 0.0)

    def test_mqtt_publish_with_repeated_mqtt_context_scores_low(self):
        row = {
            "src_ip": "192.168.0.55",
            "dst_ip": "203.0.113.88",
            "src_port": 50123,
            "dst_port": 1883,
            "ml_label": "MQTT_Publish",
            "ml_confidence": 0.95,
            "service": "mqtt",
            "src_conn_count": 10,
            "src_unique_targets": 1,
            "src_unique_ports": 1,
            "src_dst_conn_count": 6,
            "src_dst_port_conn_count": 6,
            "src_dst_conn_share": 0.60,
            "src_dst_port_conn_share": 0.60,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["support_level"], "strong")
        self.assertEqual(scored["verdict"], "Low")
        self.assertGreater(float(scored["final_score"]), 0.0)

    def test_single_mqtt_publish_flow_stays_normal(self):
        row = {
            "src_ip": "192.168.0.55",
            "dst_ip": "203.0.113.88",
            "src_port": 50123,
            "dst_port": 1883,
            "ml_label": "MQTT_Publish",
            "ml_confidence": 0.95,
            "service": "mqtt",
            "src_conn_count": 1,
            "src_unique_targets": 1,
            "src_unique_ports": 1,
            "src_dst_conn_count": 1,
            "src_dst_port_conn_count": 1,
            "src_dst_conn_share": 1.0,
            "src_dst_port_conn_share": 1.0,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertEqual(float(scored["final_score"]), 0.0)

    def test_thingspeak_with_real_host_context_scores_low(self):
        row = {
            "src_ip": "192.168.0.20",
            "dst_ip": "52.7.123.45",
            "src_port": 49152,
            "dst_port": 80,
            "ml_label": "Thing_Speak",
            "ml_confidence": 0.96,
            "service": "http",
            "http_request_count": 8,
            "http_top_host": "api.thingspeak.com",
            "http_top_uri": "/update",
            "src_conn_count": 12,
            "src_unique_targets": 1,
            "src_unique_ports": 1,
            "src_dst_conn_count": 8,
            "src_dst_port_conn_count": 8,
            "src_dst_conn_share": 0.66,
            "src_dst_port_conn_share": 0.66,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["support_level"], "strong")
        self.assertEqual(scored["verdict"], "Low")
        self.assertGreater(float(scored["final_score"]), 0.0)

    def test_generic_browsing_host_stays_normal_for_thingspeak(self):
        row = {
            "src_ip": "192.168.0.20",
            "dst_ip": "23.50.69.138",
            "src_port": 49152,
            "dst_port": 80,
            "ml_label": "Thing_Speak",
            "ml_confidence": 0.96,
            "service": "http",
            "http_request_count": 8,
            "http_top_host": "www.kakaocorp.com",
            "http_top_uri": "/",
            "src_conn_count": 12,
            "src_unique_targets": 1,
            "src_unique_ports": 1,
            "src_dst_conn_count": 8,
            "src_dst_port_conn_count": 8,
            "src_dst_conn_share": 0.66,
            "src_dst_port_conn_share": 0.66,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertEqual(float(scored["final_score"]), 0.0)

    def test_wipro_bulb_with_device_context_scores_low(self):
        row = {
            "src_ip": "192.168.0.70",
            "dst_ip": "198.51.100.120",
            "src_port": 50222,
            "dst_port": 443,
            "ml_label": "Wipro_bulb",
            "ml_confidence": 0.97,
            "service": "https",
            "ssl_event_count": 5,
            "ssl_top_sni": "api.smartbulb.wipro",
            "src_conn_count": 9,
            "src_unique_targets": 1,
            "src_unique_ports": 1,
            "src_dst_conn_count": 7,
            "src_dst_port_conn_count": 7,
            "src_dst_conn_share": 0.78,
            "src_dst_port_conn_share": 0.78,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["support_level"], "strong")
        self.assertEqual(scored["verdict"], "Low")
        self.assertGreater(float(scored["final_score"]), 0.0)

    def test_generic_https_noise_stays_normal_for_wipro_bulb(self):
        row = {
            "src_ip": "192.168.0.70",
            "dst_ip": "198.51.100.120",
            "src_port": 50222,
            "dst_port": 443,
            "ml_label": "Wipro_bulb",
            "ml_confidence": 0.97,
            "service": "https",
            "ssl_event_count": 5,
            "ssl_top_sni": "cdn.example.com",
            "src_conn_count": 9,
            "src_unique_targets": 1,
            "src_unique_ports": 1,
            "src_dst_conn_count": 7,
            "src_dst_port_conn_count": 7,
            "src_dst_conn_share": 0.78,
            "src_dst_port_conn_share": 0.78,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertEqual(float(scored["final_score"]), 0.0)

    def test_arp_poisoning_with_conflicting_arp_evidence_surfaces(self):
        row = {
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "src_port": 53530,
            "dst_port": 53,
            "ml_label": "ARP_poisioning",
            "ml_confidence": 0.96,
            "service": "dns",
            "arp_packet_count": 8,
            "arp_reply_count": 6,
            "arp_request_count": 2,
            "arp_conflicting_mac_count": 2,
        }

        scored = _score_single_row(row)

        self.assertFalse(bool(scored["suppressed"]))
        self.assertFalse(bool(scored["validation_failed"]))
        self.assertEqual(scored["support_level"], "strong")
        self.assertIn(scored["verdict"], {"High", "Critical"})
        self.assertGreater(float(scored["final_score"]), 0.0)

    def test_arp_poisoning_without_conflicting_arp_evidence_stays_normal(self):
        row = {
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "src_port": 53530,
            "dst_port": 53,
            "ml_label": "ARP_poisioning",
            "ml_confidence": 0.96,
            "service": "dns",
            "arp_packet_count": 6,
            "arp_reply_count": 4,
            "arp_request_count": 2,
            "arp_conflicting_mac_count": 1,
        }

        scored = _score_single_row(row)

        self.assertEqual(scored["verdict"], "Normal")
        self.assertTrue(bool(scored["validation_failed"]))
        self.assertEqual(float(scored["final_score"]), 0.0)


if __name__ == "__main__":
    unittest.main()
