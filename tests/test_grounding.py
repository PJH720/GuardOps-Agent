"""Grounding gate: in-domain SecOps queries pass, out-of-domain queries are rejected before any LLM call."""
import unittest
from pathlib import Path

from guardops.retriever import RbacBm25Retriever, build_index, evaluate_grounding

RETRIEVER = RbacBm25Retriever(build_index(Path(__file__).resolve().parents[1] / "knowledge"), frozenset({"all", "eng"}))


def verdict(q):
    hits, n = RETRIEVER.search(q)
    return evaluate_grounding(hits, n)


class GroundingGateTest(unittest.TestCase):
    def test_korean_in_domain_query_is_grounded(self):
        self.assertTrue(verdict("운영 DB 이상 로그인 대응 런북").grounded)

    def test_english_alert_is_grounded_via_ko_en_bridge(self):
        self.assertTrue(verdict("DB server abnormal login alert received. Investigate runbook and take required action.").grounded)

    def test_out_of_domain_queries_are_rejected(self):
        for q in ["점심 메뉴 추천해줘", "비트코인 시세 알려줘", "오늘 서울 날씨"]:
            with self.subTest(q=q):
                self.assertFalse(verdict(q).grounded)

    def test_empty_query_rejected(self):
        self.assertEqual(verdict("").reason, "no_results")


if __name__ == "__main__":
    unittest.main()
