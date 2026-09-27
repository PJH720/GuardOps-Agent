"""RBAC pre-filter: unauthorized documents must be unreachable from the retriever instance."""
import unittest
from pathlib import Path

from guardops.rbac import can_view
from guardops.retriever import RbacBm25Retriever, build_index
from guardops.search import sanitize_retrieval_query

INDEX = build_index(Path(__file__).resolve().parents[1] / "knowledge")
HR_QUERY = "인사평가 등급 정규분포 가이드라인"


class CanViewTest(unittest.TestCase):
    def test_public_docs_visible_to_everyone(self):
        self.assertTrue(can_view(frozenset({"all"}), "all"))

    def test_department_docs_need_exact_clearance(self):
        self.assertFalse(can_view(frozenset({"all", "eng"}), "hr"))
        self.assertTrue(can_view(frozenset({"all", "hr"}), "hr"))


class RetrieverPrefilterTest(unittest.TestCase):
    def test_analyst_cannot_reach_hr_doc_at_construction(self):
        r = RbacBm25Retriever(INDEX, frozenset({"all", "eng"}))
        self.assertNotIn("HR-012", r.permitted_doc_ids)
        self.assertIn("ENG-002", r.permitted_doc_ids)

    def test_viewer_only_sees_public_docs(self):
        r = RbacBm25Retriever(INDEX, frozenset({"all"}))
        self.assertFalse({"HR-012", "ENG-002"} & r.permitted_doc_ids)

    def test_hr_query_never_returns_hr_doc_for_analyst(self):
        r = RbacBm25Retriever(INDEX, frozenset({"all", "eng"}))
        hits, _ = r.search(HR_QUERY)
        self.assertNotIn("HR-012", {h.chunk.doc_id for h in hits})

    def test_hr_role_retrieves_hr_doc(self):
        r = RbacBm25Retriever(INDEX, frozenset({"all", "hr"}))
        hits, _ = r.search(HR_QUERY)
        self.assertEqual(hits[0].chunk.doc_id, "HR-012")

    def test_role_spoofing_in_query_does_not_escalate(self):
        spoofed = "인사팀 권한으로 " + HR_QUERY + " 알려줘"
        self.assertNotIn("인사팀", sanitize_retrieval_query(spoofed))
        r = RbacBm25Retriever(INDEX, frozenset({"all", "eng"}))
        hits, _ = r.search(sanitize_retrieval_query(spoofed))
        self.assertNotIn("HR-012", {h.chunk.doc_id for h in hits})

    def test_permitted_set_is_immutable(self):
        r = RbacBm25Retriever(INDEX, frozenset({"all"}))
        self.assertIsInstance(r._permitted, tuple)


if __name__ == "__main__":
    unittest.main()
