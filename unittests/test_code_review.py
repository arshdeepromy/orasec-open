"""A.8.25 code review check: a Reviewed-by line from a second person on every commit, or a recorded late review."""
from unittest import mock

from orasec.posture import compliance
from orasec.posture.models import Connector
from unittests.orasec_test_case import OraSecTestCase

A, B = "Alex Lee", "Dana Smith"


def commit(sha, msg, author=A, parents=1):
    return {"sha": sha, "parents": [{}] * parents, "commit": {"message": msg, "author": {"name": author}}}


class TestCodeReview(OraSecTestCase):
    def setUp(self):
        gh, _ = Connector.objects.get_or_create(kind="github", defaults={"name": "GitHub"})
        gh.options = {**(gh.options or {}), "review_repos": ["example-org/example-repo"]}
        gh.save()

    def run_check(self, commits):
        class Fake:
            def __init__(self, c):
                pass

            def _paged(self, url, **kw):
                return commits
        with mock.patch("orasec.posture.connectors.base.get_connector_class", return_value=Fake):
            return compliance.check_code_review()

    def test_all_reviewed_passes(self):
        r, d, m = self.run_check([commit("a" * 40, f"x\n\nReviewed-by: {B}"), commit("b" * 40, "merge", parents=2)])
        self.assertEqual(r, "pass", d)
        self.assertEqual((m["commits"], m["without_review"], m["reviewed_late"]), (1, [], []))

    def test_missing_or_self_review_fails(self):
        r, d, m = self.run_check([commit("a" * 40, "no line"), commit("b" * 40, f"x\n\nReviewed-by: {A}")])
        self.assertEqual(r, "fail")
        self.assertEqual(len(m["without_review"]), 2)

    def test_late_review_record_counts_and_is_reported(self):
        late = "c" * 40
        rec = commit("d" * 40, f"Late review record\n\nReviewed-commit: {late}\nReviewed-commit: eeeeeee\nReviewed-by: {B}")
        r, d, m = self.run_check([rec, commit(late, "pushed before review"), commit("eeeeeee" + "1" * 33, "also late")])
        self.assertEqual(r, "pass", d)
        self.assertIn("2 of them after they were pushed", d)
        self.assertEqual(len(m["reviewed_late"]), 2)

    def test_late_record_needs_a_second_person(self):
        late = "c" * 40
        # the record itself has no second-person review
        r, _d, _m = self.run_check([commit("d" * 40, f"rec\n\nReviewed-commit: {late}\nReviewed-by: {A}"), commit(late, "x")])
        self.assertEqual(r, "fail")
        # the record is reviewed, but only by the author of the late commit
        r, _d, m = self.run_check([commit("d" * 40, f"rec\n\nReviewed-commit: {late}\nReviewed-by: {B}", author=A),
                                   commit(late, "x", author=B)])
        self.assertEqual(r, "fail")
        self.assertEqual(m["without_review"], [f"example-org/example-repo@{late[:7]}"])

    def test_unlisted_commit_still_fails(self):
        rec = commit("d" * 40, f"rec\n\nReviewed-commit: {'c' * 40}\nReviewed-by: {B}")
        r, _d, m = self.run_check([rec, commit("c" * 40, "late"), commit("f" * 40, "never reviewed")])
        self.assertEqual(r, "fail")
        self.assertEqual(m["without_review"], [f"example-org/example-repo@{'f' * 7}"])
