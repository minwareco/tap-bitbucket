import unittest
from unittest import mock
import tap_bitbucket


class TestFetchMissingRefsBatch(unittest.TestCase):
    """Test fetch_missing_refs_batch calls fetchMultipleCommits correctly."""

    def test_calls_fetchMultipleCommits_with_two_args(self):
        """fetchMultipleCommits should be called with (repo_path, shas) only,
        not the extra 'bitbucket' source argument that was causing a TypeError."""
        git_local = mock.MagicMock()
        missing_refs = [
            {'sha': 'abc123', 'ref': 'refs/heads/main'},
            {'sha': 'def456', 'ref': 'refs/heads/feature'},
        ]

        result = tap_bitbucket.fetch_missing_refs_batch(git_local, 'org/repo', missing_refs)

        git_local.fetchMultipleCommits.assert_called_once_with(
            'org/repo', ['abc123', 'def456']
        )
        self.assertEqual(result, missing_refs)

    def test_returns_empty_list_on_no_refs(self):
        """Should return empty list when no missing refs are provided."""
        git_local = mock.MagicMock()

        result = tap_bitbucket.fetch_missing_refs_batch(git_local, 'org/repo', [])

        git_local.fetchMultipleCommits.assert_not_called()
        self.assertEqual(result, [])

    def test_returns_empty_list_on_exception(self):
        """Should return empty list and not raise when fetchMultipleCommits fails."""
        git_local = mock.MagicMock()
        git_local.fetchMultipleCommits.side_effect = Exception("fetch failed")
        missing_refs = [{'sha': 'abc123', 'ref': 'refs/heads/main'}]

        result = tap_bitbucket.fetch_missing_refs_batch(git_local, 'org/repo', missing_refs)

        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
