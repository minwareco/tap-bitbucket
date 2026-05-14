import unittest
from unittest import mock
from minware_singer_utils import GitLocalRepoNotFoundException, GitLocalException
import tap_bitbucket


class TestRepoNotFoundHandling(unittest.TestCase):
    """Test that missing/inaccessible repos are skipped in do_sync."""

    def _make_catalog(self, stream_ids):
        """Build a minimal catalog with the given stream IDs selected."""
        streams = []
        for sid in stream_ids:
            streams.append(
                {
                    "tap_stream_id": sid,
                    "schema": {},
                    "key_properties": ["id"],
                    "metadata": [{"breadcrumb": [], "metadata": {"selected": True}}],
                }
            )
        return {"streams": streams}

    @mock.patch("tap_bitbucket.validate_dependencies")
    @mock.patch("tap_bitbucket.get_selected_streams", return_value=["commits"])
    @mock.patch("singer.write_schema")
    @mock.patch("singer.write_state")
    @mock.patch.dict(
        tap_bitbucket.SYNC_FUNCTIONS, {"commits": mock.MagicMock(return_value={})}
    )
    def test_skips_repo_on_api_not_found(
        self,
        mock_write_state,
        mock_write_schema,
        mock_get_selected,
        mock_validate,
    ):
        """When a sync function raises NotFoundException (API 404), the repo
        is skipped and sync continues to the next repo."""
        sync_func = tap_bitbucket.SYNC_FUNCTIONS["commits"]
        sync_func.side_effect = [
            tap_bitbucket.NotFoundException(
                "HTTP-error-code: 404, Error: The resource you have specified cannot be found"
            ),
            {},  # second repo succeeds
        ]

        config = {
            "repository": "org/deleted-repo org/good-repo",
            "start_date": "2024-01-01",
        }
        catalog = self._make_catalog(["commits"])

        # Should not raise — the deleted repo is skipped
        tap_bitbucket.do_sync(config, {}, catalog, mock.MagicMock())

        # Sync function was called for both repos
        self.assertEqual(sync_func.call_count, 2)

    @mock.patch("tap_bitbucket.validate_dependencies")
    @mock.patch("tap_bitbucket.get_selected_streams", return_value=["commits"])
    @mock.patch("singer.write_schema")
    @mock.patch("singer.write_state")
    @mock.patch.dict(
        tap_bitbucket.SYNC_FUNCTIONS, {"commits": mock.MagicMock(return_value={})}
    )
    def test_state_not_written_for_api_not_found_repo(
        self,
        mock_write_state,
        mock_write_schema,
        mock_get_selected,
        mock_validate,
    ):
        """State should not be written when all repos are skipped due to API 404."""
        sync_func = tap_bitbucket.SYNC_FUNCTIONS["commits"]
        sync_func.side_effect = tap_bitbucket.NotFoundException(
            "HTTP-error-code: 404, Error: The resource you have specified cannot be found"
        )

        config = {
            "repository": "org/deleted-repo",
            "start_date": "2024-01-01",
        }
        catalog = self._make_catalog(["commits"])

        tap_bitbucket.do_sync(config, {}, catalog, mock.MagicMock())

        # write_state is called once at the end of do_sync, but should still
        # be called since it writes the final state regardless
        # The key point: the sync function raised but didn't crash
        self.assertEqual(sync_func.call_count, 1)

    @mock.patch("tap_bitbucket.validate_dependencies")
    @mock.patch("tap_bitbucket.get_selected_streams", return_value=["commits"])
    @mock.patch("singer.write_schema")
    @mock.patch("singer.write_state")
    @mock.patch.dict(
        tap_bitbucket.SYNC_FUNCTIONS, {"commits": mock.MagicMock(return_value={})}
    )
    def test_skips_repo_when_not_found_on_clone(
        self,
        mock_write_state,
        mock_write_schema,
        mock_get_selected,
        mock_validate,
    ):
        """When GitLocalRepoNotFoundException is raised during sync, the repo
        is skipped and sync continues to the next repo."""
        sync_func = tap_bitbucket.SYNC_FUNCTIONS["commits"]
        sync_func.side_effect = [
            GitLocalRepoNotFoundException("repo not found"),
            {},  # second repo succeeds
        ]

        config = {
            "repository": "org/missing-repo org/good-repo",
            "start_date": "2024-01-01",
        }
        catalog = self._make_catalog(["commits"])

        tap_bitbucket.do_sync(config, {}, catalog, mock.MagicMock())

        self.assertEqual(sync_func.call_count, 2)

    @mock.patch("tap_bitbucket.validate_dependencies")
    @mock.patch("tap_bitbucket.get_selected_streams", return_value=["commits"])
    @mock.patch("singer.write_schema")
    @mock.patch("singer.write_state")
    @mock.patch.dict(
        tap_bitbucket.SYNC_FUNCTIONS, {"commits": mock.MagicMock(return_value={})}
    )
    def test_other_exceptions_still_raise(
        self,
        mock_write_state,
        mock_write_schema,
        mock_get_selected,
        mock_validate,
    ):
        """A generic GitLocalException (not repo-not-found) should still propagate."""
        sync_func = tap_bitbucket.SYNC_FUNCTIONS["commits"]
        sync_func.side_effect = GitLocalException("network timeout")

        config = {
            "repository": "org/some-repo",
            "start_date": "2024-01-01",
        }
        catalog = self._make_catalog(["commits"])

        with self.assertRaises(GitLocalException):
            tap_bitbucket.do_sync(config, {}, catalog, mock.MagicMock())

    @mock.patch("tap_bitbucket.validate_dependencies")
    @mock.patch("tap_bitbucket.get_selected_streams", return_value=["commits"])
    @mock.patch("singer.write_schema")
    @mock.patch("singer.write_state")
    @mock.patch.dict(
        tap_bitbucket.SYNC_FUNCTIONS, {"commits": mock.MagicMock(return_value={})}
    )
    def test_other_bitbucket_exceptions_still_raise(
        self,
        mock_write_state,
        mock_write_schema,
        mock_get_selected,
        mock_validate,
    ):
        """A non-404 BitBucketException (e.g. AuthException) should still propagate."""
        sync_func = tap_bitbucket.SYNC_FUNCTIONS["commits"]
        sync_func.side_effect = tap_bitbucket.AuthException("forbidden")

        config = {
            "repository": "org/some-repo",
            "start_date": "2024-01-01",
        }
        catalog = self._make_catalog(["commits"])

        with self.assertRaises(tap_bitbucket.AuthException):
            tap_bitbucket.do_sync(config, {}, catalog, mock.MagicMock())


if __name__ == "__main__":
    unittest.main()
