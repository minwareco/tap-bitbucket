import unittest
from unittest import mock

import requests

import tap_bitbucket


def _ok_response():
    """A fake successful 200 response object."""
    resp = mock.MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"values": []}
    return resp


def _rate_limited_response():
    """A fake 429 (rate limited) response object."""
    resp = mock.MagicMock()
    resp.status_code = 429
    return resp


class TestConnectionRetry(unittest.TestCase):
    """authed_request should retry transient connection errors (e.g. the
    'Connection reset by peer' / ConnectionResetError(104) seen in MW-12382)
    using the same backoff budget as 429/5xx responses, rather than crashing.
    """

    @mock.patch("tap_bitbucket.time.sleep")  # skip real backoff waits
    @mock.patch("tap_bitbucket.session.request")
    def test_connection_reset_retries_then_succeeds(self, mock_request, _mock_sleep):
        # First call blows up with a connection reset, second call succeeds.
        mock_request.side_effect = [
            requests.exceptions.ConnectionError(
                "('Connection aborted.', ConnectionResetError(104, 'Connection reset by peer'))"
            ),
            _ok_response(),
        ]

        result = tap_bitbucket.authed_request(
            "commits", "https://api.bitbucket.org/2.0/foo", "GET"
        )

        self.assertEqual(result, {"values": []})
        self.assertEqual(mock_request.call_count, 2)

    @mock.patch("tap_bitbucket.time.sleep")
    @mock.patch("tap_bitbucket.session.request")
    def test_connection_reset_exhausts_retries_and_raises(self, mock_request, _mock_sleep):
        # Persistent connection reset should surface as an error after retries,
        # not hang or return None.
        mock_request.side_effect = requests.exceptions.ConnectionError(
            "Connection reset by peer"
        )

        with self.assertRaises(Exception):
            tap_bitbucket.authed_request(
                "commits", "https://api.bitbucket.org/2.0/foo", "GET"
            )

        # Should have retried up to the configured maximum, not given up after one.
        self.assertGreater(mock_request.call_count, 1)

    @mock.patch("tap_bitbucket.time.sleep")
    @mock.patch("tap_bitbucket.session.request")
    def test_rate_limit_then_connection_reset_then_success(self, mock_request, _mock_sleep):
        # Mirrors the exact production sequence in the MW-12382 logs: a 429
        # rate-limit response, a backoff, then the retried request hits a
        # stale-connection reset, then a fresh connection succeeds. The 429 and
        # the connection error share the same retry budget.
        mock_request.side_effect = [
            _rate_limited_response(),
            requests.exceptions.ConnectionError("Connection reset by peer"),
            _ok_response(),
        ]

        result = tap_bitbucket.authed_request(
            "commits", "https://api.bitbucket.org/2.0/foo", "GET"
        )

        self.assertEqual(result, {"values": []})
        self.assertEqual(mock_request.call_count, 3)

    def test_drop_pooled_connections_closes_adapters_but_keeps_session(self):
        # The helper must close every mounted adapter's connection pool so the
        # next request opens a fresh socket, without unmounting the adapters
        # (the session — and its auth headers — must stay usable).
        fake_adapters = {"https://": mock.MagicMock(), "http://": mock.MagicMock()}
        with mock.patch.object(tap_bitbucket.session, "adapters", fake_adapters):
            tap_bitbucket.drop_pooled_connections()
            for adapter in fake_adapters.values():
                adapter.close.assert_called_once()

    @mock.patch("tap_bitbucket.drop_pooled_connections")
    @mock.patch("tap_bitbucket.time.sleep")
    @mock.patch("tap_bitbucket.session.request")
    def test_stale_connection_refreshed_after_rate_limit_backoff(
        self, mock_request, _mock_sleep, mock_drop
    ):
        # This is the exact scenario in the MW-12382 logs: a 429 forces a long
        # idle backoff that leaves the pooled socket stale. Connections must be
        # dropped before the retry so it doesn't hit 'Connection reset by peer'.
        mock_request.side_effect = [_rate_limited_response(), _ok_response()]

        result = tap_bitbucket.authed_request(
            "commits", "https://api.bitbucket.org/2.0/foo", "GET"
        )

        self.assertEqual(result, {"values": []})
        mock_drop.assert_called()


if __name__ == "__main__":
    unittest.main()
