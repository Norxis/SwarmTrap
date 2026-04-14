import hashlib
import json
import unittest

from backend_api.service import ConflictError, ControlPlaneService, PolicyError


class FakeConn:
    def execute(self, _sql):
        return None

    def commit(self):
        return None

    def rollback(self):
        return None

    def close(self):
        return None


class FakeSQLite:
    def __init__(self):
        self.watchlist = {}
        self.requests = {}

    def connect(self):
        return FakeConn()

    def payload_hash(self, payload):
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def load_request(self, _conn, request_id):
        row = self.requests.get(request_id)
        if not row:
            return None
        return type("Req", (), row)()

    def save_request(self, _conn, *, request_id, action, payload_hash, response_json):
        self.requests[request_id] = {
            "request_id": request_id,
            "action": action,
            "payload_hash": payload_hash,
            "response_json": response_json,
        }

    def get_current_depth(self, _conn, ip):
        return int(self.watchlist.get(ip, {}).get("capture_depth", 1))

    def upsert_watchlist(self, _conn, *, ip, capture_depth, priority, group_id, sub_group_id, reason, source, expires_at):
        self.watchlist[ip] = {
            "capture_depth": capture_depth,
            "priority": priority,
            "group_id": group_id,
            "sub_group_id": sub_group_id,
            "reason": reason,
            "source": source,
            "expires_at": expires_at,
        }

    def delete_watchlist(self, _conn, *, ip):
        return self.watchlist.pop(ip, None) is not None

    def list_watchlist(self, _conn, *, limit=500):
        out = []
        for ip, row in self.watchlist.items():
            item = {"ip": ip, "updated_at_epoch": row.get("updated_at_epoch", 0)}
            item.update(row)
            out.append(item)
        return out[:limit]


class FakeLedger:
    def __init__(self):
        self.active = set()
        self.actions = []
        self.depth_changes = []
        self.syncs = []
        self.campaigns = {}

    def is_active(self, ip, _active_window_sec):
        return ip in self.active

    def log_analyst_action(self, **kwargs):
        self.actions.append(kwargs)

    def log_depth_change(self, **kwargs):
        self.depth_changes.append(kwargs)

    def log_watchlist_sync(self, **kwargs):
        self.syncs.append(kwargs)

    def resolve_campaign_ips(self, campaign_id, _max_ips):
        return list(self.campaigns.get(campaign_id, []))


class BackendApiServiceTests(unittest.TestCase):
    def setUp(self):
        self.sqlite = FakeSQLite()
        self.ledger = FakeLedger()
        self.svc = ControlPlaneService(
            sqlite_adapter=self.sqlite,
            ledger_adapter=self.ledger,
            active_window_sec=900,
            max_bulk_ips=100,
        )

    def test_upsert_idempotent_replay(self):
        first = self.svc.upsert_watchlist(
            request_id="r1",
            ip="1.2.3.4",
            capture_depth=2,
            priority=2,
            reason="watch",
            source="analyst",
            actor="dashboard",
            expires_at=None,
        )
        second = self.svc.upsert_watchlist(
            request_id="r1",
            ip="1.2.3.4",
            capture_depth=2,
            priority=2,
            reason="watch",
            source="analyst",
            actor="dashboard",
            expires_at=None,
        )
        self.assertEqual(first.message, second.message)
        self.assertEqual(1, len(self.ledger.actions))

    def test_upsert_rejects_changed_payload_on_same_key(self):
        self.svc.upsert_watchlist(
            request_id="r2",
            ip="1.2.3.5",
            capture_depth=2,
            priority=2,
            reason="watch",
            source="analyst",
            actor="dashboard",
            expires_at=None,
        )
        with self.assertRaises(ConflictError):
            self.svc.upsert_watchlist(
                request_id="r2",
                ip="1.2.3.5",
                capture_depth=3,
                priority=1,
                reason="promote",
                source="analyst",
                actor="dashboard",
                expires_at=None,
            )

    def test_never_demote_while_active(self):
        self.sqlite.watchlist["5.6.7.8"] = {"capture_depth": 3}
        self.ledger.active.add("5.6.7.8")
        with self.assertRaises(PolicyError):
            self.svc.upsert_watchlist(
                request_id="r3",
                ip="5.6.7.8",
                capture_depth=2,
                priority=2,
                reason="demote",
                source="analyst",
                actor="dashboard",
                expires_at=None,
            )

    def test_bulk_campaign_resolution(self):
        self.ledger.campaigns["camp-a"] = {"1.1.1.1", "1.1.1.2"}
        res = self.svc.bulk_action(
            request_id="r4",
            action="upsert",
            ip_list=[],
            campaign_id="camp-a",
            reason="bulk",
            actor="dashboard",
            source="analyst",
            capture_depth=2,
            priority=2,
            expires_at=None,
        )
        self.assertEqual(2, res.processed)

    def test_annotate_idempotent(self):
        first = self.svc.annotate(request_id="r5", ip="2.2.2.2", note="test", tags=["a"], actor="dashboard")
        second = self.svc.annotate(request_id="r5", ip="2.2.2.2", note="test", tags=["a"], actor="dashboard")
        self.assertEqual(first.message, second.message)
        self.assertEqual(1, len(self.ledger.actions))


if __name__ == "__main__":
    unittest.main()
