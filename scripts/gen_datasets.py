"""scripts/gen_datasets.py
Synthetic multi-schema dataset generator with ground-truth mapping definitions.
Generates:
  - Dataset A: Original Kavach legacy CSVs
  - Dataset B: Workday-style HR CSV + Okta-style nested JSONL events
  - Dataset C: AWS CloudTrail / IAM-style JSON events + Entitlements CSV
  - Dataset D: Stress-test CSV (mixed dates, Y/N flags, snake/camel mix)
"""
from __future__ import annotations

import json
from pathlib import Path
import random

DATA_DIR = Path("data/synthetic")
DATA_DIR.mkdir(parents=True, exist_ok=True)


GROUND_TRUTH_MAPPINGS = {
    "dataset_a_users": {
        "user_id": "identity_id",
        "username": "full_name",
        "department": "department",
        "job_title": "job_title",
        "is_active": "employment_status",
        "hire_date": "hire_date",
    },
    "dataset_a_events": {
        "timestamp": "timestamp",
        "user_id": "user_key",
        "action": "action",
        "resource": "resource",
        "resource_sensitivity": "resource_sensitivity",
        "status": "success",
        "source_ip": "source_ip",
    },
    "dataset_b_workday": {
        "Worker_ID": "employee_id",
        "Full_Name": "full_name",
        "Corporate_Email": "email",
        "Department_Name": "department",
        "Job_Role": "job_title",
        "Worker_Status": "employment_status",
        "Hire_Date": "hire_date",
        "Location_Name": "location",
    },
    "dataset_b_okta": {
        "published": "timestamp",
        "actor.alternateId": "user_key",
        "action.message": "action",
        "target.alternateId": "resource",
        "client.ipAddress": "source_ip",
        "outcome.result": "success",
    },
    "dataset_c_cloudtrail": {
        "eventTime": "timestamp",
        "userIdentity.arn": "user_key",
        "eventName": "action",
        "sourceIPAddress": "source_ip",
        "requestParameters.resourceName": "resource",
    },
    "dataset_c_iam": {
        "User_ARN": "account_id",
        "System_Name": "system",
        "Policy_Name": "entitlement",
        "Privilege_Level": "privilege_weight",
    },
    "dataset_d_stress": {
        "ts_event": "timestamp",
        "usr_key": "user_key",
        "op_verb": "action",
        "target_res": "resource",
        "ip_addr": "source_ip",
        "is_ok_yn": "success",
    },
}


def generate_all_datasets() -> None:
    random.seed(42)

    # ── Dataset A: Reference Legacy Data ──────────────────────────────────────
    ds_a_dir = DATA_DIR / "dataset_a"
    ds_a_dir.mkdir(parents=True, exist_ok=True)
    # Copies or references exist in backend/data/

    # ── Dataset B: Workday HR + Okta JSONL ────────────────────────────────────
    ds_b_dir = DATA_DIR / "dataset_b"
    ds_b_dir.mkdir(parents=True, exist_ok=True)

    # Workday HR CSV
    hr_rows = [
        "Worker_ID,Full_Name,Corporate_Email,Department_Name,Job_Role,Worker_Status,Hire_Date,Location_Name",
        "W101,Aarav Patel,aarav.patel@acme.corp,Engineering,Senior Software Engineer,Active,2022-03-15,Bangalore",
        "W102,Priya Sharma,priya.sharma@acme.corp,Finance,Financial Analyst,Active,2021-08-01,Mumbai",
        "W103,Rohan Verma,rohan.verma@acme.corp,IT Infrastructure,Cloud DevOps Lead,Active,2020-01-10,Bangalore",
        "W104,Ananya Iyer,ananya.iyer@acme.corp,Human Resources,HR Business Partner,Terminated,2019-06-20,Delhi",
        "W105,Vikram Singh,vikram.singh@acme.corp,Security Operations,SecOps Analyst,Active,2023-11-05,Hyderabad",
    ]
    with open(ds_b_dir / "workday_hr.csv", "w", encoding="utf-8") as f:
        f.write("\n".join(hr_rows) + "\n")

    # Okta Events JSONL
    okta_records = [
        {
            "published": "2026-03-20T10:15:30.123Z",
            "actor": {"id": "00u1", "alternateId": "aarav.patel@acme.corp", "displayName": "Aarav Patel"},
            "action": {"message": "user.authentication.sso", "category": "APPLICATION"},
            "target": [{"id": "app1", "alternateId": "GitHub Enterprise", "type": "AppInstance"}],
            "client": {"ipAddress": "103.21.244.15", "zone": "IN"},
            "outcome": {"result": "SUCCESS"},
        },
        {
            "published": "2026-03-20T11:02:14.000Z",
            "actor": {"id": "00u2", "alternateId": "priya.sharma@acme.corp", "displayName": "Priya Sharma"},
            "action": {"message": "core.user.config_change", "category": "CONFIGURATION"},
            "target": [{"id": "app2", "alternateId": "SAP S/4HANA", "type": "AppInstance"}],
            "client": {"ipAddress": "182.72.10.42", "zone": "IN"},
            "outcome": {"result": "SUCCESS"},
        },
        {
            "published": "2026-03-20T23:45:10.500Z",
            "actor": {"id": "00u3", "alternateId": "rohan.verma@acme.corp", "displayName": "Rohan Verma"},
            "action": {"message": "system.mfa.challenge", "category": "AUTHENTICATION"},
            "target": [{"id": "app3", "alternateId": "AWS IAM Production", "type": "AppInstance"}],
            "client": {"ipAddress": "49.207.50.88", "zone": "IN"},
            "outcome": {"result": "FAILURE"},
        },
    ]
    with open(ds_b_dir / "okta_events.jsonl", "w", encoding="utf-8") as f:
        for r in okta_records:
            f.write(json.dumps(r) + "\n")

    # ── Dataset C: AWS CloudTrail / IAM ───────────────────────────────────────
    ds_c_dir = DATA_DIR / "dataset_c"
    ds_c_dir.mkdir(parents=True, exist_ok=True)

    cloudtrail_events = [
        {
            "eventTime": "2026-03-21T04:12:00Z",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDA12345EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/rohan.verma",
                "userName": "rohan.verma",
            },
            "eventName": "GetSecretValue",
            "eventSource": "secretsmanager.amazonaws.com",
            "sourceIPAddress": "54.240.196.18",
            "requestParameters": {
                "resourceName": "prod/db/master_credentials",
            },
            "responseElements": {"status": "SUCCESS"},
        },
        {
            "eventTime": "2026-03-21T05:30:15Z",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROA98765:admin-session",
                "arn": "arn:aws:sts::123456789012:assumed-role/SecOpsAdmin/admin-session",
                "userName": "admin-session",
            },
            "eventName": "DeleteBucketPolicy",
            "eventSource": "s3.amazonaws.com",
            "sourceIPAddress": "13.235.12.90",
            "requestParameters": {
                "resourceName": "finance-crown-jewel-backup",
            },
            "responseElements": {"status": "SUCCESS"},
        },
    ]
    with open(ds_c_dir / "cloudtrail_events.json", "w", encoding="utf-8") as f:
        json.dump(cloudtrail_events, f, indent=2)

    iam_entitlements = [
        "User_ARN,System_Name,Policy_Name,Privilege_Level",
        "arn:aws:iam::123456789012:user/rohan.verma,AWS,AdministratorAccess,10",
        "arn:aws:iam::123456789012:user/aarav.patel,AWS,ReadOnlyAccess,2",
        "arn:aws:iam::123456789012:user/vikram.singh,AWS,SecurityAudit,6",
    ]
    with open(ds_c_dir / "iam_entitlements.csv", "w", encoding="utf-8") as f:
        f.write("\n".join(iam_entitlements) + "\n")

    # ── Dataset D: Stress Test ────────────────────────────────────────────────
    ds_d_dir = DATA_DIR / "dataset_d"
    ds_d_dir.mkdir(parents=True, exist_ok=True)

    stress_rows = [
        "ts_event,usr_key,op_verb,target_res,ip_addr,is_ok_yn,extra_junk_col",
        "2026-03-22 08:30:00,user_991,LOGIN,SRV-ALPHA,192.168.1.50,Y,col_dummy_1",
        "2026-03-22T09:15:00Z,user_992,QUERY,DB-CROWN,10.0.0.12,Y,col_dummy_2",
        "2026/03/22 14:10:00,user_991,DELETE_ROW,CUSTOMER_TABLE,192.168.1.50,N,col_dummy_3",
    ]
    with open(ds_d_dir / "stress_logs.csv", "w", encoding="utf-8") as f:
        f.write("\n".join(stress_rows) + "\n")

    # ── Org Context & Planted Cases (Phase 4) ────────────────────────────────
    org_dir = DATA_DIR / "org_context"
    org_dir.mkdir(parents=True, exist_ok=True)

    # Oncall
    oncall_rows = [
        "user,system,start_time,end_time,role",
        "U_ONCALL_NIGHT,PROD_DB,2026-03-24T20:00:00Z,2026-03-25T08:00:00Z,Primary SRE",
        "aarav.patel@acme.corp,GitHub Enterprise,2026-03-20T00:00:00Z,2026-03-21T00:00:00Z,DevOps",
    ]
    with open(org_dir / "oncall.csv", "w", encoding="utf-8") as f:
        f.write("\n".join(oncall_rows) + "\n")

    # Change Tickets
    ticket_rows = [
        "ticket_id,user,system,start_time,end_time,status,summary",
        "CHG-1001,U_TICKET_APPROVED,CUSTOMER_DATA,2026-03-26T21:00:00Z,2026-03-27T03:00:00Z,APPROVED,Quarterly backup export",
        "CHG-2002,U_MALICIOUS_WRONG_SYSTEM,DEV_SANDBOX,2026-03-27T00:00:00Z,2026-03-27T08:00:00Z,APPROVED,Dev sandbox migration",
        "CHG-2003,U_MALICIOUS_EXPIRED_TICKET,PROD_DB,2026-03-27T00:00:00Z,2026-03-27T04:00:00Z,EXPIRED,Database maintenance",
    ]
    with open(org_dir / "tickets.csv", "w", encoding="utf-8") as f:
        f.write("\n".join(ticket_rows) + "\n")

    # Project Memberships
    project_rows = [
        "project_id,user,system,start_date,end_date,role",
        "PRJ-FIN-INTEGRATION,U_PROJECT_MEMBER,FINANCE_LAKE,2026-01-01,2026-12-31,Data Engineer",
    ]
    with open(org_dir / "projects.csv", "w", encoding="utf-8") as f:
        f.write("\n".join(project_rows) + "\n")

    # Leave Records
    leave_rows = [
        "user,start_date,end_date,leave_type",
        "ananya.iyer@acme.corp,2026-03-15,2026-03-22,Annual Leave",
    ]
    with open(org_dir / "leave.csv", "w", encoding="utf-8") as f:
        f.write("\n".join(leave_rows) + "\n")

    # HR Events (Transfers, Promotions)
    hr_event_rows = [
        "user,event_type,old_role,new_role,effective_date",
        "U_RECENT_TRANSFER,ROLE_TRANSFER,HR Generalist,Marketing Analyst,2026-03-10",
    ]
    with open(org_dir / "hr_events.csv", "w", encoding="utf-8") as f:
        f.write("\n".join(hr_event_rows) + "\n")

    # Approved Exceptions
    exception_rows = [
        "exception_id,user,entitlement,expiry_date,approver,justification",
        "EXC-901,U_APPROVED_EXCEPTION,aws_iam_admin,2026-06-30,CISO,Cloud migration temporary access",
    ]
    with open(org_dir / "exceptions.csv", "w", encoding="utf-8") as f:
        f.write("\n".join(exception_rows) + "\n")

    # Planted Cases Metadata
    planted_cases = {
        "benign_cases": [
            {
                "user_id": "U_ONCALL_NIGHT",
                "finding": "HIGH_SENS_EXPORT_NIGHT",
                "system": "PROD_DB",
                "timestamp": "2026-03-25T02:30:00Z",
                "mitigating_tool": "was_on_call",
                "expected_status": "refuted",
            },
            {
                "user_id": "U_TICKET_APPROVED",
                "finding": "HIGH_SENS_EXPORT_NIGHT",
                "system": "CUSTOMER_DATA",
                "timestamp": "2026-03-26T22:15:00Z",
                "mitigating_tool": "change_ticket_covering",
                "expected_status": "refuted",
            },
            {
                "user_id": "U_PROJECT_MEMBER",
                "finding": "CROSS_DEPT_ACCESS",
                "system": "FINANCE_LAKE",
                "timestamp": "2026-03-26T15:00:00Z",
                "mitigating_tool": "project_membership",
                "expected_status": "refuted",
            },
            {
                "user_id": "U_RECENT_TRANSFER",
                "finding": "CROSS_DEPT_ACCESS",
                "system": "MARKETING_CRM",
                "timestamp": "2026-03-25T11:00:00Z",
                "mitigating_tool": "recent_role_change",
                "expected_status": "refuted",
            },
            {
                "user_id": "U_APPROVED_EXCEPTION",
                "finding": "STALE_PRIVILEGED_ACCOUNT",
                "system": "AWS",
                "timestamp": "2026-03-25T10:00:00Z",
                "mitigating_tool": "approved_exception",
                "expected_status": "refuted",
            },
        ],
        "malicious_cases": [
            {
                "user_id": "U_MALICIOUS_NO_TICKET",
                "finding": "HIGH_SENS_EXPORT_NIGHT",
                "system": "FINANCE_LAKE",
                "timestamp": "2026-03-27T03:15:00Z",
                "mitigating_tool": None,
                "expected_status": "stands",
            },
            {
                "user_id": "U_MALICIOUS_WRONG_SYSTEM",
                "finding": "HIGH_SENS_EXPORT_NIGHT",
                "system": "CORE_BANKING_PROD",
                "timestamp": "2026-03-27T04:00:00Z",
                "mitigating_tool": None,
                "expected_status": "stands",
            },
            {
                "user_id": "U_MALICIOUS_EXPIRED_TICKET",
                "finding": "HIGH_SENS_EXPORT_NIGHT",
                "system": "PROD_DB",
                "timestamp": "2026-03-27T06:00:00Z",
                "mitigating_tool": None,
                "expected_status": "stands",
            },
            {
                "user_id": "U_HARD_RULE_SOD",
                "finding": "SOD_CONFLICT",
                "system": "SAP",
                "timestamp": "2026-03-27T07:00:00Z",
                "mitigating_tool": None,
                "expected_status": "stands",
            },
        ],
    }
    with open(org_dir / "planted_cases.json", "w", encoding="utf-8") as f:
        json.dump(planted_cases, f, indent=2)

    # Save Ground Truth file
    with open(DATA_DIR / "ground_truth.json", "w", encoding="utf-8") as f:
        json.dump(GROUND_TRUTH_MAPPINGS, f, indent=2)

    print("Synthetic datasets A, B, C, D, Org Context, and ground_truth.json successfully generated.")


if __name__ == "__main__":
    generate_all_datasets()

