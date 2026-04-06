"""
CYBERMETRICS — Gerador de dados mockados para o star schema de vulnerabilidades.

Uso:
    pip install -r requirements.txt
    python generate_mock_data.py

Variáveis de ambiente:
    DATABASE_URL  (default: postgresql://cybermetrics:cybermetrics@localhost:5432/cybermetrics)
"""

import os
import random
from datetime import date, timedelta
from uuid import uuid4

import psycopg2

DB_DSN = os.getenv(
    "DATABASE_URL",
    "postgresql://cybermetrics:cybermetrics@localhost:5432/cybermetrics",
)

random.seed(42)  # reprodutível

# ============================================================
# Pools de dados realistas
# ============================================================

ASSETS = [
    # (external_id, name, type, environment, team, BU, criticality, cloud_provider, repo_url)
    ("app-api-gateway",      "API Gateway",            "application", "production",  "platform",      "Engineering", "critical", None,  "https://github.com/acme/api-gateway"),
    ("app-auth-service",     "Auth Service",            "application", "production",  "identity",      "Engineering", "critical", None,  "https://github.com/acme/auth-service"),
    ("app-payment-api",      "Payment API",             "application", "production",  "payments",      "Finance",     "critical", None,  "https://github.com/acme/payment-api"),
    ("app-user-portal",      "User Portal",             "application", "production",  "frontend",      "Product",     "high",     None,  "https://github.com/acme/user-portal"),
    ("app-admin-dashboard",  "Admin Dashboard",         "application", "production",  "frontend",      "Product",     "high",     None,  "https://github.com/acme/admin-dashboard"),
    ("app-notification-svc", "Notification Service",    "application", "production",  "platform",      "Engineering", "medium",   None,  "https://github.com/acme/notification-svc"),
    ("app-reporting-api",    "Reporting API",           "application", "staging",     "data",          "Engineering", "medium",   None,  "https://github.com/acme/reporting-api"),
    ("app-mobile-bff",       "Mobile BFF",              "application", "production",  "mobile",        "Product",     "high",     None,  "https://github.com/acme/mobile-bff"),
    ("app-internal-tools",   "Internal Tools",          "application", "development", "devops",        "Engineering", "low",      None,  "https://github.com/acme/internal-tools"),
    ("app-ml-pipeline",      "ML Pipeline",             "application", "staging",     "data",          "Engineering", "medium",   None,  "https://github.com/acme/ml-pipeline"),
    ("host-web-prod-01",     "web-prod-01",             "host",        "production",  "infrastructure","Engineering", "high",     "aws", None),
    ("host-web-prod-02",     "web-prod-02",             "host",        "production",  "infrastructure","Engineering", "high",     "aws", None),
    ("host-db-prod-01",      "db-prod-01",              "host",        "production",  "infrastructure","Engineering", "critical", "aws", None),
    ("host-ci-runner-01",    "ci-runner-01",            "host",        "development", "devops",        "Engineering", "low",      "aws", None),
    ("cloud-aws-prod",       "AWS Production Account",  "cloud_resource", "production", "cloud",       "Engineering", "critical", "aws", None),
    ("cloud-aws-staging",    "AWS Staging Account",     "cloud_resource", "staging",    "cloud",       "Engineering", "medium",   "aws", None),
    ("cloud-aws-dev",        "AWS Dev Account",         "cloud_resource", "development","cloud",       "Engineering", "low",      "aws", None),
    ("cloud-gcp-analytics",  "GCP Analytics Project",   "cloud_resource", "production", "data",        "Engineering", "high",     "gcp", None),
    ("container-api-gw",     "api-gateway:latest",      "container",   "production",  "platform",      "Engineering", "critical", None, None),
    ("container-auth",       "auth-service:latest",     "container",   "production",  "identity",      "Engineering", "critical", None, None),
    ("container-payment",    "payment-api:latest",      "container",   "production",  "payments",      "Finance",     "critical", None, None),
    ("container-nginx",      "nginx:1.25",              "container",   "production",  "infrastructure","Engineering", "high",     None, None),
    ("container-redis",      "redis:7.2",               "container",   "production",  "platform",      "Engineering", "medium",   None, None),
]

VULNERABILITIES = [
    # (external_id, title, cve, cwe_id, cwe_name, owasp_category, description)
    # -- SAST
    ("sast-sqli-001",          "SQL Injection",                         None,             "CWE-89",  "SQL Injection",                        "A03:2021 Injection",                      "User input concatenated in SQL query"),
    ("sast-xss-001",           "Reflected XSS",                        None,             "CWE-79",  "Cross-site Scripting",                 "A03:2021 Injection",                      "User input reflected in HTML response without encoding"),
    ("sast-xss-002",           "Stored XSS",                           None,             "CWE-79",  "Cross-site Scripting",                 "A03:2021 Injection",                      "User input stored and rendered without sanitization"),
    ("sast-path-001",          "Path Traversal",                       None,             "CWE-22",  "Path Traversal",                       "A01:2021 Broken Access Control",          "File path constructed from user input"),
    ("sast-crypto-001",        "Weak Cryptographic Algorithm",         None,             "CWE-327", "Use of Broken Crypto Algorithm",       "A02:2021 Cryptographic Failures",         "Use of MD5 or SHA1 for password hashing"),
    ("sast-hardcoded-001",     "Hardcoded Credentials",                None,             "CWE-798", "Hardcoded Credentials",                "A07:2021 Identification Failures",        "Credentials hardcoded in source code"),
    ("sast-ssrf-001",          "Server-Side Request Forgery",          None,             "CWE-918", "SSRF",                                 "A10:2021 SSRF",                           "URL from user input used in server-side request"),
    ("sast-deserialization-001","Insecure Deserialization",             None,             "CWE-502", "Deserialization of Untrusted Data",    "A08:2021 Software and Data Integrity",    "Deserialization of untrusted data without validation"),
    ("sast-log-injection-001", "Log Injection",                        None,             "CWE-117", "Log Injection",                        "A09:2021 Security Logging Failures",      "User input written directly to logs"),
    ("sast-open-redirect-001", "Open Redirect",                        None,             "CWE-601", "Open Redirect",                        "A01:2021 Broken Access Control",          "Redirect URL from user input without validation"),
    # -- DAST
    ("dast-sqli-001",          "SQL Injection (Dynamic)",              None,             "CWE-89",  "SQL Injection",                        "A03:2021 Injection",                      "SQL injection detected via dynamic analysis"),
    ("dast-xss-001",           "Reflected XSS (Dynamic)",              None,             "CWE-79",  "Cross-site Scripting",                 "A03:2021 Injection",                      "XSS detected in HTTP response"),
    ("dast-csrf-001",          "Cross-Site Request Forgery",           None,             "CWE-352", "CSRF",                                 "A01:2021 Broken Access Control",          "Missing CSRF token on form submission"),
    ("dast-headers-001",       "Missing Security Headers",            None,             "CWE-693", "Protection Mechanism Failure",          "A05:2021 Security Misconfiguration",      "Missing X-Frame-Options, CSP headers"),
    ("dast-tls-001",           "Weak TLS Configuration",              None,             "CWE-326", "Inadequate Encryption Strength",       "A02:2021 Cryptographic Failures",         "TLS 1.0/1.1 still enabled"),
    # -- SCA
    ("sca-log4j-001",          "Log4Shell (Log4j RCE)",               "CVE-2021-44228","CWE-502", "Deserialization of Untrusted Data",    "A06:2021 Vulnerable Components",          "Critical RCE in Apache Log4j 2.x"),
    ("sca-spring4shell-001",   "Spring4Shell",                        "CVE-2022-22965","CWE-94",  "Code Injection",                       "A06:2021 Vulnerable Components",          "RCE in Spring Framework"),
    ("sca-jackson-001",        "Jackson Databind Deserialization",     "CVE-2019-12384","CWE-502", "Deserialization of Untrusted Data",    "A06:2021 Vulnerable Components",          "Deserialization vulnerability in Jackson"),
    ("sca-lodash-001",         "Lodash Prototype Pollution",          "CVE-2020-8203", "CWE-1321","Prototype Pollution",                  "A06:2021 Vulnerable Components",          "Prototype pollution in lodash"),
    ("sca-axios-001",          "Axios SSRF",                          "CVE-2023-45857","CWE-918", "SSRF",                                 "A06:2021 Vulnerable Components",          "SSRF vulnerability in axios"),
    ("sca-express-001",        "Express.js Open Redirect",            "CVE-2024-29041","CWE-601", "Open Redirect",                        "A06:2021 Vulnerable Components",          "Open redirect in express"),
    ("sca-openssl-001",        "OpenSSL Buffer Overflow",             "CVE-2022-3602", "CWE-120", "Buffer Overflow",                      "A06:2021 Vulnerable Components",          "Buffer overflow in OpenSSL X.509 cert verification"),
    # -- CSPM
    ("cspm-s3-public-001",     "S3 Bucket Publicly Accessible",       None,             "CWE-284", "Improper Access Control",              "A01:2021 Broken Access Control",          "S3 bucket allows public access"),
    ("cspm-sg-open-001",       "Security Group Open to World",        None,             "CWE-284", "Improper Access Control",              "A05:2021 Security Misconfiguration",      "Security group allows 0.0.0.0/0 ingress"),
    ("cspm-rds-public-001",    "RDS Instance Publicly Accessible",    None,             "CWE-284", "Improper Access Control",              "A05:2021 Security Misconfiguration",      "RDS instance has public accessibility enabled"),
    ("cspm-iam-admin-001",     "IAM User with Admin Access",          None,             "CWE-250", "Execution with Unnecessary Privileges","A01:2021 Broken Access Control",          "IAM user has full administrative access"),
    ("cspm-mfa-001",           "MFA Not Enabled on Root Account",     None,             "CWE-308", "Use of Single-factor Authentication",  "A07:2021 Identification Failures",        "Root account without MFA"),
    ("cspm-logging-001",       "CloudTrail Logging Disabled",         None,             "CWE-778", "Insufficient Logging",                 "A09:2021 Security Logging Failures",      "CloudTrail not enabled in region"),
    ("cspm-encryption-001",    "EBS Volume Not Encrypted",            None,             "CWE-311", "Missing Encryption",                   "A02:2021 Cryptographic Failures",         "EBS volume without encryption at rest"),
    ("cspm-kms-rotation-001",  "KMS Key Rotation Disabled",           None,             "CWE-320", "Key Management Errors",                "A02:2021 Cryptographic Failures",         "KMS key without automatic rotation"),
    # -- Container
    ("cont-cve-2023-001",      "Container OS CVE (glibc)",            "CVE-2023-6246", "CWE-120", "Buffer Overflow",                      "A06:2021 Vulnerable Components",          "Heap buffer overflow in glibc"),
    ("cont-cve-2024-001",      "Container OS CVE (openssl)",          "CVE-2024-0727", "CWE-476", "NULL Pointer Dereference",             "A06:2021 Vulnerable Components",          "NULL dereference in OpenSSL PKCS12"),
    ("cont-root-001",          "Container Running as Root",           None,             "CWE-250", "Execution with Unnecessary Privileges","A05:2021 Security Misconfiguration",      "Container process running as UID 0"),
    ("cont-no-healthcheck-001","Container Without Healthcheck",       None,             "CWE-693", "Protection Mechanism Failure",          "A05:2021 Security Misconfiguration",      "No HEALTHCHECK defined in Dockerfile"),
    # -- IaC
    ("iac-tf-sg-open-001",     "Terraform SG Open to World",          None,             "CWE-284", "Improper Access Control",              "A05:2021 Security Misconfiguration",      "Security group resource allows 0.0.0.0/0"),
    ("iac-tf-s3-logging-001",  "Terraform S3 Without Logging",        None,             "CWE-778", "Insufficient Logging",                 "A09:2021 Security Logging Failures",      "S3 bucket resource without access logging"),
    ("iac-tf-rds-backup-001",  "Terraform RDS Without Backup",        None,             "CWE-693", "Protection Mechanism Failure",          "A05:2021 Security Misconfiguration",      "RDS resource without backup retention"),
    # -- Secret Scan
    ("secret-aws-key-001",     "AWS Access Key in Code",              None,             "CWE-798", "Hardcoded Credentials",                "A07:2021 Identification Failures",        "AWS access key found in source code"),
    ("secret-private-key-001", "Private Key in Repository",           None,             "CWE-798", "Hardcoded Credentials",                "A07:2021 Identification Failures",        "RSA/EC private key found in repository"),
    ("secret-api-token-001",   "API Token in Code",                   None,             "CWE-798", "Hardcoded Credentials",                "A07:2021 Identification Failures",        "API token or bearer token in source"),
    # -- Pentest
    ("pt-auth-bypass-001",     "Authentication Bypass",               None,             "CWE-287", "Improper Authentication",              "A07:2021 Identification Failures",        "Authentication bypass via parameter manipulation"),
    ("pt-idor-001",            "Insecure Direct Object Reference",    None,             "CWE-639", "Authorization Bypass via User-Controlled Key", "A01:2021 Broken Access Control", "IDOR allowing access to other users' data"),
    ("pt-privesc-001",         "Privilege Escalation",                None,             "CWE-269", "Improper Privilege Management",        "A01:2021 Broken Access Control",          "Horizontal privilege escalation via role manipulation"),
    ("pt-info-disclosure-001", "Information Disclosure",              None,             "CWE-200", "Exposure of Sensitive Information",    "A01:2021 Broken Access Control",          "Stack traces and internal IPs exposed in error responses"),
]

# Mapeamento vuln_external_id → source names compatíveis
VULN_SOURCE_MAP = {
    "sast-":   ["Checkmarx SAST", "SonarQube", "Semgrep"],
    "dast-":   ["OWASP ZAP", "Burp Suite"],
    "sca-":    ["Snyk Open Source", "Trivy SCA", "Dependency-Check"],
    "cspm-":   ["Wiz", "Prowler", "AWS Security Hub"],
    "cont-":   ["Trivy Container", "Grype"],
    "iac-":    ["Checkov", "tfsec"],
    "secret-": ["Gitleaks", "TruffleHog"],
    "pt-":     ["Manual Pentest"],
}

# Quais assets são compatíveis com cada tipo de vuln
VULN_ASSET_MAP = {
    "sast-":   [a[0] for a in ASSETS if a[2] == "application"],
    "dast-":   [a[0] for a in ASSETS if a[2] == "application"],
    "sca-":    [a[0] for a in ASSETS if a[2] == "application"],
    "cspm-":   [a[0] for a in ASSETS if a[2] == "cloud_resource"],
    "cont-":   [a[0] for a in ASSETS if a[2] == "container"],
    "iac-":    [a[0] for a in ASSETS if a[2] in ("cloud_resource", "application")],
    "secret-": [a[0] for a in ASSETS if a[2] == "application"],
    "pt-":     [a[0] for a in ASSETS if a[2] in ("application", "host")],
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 0.10,
    "HIGH":     0.25,
    "MEDIUM":   0.35,
    "LOW":      0.20,
    "INFO":     0.10,
}

SEVERITIES = list(SEVERITY_WEIGHTS.keys())
SEVERITY_W = list(SEVERITY_WEIGHTS.values())

STATUS_TRANSITIONS = {
    "NEW":            ["CONFIRMED", "FALSE_POSITIVE"],
    "CONFIRMED":      ["IN_REMEDIATION", "ACCEPTED_RISK", "WONT_FIX"],
    "IN_REMEDIATION": ["FIXED", "CONFIRMED"],  # pode voltar
    "FIXED":          [],
    "ACCEPTED_RISK":  [],
    "FALSE_POSITIVE": [],
    "WONT_FIX":       [],
}

FILE_PATHS = [
    "src/controllers/UserController.java",
    "src/controllers/PaymentController.java",
    "src/services/AuthService.java",
    "src/services/OrderService.py",
    "src/db/QueryBuilder.py",
    "src/utils/Crypto.java",
    "src/api/routes/users.ts",
    "src/api/routes/payments.ts",
    "src/api/middleware/auth.ts",
    "src/views/Dashboard.tsx",
    "src/views/UserProfile.tsx",
    "lib/http_client.py",
    "app/models/user.rb",
    "app/controllers/sessions_controller.rb",
    "infra/terraform/main.tf",
    "infra/terraform/iam.tf",
    "infra/terraform/network.tf",
    "infra/cloudformation/template.yaml",
    "Dockerfile",
    "docker-compose.yml",
    ".env",
    "config/settings.py",
]

DAST_URLS = [
    "https://api.acme.com/v1/users",
    "https://api.acme.com/v1/payments",
    "https://api.acme.com/v1/auth/login",
    "https://portal.acme.com/dashboard",
    "https://admin.acme.com/settings",
    "https://api.acme.com/v1/reports",
    "https://api.acme.com/v1/search",
]

CLOUD_RESOURCES = [
    "arn:aws:s3:::acme-prod-data",
    "arn:aws:s3:::acme-prod-logs",
    "arn:aws:ec2:us-east-1:123456789012:security-group/sg-abc123",
    "arn:aws:rds:us-east-1:123456789012:db:acme-prod-db",
    "arn:aws:iam::123456789012:user/deploy-bot",
    "arn:aws:iam::123456789012:user/ci-runner",
    "arn:aws:ec2:us-east-1:123456789012:volume/vol-xyz789",
    "arn:aws:kms:us-east-1:123456789012:key/mrk-abc",
    "projects/acme-analytics/zones/us-central1-a/instances/etl-worker-01",
]

SCA_COMPONENTS = [
    ("log4j-core", "2.14.1"),
    ("spring-webmvc", "5.3.17"),
    ("jackson-databind", "2.9.10"),
    ("lodash", "4.17.19"),
    ("axios", "1.5.0"),
    ("express", "4.18.1"),
    ("openssl", "3.0.6"),
    ("glibc", "2.35-0ubuntu3"),
    ("libssl3", "3.0.2-0ubuntu1"),
]

START_DATE = date(2025, 10, 1)
END_DATE = date(2026, 4, 4)
NUM_FINDINGS = 3000
NUM_SCANS = 180  # ~1 scan/dia por 6 meses


# ============================================================
# Helpers
# ============================================================

def get_vuln_prefix(vuln_ext_id: str) -> str:
    for prefix in VULN_SOURCE_MAP:
        if vuln_ext_id.startswith(prefix):
            return prefix
    return ""


def random_date_between(start: date, end: date) -> date:
    delta = (end - start).days
    return start + timedelta(days=random.randint(0, delta))


def random_cvss(severity: str) -> float:
    ranges = {
        "CRITICAL": (9.0, 10.0),
        "HIGH":     (7.0, 8.9),
        "MEDIUM":   (4.0, 6.9),
        "LOW":      (0.1, 3.9),
        "INFO":     (0.0, 0.0),
    }
    lo, hi = ranges[severity]
    return round(random.uniform(lo, hi), 1)


# ============================================================
# Inserção de dimensões
# ============================================================

def insert_assets(cur):
    for a in ASSETS:
        cur.execute("""
            INSERT INTO dim_asset (asset_external_id, asset_name, asset_type, environment,
                                   team, business_unit, criticality, cloud_provider, repo_url)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (asset_external_id) DO NOTHING
        """, a)


def insert_vulnerabilities(cur):
    for v in VULNERABILITIES:
        cur.execute("""
            INSERT INTO dim_vulnerability (vuln_external_id, vuln_title, cve_id, cwe_id,
                                           cwe_name, owasp_category, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (vuln_external_id) DO NOTHING
        """, v)


# ============================================================
# Pré-carrega chaves de dimensão
# ============================================================

def load_dim_keys(cur) -> dict:
    keys = {}

    cur.execute("SELECT severity_key, severity_name FROM dim_severity")
    keys["severity"] = {row[1]: row[0] for row in cur.fetchall()}

    cur.execute("SELECT status_key, status_name FROM dim_status")
    keys["status"] = {row[1]: row[0] for row in cur.fetchall()}

    cur.execute("SELECT source_key, source_name FROM dim_source")
    keys["source"] = {row[1]: row[0] for row in cur.fetchall()}

    cur.execute("SELECT asset_key, asset_external_id FROM dim_asset")
    keys["asset"] = {row[1]: row[0] for row in cur.fetchall()}

    cur.execute("SELECT vuln_key, vuln_external_id FROM dim_vulnerability")
    keys["vuln"] = {row[1]: row[0] for row in cur.fetchall()}

    cur.execute("SELECT severity_name, sla_days FROM dim_severity")
    keys["sla"] = {row[0]: row[1] for row in cur.fetchall()}

    return keys


# ============================================================
# Geração de findings
# ============================================================

def generate_findings(cur, keys: dict):
    """Gera findings transacionais e constrói o snapshot acumulado."""

    # Estrutura para rastrear findings únicos e seu ciclo de vida
    finding_lifecycle: dict[str, dict] = {}
    scan_dates = sorted(set(
        random_date_between(START_DATE, END_DATE) for _ in range(NUM_SCANS)
    ))

    findings_inserted = 0

    for _ in range(NUM_FINDINGS):
        vuln = random.choice(VULNERABILITIES)
        vuln_ext_id = vuln[0]
        prefix = get_vuln_prefix(vuln_ext_id)

        # Seleciona asset e source compatíveis
        compatible_assets = VULN_ASSET_MAP.get(prefix, [])
        compatible_sources = VULN_SOURCE_MAP.get(prefix, [])
        if not compatible_assets or not compatible_sources:
            continue

        asset_ext_id = random.choice(compatible_assets)
        source_name = random.choice(compatible_sources)

        # Chave única do finding (vuln + asset + source)
        finding_id = f"{vuln_ext_id}::{asset_ext_id}::{source_name}::{uuid4().hex[:8]}"

        severity = random.choices(SEVERITIES, weights=SEVERITY_W, k=1)[0]
        cvss = random_cvss(severity)
        epss = round(random.uniform(0.0001, 0.95), 4) if severity in ("CRITICAL", "HIGH") else round(random.uniform(0.0001, 0.3), 4)

        detected_date = random.choice(scan_dates[:len(scan_dates) * 3 // 4])  # bias para detecção mais cedo
        scan_id = f"scan-{detected_date.isoformat()}-{source_name.replace(' ', '-').lower()}"

        # Status inicial
        status = "NEW"

        # Simular evolução do ciclo de vida
        days_since = (END_DATE - detected_date).days
        lifecycle = {
            "detected_date": detected_date,
            "triaged_date": None,
            "in_remediation_date": None,
            "fixed_date": None,
            "accepted_risk_date": None,
            "false_positive_date": None,
        }

        changes = []

        if days_since > 5 and random.random() < 0.7:
            status = "CONFIRMED"
            lifecycle["triaged_date"] = detected_date + timedelta(days=random.randint(1, 5))
            changes.append(("STATUS_CHANGE", "status", "NEW", "CONFIRMED", lifecycle["triaged_date"]))

            if days_since > 15 and random.random() < 0.6:
                status = "IN_REMEDIATION"
                lifecycle["in_remediation_date"] = lifecycle["triaged_date"] + timedelta(days=random.randint(3, 15))
                changes.append(("STATUS_CHANGE", "status", "CONFIRMED", "IN_REMEDIATION", lifecycle["in_remediation_date"]))

                if days_since > 30 and random.random() < 0.5:
                    status = "FIXED"
                    lifecycle["fixed_date"] = lifecycle["in_remediation_date"] + timedelta(days=random.randint(5, 30))
                    changes.append(("STATUS_CHANGE", "status", "IN_REMEDIATION", "FIXED", lifecycle["fixed_date"]))

            elif random.random() < 0.1:
                status = "ACCEPTED_RISK"
                lifecycle["accepted_risk_date"] = lifecycle["triaged_date"] + timedelta(days=random.randint(5, 20))
                changes.append(("STATUS_CHANGE", "status", "CONFIRMED", "ACCEPTED_RISK", lifecycle["accepted_risk_date"]))

            elif random.random() < 0.08:
                status = "FALSE_POSITIVE"
                lifecycle["false_positive_date"] = lifecycle["triaged_date"] + timedelta(days=random.randint(1, 5))
                changes.append(("STATUS_CHANGE", "status", "CONFIRMED", "FALSE_POSITIVE", lifecycle["false_positive_date"]))

        # Severity change (10% chance)
        if random.random() < 0.10 and days_since > 10:
            old_sev = severity
            severity = random.choice([s for s in SEVERITIES if s != old_sev])
            cvss = random_cvss(severity)
            change_date = detected_date + timedelta(days=random.randint(5, min(days_since, 30)))
            changes.append(("SEVERITY_CHANGE", "severity", old_sev, severity, change_date))

        # Dimensões degeneradas
        file_path = None
        line_number = None
        component_name = None
        component_version = None
        resource_id = None
        url = None

        if prefix in ("sast-", "iac-", "secret-"):
            file_path = random.choice(FILE_PATHS)
            line_number = random.randint(1, 500)
        elif prefix == "dast-":
            url = random.choice(DAST_URLS)
        elif prefix == "sca-":
            comp = random.choice(SCA_COMPONENTS)
            component_name = comp[0]
            component_version = comp[1]
        elif prefix == "cspm-":
            resource_id = random.choice(CLOUD_RESOURCES)
        elif prefix == "cont-":
            pass  # Degenerate dims já estão no asset name

        # --- INSERT fact_vulnerability_findings ---
        sla_limit = keys["sla"][severity]
        last_seen = lifecycle["fixed_date"] or END_DATE
        days_open = (last_seen - detected_date).days
        days_to_remediate = (lifecycle["fixed_date"] - detected_date).days if lifecycle["fixed_date"] else None

        cur.execute("""
            INSERT INTO fact_vulnerability_findings (
                finding_id, scan_id, detected_date,
                asset_key, vuln_key, severity_key, status_key, source_key,
                file_path, line_number, component_name, component_version,
                resource_id, url, cvss_score, epss_score, scan_completed_at
            ) VALUES (
                %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s, %s
            )
            ON CONFLICT (finding_id, scan_id) DO NOTHING
        """, (
            finding_id, scan_id, detected_date,
            keys["asset"][asset_ext_id],
            keys["vuln"][vuln_ext_id],
            keys["severity"][severity],
            keys["status"][status],
            keys["source"][source_name],
            file_path, line_number, component_name, component_version,
            resource_id, url, cvss, epss,
            detected_date,
        ))

        # --- INSERT fact_vulnerability_snapshot ---
        cur.execute("""
            INSERT INTO fact_vulnerability_snapshot (
                finding_id, asset_key, vuln_key, current_severity_key, current_status_key, source_key,
                detected_date, triaged_date, in_remediation_date, fixed_date,
                accepted_risk_date, false_positive_date,
                last_seen_date, first_scan_id, latest_scan_id,
                file_path, line_number, component_name, component_version,
                resource_id, url, cvss_score, epss_score,
                days_open, days_to_remediate, sla_days_limit, sla_breached, recurrence_count
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s, %s
            )
            ON CONFLICT (finding_id) DO NOTHING
        """, (
            finding_id,
            keys["asset"][asset_ext_id],
            keys["vuln"][vuln_ext_id],
            keys["severity"][severity],
            keys["status"][status],
            keys["source"][source_name],
            lifecycle["detected_date"],
            lifecycle["triaged_date"],
            lifecycle["in_remediation_date"],
            lifecycle["fixed_date"],
            lifecycle["accepted_risk_date"],
            lifecycle["false_positive_date"],
            last_seen,
            scan_id,
            scan_id,
            file_path, line_number, component_name, component_version,
            resource_id, url, cvss, epss,
            days_open, days_to_remediate, sla_limit, days_open > sla_limit, 0,
        ))

        # --- INSERT fact_vulnerability_changes ---
        for chg in changes:
            change_type, field, old_val, new_val, change_date = chg
            cur.execute("""
                INSERT INTO fact_vulnerability_changes
                    (finding_id, changed_at, change_type, field_changed, old_value, new_value, source_key)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                finding_id, change_date, change_type, field,
                old_val, new_val, keys["source"][source_name],
            ))

        findings_inserted += 1

    return findings_inserted


# ============================================================
# Main
# ============================================================

def main():
    print("🔌 Conectando ao banco...")
    conn = psycopg2.connect(DB_DSN)
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            print("📦 Inserindo assets...")
            insert_assets(cur)

            print("📦 Inserindo vulnerabilidades...")
            insert_vulnerabilities(cur)

            print("🔑 Carregando chaves de dimensão...")
            keys = load_dim_keys(cur)

            print(f"⚙️  Gerando {NUM_FINDINGS} findings...")
            count = generate_findings(cur, keys)

            conn.commit()
            print(f"✅ {count} findings inseridos com sucesso!")

            # Estatísticas
            cur.execute("SELECT COUNT(*) FROM fact_vulnerability_findings")
            print(f"   fact_vulnerability_findings:  {cur.fetchone()[0]} linhas")

            cur.execute("SELECT COUNT(*) FROM fact_vulnerability_snapshot")
            print(f"   fact_vulnerability_snapshot:   {cur.fetchone()[0]} linhas")

            cur.execute("SELECT COUNT(*) FROM fact_vulnerability_changes")
            print(f"   fact_vulnerability_changes:    {cur.fetchone()[0]} linhas")

            # Resumo por severidade
            cur.execute("""
                SELECT s.severity_name, COUNT(*),
                       COUNT(*) FILTER (WHERE st.is_open),
                       COUNT(*) FILTER (WHERE f.sla_breached)
                FROM fact_vulnerability_snapshot f
                JOIN dim_severity s ON s.severity_key = f.current_severity_key
                JOIN dim_status st ON st.status_key = f.current_status_key
                GROUP BY s.severity_name, s.severity_order
                ORDER BY s.severity_order
            """)
            print("\n📊 Resumo por severidade:")
            print(f"   {'Severidade':<12} {'Total':>8} {'Abertas':>8} {'SLA Break':>10}")
            for row in cur.fetchall():
                print(f"   {row[0]:<12} {row[1]:>8} {row[2]:>8} {row[3]:>10}")

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
