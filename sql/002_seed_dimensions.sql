-- ============================================================
-- CYBERMETRICS — Seed de Dimensões
-- Dados de referência que não dependem de fontes externas
-- ============================================================

-- ======================== dim_date ========================
-- Popula 2025-01-01 a 2027-12-31
INSERT INTO dim_date (full_date, year, quarter, month, month_name, week_of_year, day_of_month, day_of_week, day_name, is_weekend)
SELECT
    d::date,
    EXTRACT(YEAR FROM d)::SMALLINT,
    EXTRACT(QUARTER FROM d)::SMALLINT,
    EXTRACT(MONTH FROM d)::SMALLINT,
    TO_CHAR(d, 'Month'),
    EXTRACT(WEEK FROM d)::SMALLINT,
    EXTRACT(DAY FROM d)::SMALLINT,
    EXTRACT(DOW FROM d)::SMALLINT,
    TO_CHAR(d, 'Day'),
    EXTRACT(DOW FROM d) IN (0, 6)
FROM generate_series('2025-01-01'::date, '2027-12-31'::date, '1 day') d
ON CONFLICT (full_date) DO NOTHING;


-- ======================== dim_severity ========================
INSERT INTO dim_severity (severity_name, severity_order, sla_days) VALUES
    ('CRITICAL', 1, 7),
    ('HIGH',     2, 30),
    ('MEDIUM',   3, 90),
    ('LOW',      4, 180),
    ('INFO',     5, 365)
ON CONFLICT (severity_name) DO NOTHING;


-- ======================== dim_status ========================
INSERT INTO dim_status (status_name, status_category, is_open) VALUES
    ('NEW',              'open',       true),
    ('CONFIRMED',        'open',       true),
    ('IN_REMEDIATION',   'open',       true),
    ('FIXED',            'resolved',   false),
    ('ACCEPTED_RISK',    'suppressed', false),
    ('FALSE_POSITIVE',   'suppressed', false),
    ('WONT_FIX',         'suppressed', false)
ON CONFLICT (status_name) DO NOTHING;


-- ======================== dim_scan_type ========================
INSERT INTO dim_scan_type (scan_type_code, scan_type_name, description) VALUES
    ('SAST',            'Static Application Security Testing',  'Análise estática de código-fonte'),
    ('DAST',            'Dynamic Application Security Testing', 'Análise dinâmica de aplicações em execução'),
    ('SCA',             'Software Composition Analysis',        'Análise de dependências e bibliotecas open-source'),
    ('CSPM',            'Cloud Security Posture Management',    'Conformidade e postura de segurança em cloud'),
    ('PENTEST',         'Penetration Testing',                  'Testes de intrusão manuais ou semi-automatizados'),
    ('CONTAINER_SCAN',  'Container Image Scanning',             'Análise de vulnerabilidades em imagens de container'),
    ('IAC_SCAN',        'Infrastructure as Code Scanning',      'Análise de segurança em templates IaC (Terraform, CloudFormation)'),
    ('SECRET_SCAN',     'Secret Detection',                     'Detecção de segredos e credenciais em código')
ON CONFLICT (scan_type_code) DO NOTHING;


-- ======================== dim_source ========================
-- Cada ferramenta mapeada ao seu scan_type
INSERT INTO dim_source (source_name, tool_vendor, scan_type_key)
SELECT s.source_name, s.tool_vendor, st.scan_type_key
FROM (VALUES
    ('Checkmarx SAST',     'Checkmarx',        'SAST'),
    ('SonarQube',          'SonarSource',       'SAST'),
    ('Semgrep',            'Semgrep Inc',       'SAST'),
    ('OWASP ZAP',          'OWASP',             'DAST'),
    ('Burp Suite',         'PortSwigger',       'DAST'),
    ('Snyk Open Source',   'Snyk',              'SCA'),
    ('Trivy SCA',          'Aqua Security',     'SCA'),
    ('Dependency-Check',   'OWASP',             'SCA'),
    ('Wiz',                'Wiz',               'CSPM'),
    ('Prowler',            'Prowler',           'CSPM'),
    ('AWS Security Hub',   'AWS',               'CSPM'),
    ('Trivy Container',    'Aqua Security',     'CONTAINER_SCAN'),
    ('Grype',              'Anchore',           'CONTAINER_SCAN'),
    ('Checkov',            'Bridgecrew',        'IAC_SCAN'),
    ('tfsec',              'Aqua Security',     'IAC_SCAN'),
    ('Gitleaks',           'Gitleaks',          'SECRET_SCAN'),
    ('TruffleHog',         'Truffle Security',  'SECRET_SCAN'),
    ('Manual Pentest',     'Internal',          'PENTEST')
) AS s(source_name, tool_vendor, scan_type_code)
JOIN dim_scan_type st ON st.scan_type_code = s.scan_type_code
ON CONFLICT (source_name, scan_type_key) DO NOTHING;
