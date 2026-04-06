-- ============================================================
-- CYBERMETRICS — Star Schema para Métricas de Vulnerabilidades
-- PostgreSQL 16+
-- ============================================================

-- ======================== DIMENSÕES ========================

CREATE TABLE IF NOT EXISTS dim_date (
    date_key        SERIAL PRIMARY KEY,
    full_date       DATE NOT NULL UNIQUE,
    year            SMALLINT NOT NULL,
    quarter         SMALLINT NOT NULL,
    month           SMALLINT NOT NULL,
    month_name      VARCHAR(20) NOT NULL,
    week_of_year    SMALLINT NOT NULL,
    day_of_month    SMALLINT NOT NULL,
    day_of_week     SMALLINT NOT NULL,   -- 0=domingo
    day_name        VARCHAR(20) NOT NULL,
    is_weekend      BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS dim_severity (
    severity_key    SERIAL PRIMARY KEY,
    severity_name   VARCHAR(20) NOT NULL UNIQUE,
    severity_order  SMALLINT NOT NULL,    -- 1=CRITICAL ... 5=INFO (para ORDER BY)
    sla_days        INT NOT NULL          -- SLA padrão em dias para remediação
);

CREATE TABLE IF NOT EXISTS dim_status (
    status_key      SERIAL PRIMARY KEY,
    status_name     VARCHAR(50) NOT NULL UNIQUE,
    status_category VARCHAR(20) NOT NULL, -- 'open', 'resolved', 'suppressed'
    is_open         BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS dim_scan_type (
    scan_type_key   SERIAL PRIMARY KEY,
    scan_type_code  VARCHAR(30) NOT NULL UNIQUE,
    scan_type_name  VARCHAR(100) NOT NULL,
    description     TEXT
);

CREATE TABLE IF NOT EXISTS dim_source (
    source_key      SERIAL PRIMARY KEY,
    source_name     VARCHAR(100) NOT NULL,
    tool_vendor     VARCHAR(100),
    scan_type_key   INT NOT NULL REFERENCES dim_scan_type(scan_type_key),
    UNIQUE(source_name, scan_type_key)
);

CREATE TABLE IF NOT EXISTS dim_asset (
    asset_key           SERIAL PRIMARY KEY,
    asset_external_id   VARCHAR(200) NOT NULL UNIQUE,
    asset_name          VARCHAR(255) NOT NULL,
    asset_type          VARCHAR(50) NOT NULL,       -- 'application','host','container','cloud_resource'
    environment         VARCHAR(50),                -- 'production','staging','development'
    team                VARCHAR(100),
    business_unit       VARCHAR(100),
    criticality         VARCHAR(20) DEFAULT 'medium', -- 'critical','high','medium','low'
    cloud_provider      VARCHAR(50),                  -- 'aws','azure','gcp', NULL
    repo_url            VARCHAR(500)
);

CREATE TABLE IF NOT EXISTS dim_vulnerability (
    vuln_key            SERIAL PRIMARY KEY,
    vuln_external_id    VARCHAR(200) NOT NULL UNIQUE,
    vuln_title          VARCHAR(500) NOT NULL,
    cve_id              VARCHAR(20),
    cwe_id              VARCHAR(20),
    cwe_name            VARCHAR(255),
    owasp_category      VARCHAR(200),
    description         TEXT
);


-- ======================== FATOS ========================

-- TRANSACIONAL: 1 linha por finding detectado em 1 scan
-- Grain: (finding_id, scan_id)
CREATE TABLE IF NOT EXISTS fact_vulnerability_findings (
    finding_key         BIGSERIAL PRIMARY KEY,

    -- Identificadores do sistema de origem
    finding_id          VARCHAR(200) NOT NULL,
    scan_id             VARCHAR(200),

    -- Chaves de dimensão
    detected_date       DATE NOT NULL,
    asset_key           INT NOT NULL REFERENCES dim_asset(asset_key),
    vuln_key            INT NOT NULL REFERENCES dim_vulnerability(vuln_key),
    severity_key        INT NOT NULL REFERENCES dim_severity(severity_key),
    status_key          INT NOT NULL REFERENCES dim_status(status_key),
    source_key          INT NOT NULL REFERENCES dim_source(source_key),

    -- Dimensões degeneradas (contexto específico por tipo de scan)
    file_path           VARCHAR(500),         -- SAST, IaC
    line_number         INT,                  -- SAST
    component_name      VARCHAR(255),         -- SCA
    component_version   VARCHAR(100),         -- SCA
    resource_id         VARCHAR(500),         -- CSPM, cloud
    url                 VARCHAR(1000),        -- DAST

    -- Medidas
    cvss_score          NUMERIC(4,1),
    epss_score          NUMERIC(5,4),

    -- Metadados de carga
    scan_completed_at   TIMESTAMPTZ,
    loaded_at           TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(finding_id, scan_id)
);

-- ACCUMULATING SNAPSHOT: 1 linha por finding, atualizada conforme ciclo de vida
-- Grain: (finding_id)
CREATE TABLE IF NOT EXISTS fact_vulnerability_snapshot (
    snapshot_key            BIGSERIAL PRIMARY KEY,
    finding_id              VARCHAR(200) NOT NULL UNIQUE,

    -- Chaves de dimensão (estado atual)
    asset_key               INT NOT NULL REFERENCES dim_asset(asset_key),
    vuln_key                INT NOT NULL REFERENCES dim_vulnerability(vuln_key),
    current_severity_key    INT NOT NULL REFERENCES dim_severity(severity_key),
    current_status_key      INT NOT NULL REFERENCES dim_status(status_key),
    source_key              INT NOT NULL REFERENCES dim_source(source_key),

    -- Marcos do ciclo de vida (NULL = ainda não atingiu esse estágio)
    detected_date           DATE NOT NULL,
    triaged_date            DATE,
    in_remediation_date     DATE,
    fixed_date              DATE,
    accepted_risk_date      DATE,
    false_positive_date     DATE,

    -- Rastreamento
    last_seen_date          DATE NOT NULL,
    first_scan_id           VARCHAR(200),
    latest_scan_id          VARCHAR(200),

    -- Dimensões degeneradas (valor mais recente)
    file_path               VARCHAR(500),
    line_number             INT,
    component_name          VARCHAR(255),
    component_version       VARCHAR(100),
    resource_id             VARCHAR(500),
    url                     VARCHAR(1000),

    -- Medidas
    cvss_score              NUMERIC(4,1),
    epss_score              NUMERIC(5,4),
    days_open               INT,
    days_to_remediate       INT,         -- preenchido só quando fixed_date IS NOT NULL
    sla_days_limit          INT,
    sla_breached            BOOLEAN,
    recurrence_count        INT DEFAULT 0,

    -- Metadados
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW()
);

-- CHANGE LOG: registra transições de estado para auditoria e análise
CREATE TABLE IF NOT EXISTS fact_vulnerability_changes (
    change_key      BIGSERIAL PRIMARY KEY,
    finding_id      VARCHAR(200) NOT NULL,
    changed_at      DATE NOT NULL,
    change_type     VARCHAR(50) NOT NULL,  -- 'STATUS_CHANGE','SEVERITY_CHANGE','REOPEN','REASSIGNMENT'
    field_changed   VARCHAR(50) NOT NULL,
    old_value       VARCHAR(255),
    new_value       VARCHAR(255),
    source_key      INT REFERENCES dim_source(source_key),
    loaded_at       TIMESTAMPTZ DEFAULT NOW()
);


-- ======================== ÍNDICES ========================

-- fact_vulnerability_findings
CREATE INDEX IF NOT EXISTS idx_findings_detected_date ON fact_vulnerability_findings(detected_date);
CREATE INDEX IF NOT EXISTS idx_findings_asset         ON fact_vulnerability_findings(asset_key);
CREATE INDEX IF NOT EXISTS idx_findings_severity      ON fact_vulnerability_findings(severity_key);
CREATE INDEX IF NOT EXISTS idx_findings_status        ON fact_vulnerability_findings(status_key);
CREATE INDEX IF NOT EXISTS idx_findings_source        ON fact_vulnerability_findings(source_key);

-- fact_vulnerability_snapshot
CREATE INDEX IF NOT EXISTS idx_snapshot_detected      ON fact_vulnerability_snapshot(detected_date);
CREATE INDEX IF NOT EXISTS idx_snapshot_status        ON fact_vulnerability_snapshot(current_status_key);
CREATE INDEX IF NOT EXISTS idx_snapshot_severity      ON fact_vulnerability_snapshot(current_severity_key);
CREATE INDEX IF NOT EXISTS idx_snapshot_asset         ON fact_vulnerability_snapshot(asset_key);
CREATE INDEX IF NOT EXISTS idx_snapshot_last_seen     ON fact_vulnerability_snapshot(last_seen_date);
CREATE INDEX IF NOT EXISTS idx_snapshot_sla           ON fact_vulnerability_snapshot(sla_breached) WHERE sla_breached = true;

-- fact_vulnerability_changes
CREATE INDEX IF NOT EXISTS idx_changes_finding        ON fact_vulnerability_changes(finding_id);
CREATE INDEX IF NOT EXISTS idx_changes_date           ON fact_vulnerability_changes(changed_at);
CREATE INDEX IF NOT EXISTS idx_changes_type           ON fact_vulnerability_changes(change_type);
