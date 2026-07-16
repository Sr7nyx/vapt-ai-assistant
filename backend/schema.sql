-- VAPT Assistant - Supabase Postgres schema (multi-tenant)
-- Run this once in the Supabase SQL editor. The API also ensures these on startup.

create table if not exists users (
    id         text primary key,          -- Google "sub"
    email      text default '',
    created_at timestamptz default now()
);

create table if not exists projects (
    id              bigserial primary key,
    user_id         text not null references users(id) on delete cascade,
    name            text not null,
    client          text default '',
    scope           text default '',
    tester          text default '',
    start_date      text default '',
    end_date        text default '',
    report_ref      text default 'SECTEST-XXXX',
    reviewer        text default '',
    assessment_type text default 'VAPT',
    environment     text default 'STG',
    created_at      text default ''
);
create index if not exists idx_projects_user on projects(user_id);

create table if not exists findings (
    id                 bigserial primary key,
    project_id         bigint not null references projects(id) on delete cascade,
    title              text default 'Untitled Finding',
    severity           text default 'Medium',
    cwe                text default '',
    cvss               text default '',
    category           text default '',
    status             text default 'Draft',
    environment        text default '',
    affected_host      text default '',
    affected_url       text default '',
    http_method        text default '',
    parameter          text default '',
    owner              text default '',
    description        text default '',
    evidence           text default '',
    evidence_files     text default '',
    impact             text default '',
    scenario           text default '',
    steps              text default '',
    remediation        text default '',
    fp_checks          text default '',
    retest_notes       text default '',
    additional_remarks text default '',
    references_data    text default '',
    retest_status      text default 'Not Retested',
    retest_round       integer default 0,
    retest_date        text default '',
    retester           text default '',
    retest_evidence    text default '',
    retest_history     text default '',
    original_severity  text default '',
    first_found_date   text default '',
    created_at         text default '',
    updated_at         text default ''
);
create index if not exists idx_findings_project on findings(project_id);

create table if not exists llm_usage (
    id                bigserial primary key,
    user_id           text default '',
    lane              text default '',
    model             text default '',
    prompt_tokens     integer default 0,
    completion_tokens integer default 0,
    total_tokens      integer default 0,
    created_at        timestamptz default now()
);
create index if not exists idx_usage_user on llm_usage(user_id);
