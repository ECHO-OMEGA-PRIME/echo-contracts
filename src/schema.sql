-- Echo Contracts v1.0.0 Schema
-- AI-powered contract management and e-signatures

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT,
  plan TEXT DEFAULT 'free',
  max_contracts INTEGER DEFAULT 10,
  company_name TEXT,
  company_address TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS contacts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  company TEXT,
  phone TEXT,
  role TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_contacts_tenant ON contacts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(tenant_id, email);

CREATE TABLE IF NOT EXISTS templates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  category TEXT,
  content_json TEXT NOT NULL DEFAULT '{}',
  variables_json TEXT DEFAULT '[]',
  is_public INTEGER DEFAULT 0,
  use_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_templates_tenant ON templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_templates_cat ON templates(tenant_id, category);

CREATE TABLE IF NOT EXISTS clauses (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT,
  content TEXT NOT NULL,
  is_standard INTEGER DEFAULT 0,
  risk_level TEXT DEFAULT 'low',
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_clauses_tenant ON clauses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_clauses_cat ON clauses(tenant_id, category);

CREATE TABLE IF NOT EXISTS contracts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  contract_number TEXT,
  title TEXT NOT NULL,
  description TEXT,
  type TEXT DEFAULT 'general',
  status TEXT DEFAULT 'draft',
  template_id TEXT,
  content_json TEXT DEFAULT '{}',
  variables_json TEXT DEFAULT '{}',
  counterparty_id TEXT,
  counterparty_name TEXT,
  value REAL DEFAULT 0,
  currency TEXT DEFAULT 'USD',
  start_date TEXT,
  end_date TEXT,
  renewal_type TEXT DEFAULT 'manual',
  renewal_notice_days INTEGER DEFAULT 30,
  auto_renew INTEGER DEFAULT 0,
  tags TEXT,
  owner_id TEXT,
  current_version INTEGER DEFAULT 1,
  signed_at TEXT,
  terminated_at TEXT,
  termination_reason TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (counterparty_id) REFERENCES contacts(id)
);
CREATE INDEX IF NOT EXISTS idx_contracts_tenant ON contracts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_contracts_status ON contracts(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_contracts_number ON contracts(tenant_id, contract_number);
CREATE INDEX IF NOT EXISTS idx_contracts_end ON contracts(tenant_id, end_date);
CREATE INDEX IF NOT EXISTS idx_contracts_counterparty ON contracts(counterparty_id);

CREATE TABLE IF NOT EXISTS contract_versions (
  id TEXT PRIMARY KEY,
  contract_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  content_json TEXT NOT NULL,
  change_summary TEXT,
  created_by TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (contract_id) REFERENCES contracts(id)
);
CREATE INDEX IF NOT EXISTS idx_versions_contract ON contract_versions(contract_id);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  contract_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  approver_name TEXT NOT NULL,
  approver_email TEXT,
  status TEXT DEFAULT 'pending',
  order_num INTEGER DEFAULT 0,
  comments TEXT,
  approved_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (contract_id) REFERENCES contracts(id)
);
CREATE INDEX IF NOT EXISTS idx_approvals_contract ON approvals(contract_id);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(tenant_id, status);

CREATE TABLE IF NOT EXISTS signatures (
  id TEXT PRIMARY KEY,
  contract_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  signer_name TEXT NOT NULL,
  signer_email TEXT NOT NULL,
  signer_role TEXT DEFAULT 'signer',
  status TEXT DEFAULT 'pending',
  token TEXT,
  ip_address TEXT,
  user_agent TEXT,
  signed_at TEXT,
  declined_at TEXT,
  decline_reason TEXT,
  reminder_count INTEGER DEFAULT 0,
  last_reminder_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (contract_id) REFERENCES contracts(id)
);
CREATE INDEX IF NOT EXISTS idx_sigs_contract ON signatures(contract_id);
CREATE INDEX IF NOT EXISTS idx_sigs_token ON signatures(token);
CREATE INDEX IF NOT EXISTS idx_sigs_email ON signatures(signer_email);

CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  contract_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  author_name TEXT NOT NULL,
  content TEXT NOT NULL,
  section_ref TEXT,
  is_resolved INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (contract_id) REFERENCES contracts(id)
);
CREATE INDEX IF NOT EXISTS idx_comments_contract ON comments(contract_id);

CREATE TABLE IF NOT EXISTS activity_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL,
  actor TEXT,
  details TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_activity_tenant ON activity_log(tenant_id);
