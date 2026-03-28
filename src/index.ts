/**
 * Echo Contracts v1.0.0 — AI-Powered Contract Management & E-Signatures
 * Cloudflare Worker with Hono, D1, KV, service bindings
 */
import { Hono } from 'hono';
import { cors } from 'hono/cors';

interface Env { DB: D1Database; CACHE: KVNamespace; ENGINE_RUNTIME: Fetcher; SHARED_BRAIN: Fetcher; ECHO_API_KEY?: string; }
interface RLState { c: number; t: number }

const app = new Hono<{ Bindings: Env }>();

// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});
app.use('*', cors({ origin: '*', allowMethods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'], allowHeaders: ['Content-Type','Authorization','X-Tenant-ID','X-Echo-API-Key'] }));

const uid = () => crypto.randomUUID();
const sanitize = (s: string, max = 10000) => s?.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').slice(0, max) ?? '';
const sanitizeBody = (o: Record<string, unknown>) => { const r: Record<string, unknown> = {}; for (const [k, v] of Object.entries(o)) r[k] = typeof v === 'string' ? sanitize(v) : v; return r; };
const tid = (c: any) => c.req.header('X-Tenant-ID') || c.req.query('tenant_id') || '';
const json = (d: unknown, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json' } });

// CORS headers (auto-added by Evolution Engine)
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Echo-API-Key',
};

function slog(level: 'info' | 'warn' | 'error', msg: string, data?: Record<string, unknown>) {
  const entry = { ts: new Date().toISOString(), level, worker: 'echo-contracts', version: '1.0.0', msg, ...data };
  if (level === 'error') console.error(JSON.stringify(entry));
  else console.log(JSON.stringify(entry));
}

async function rateLimit(kv: KVNamespace, key: string, limit: number, windowSec = 60): Promise<boolean> {
  const rlKey = `rl:${key}`; const now = Date.now();
  const raw = await kv.get(rlKey);
  if (!raw) { await kv.put(rlKey, JSON.stringify({ c: 1, t: now }), { expirationTtl: windowSec * 2 }); return false; }
  const st: RLState = JSON.parse(raw);
  const elapsed = (now - st.t) / 1000;
  const count = Math.max(0, st.c - (elapsed / windowSec) * limit) + 1;
  await kv.put(rlKey, JSON.stringify({ c: count, t: now }), { expirationTtl: windowSec * 2 });
  return count > limit;
}

app.use('*', async (c, next) => {
  const path = new URL(c.req.url).pathname;
  if (path === '/health' || path === '/status' || path.startsWith('/sign/')) return next();
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  const isWrite = ['POST','PUT','PATCH','DELETE'].includes(c.req.method);
  if (await rateLimit(c.env.CACHE, `${ip}:${isWrite ? 'w' : 'r'}`, isWrite ? 60 : 200)) return json({ error: 'Rate limited' }, 429);
  return next();
});

// Auth middleware — require API key for write operations (public signing exempt)
app.use('*', async (c, next) => {
  const method = c.req.method;
  const path = new URL(c.req.url).pathname;
  if (method === 'GET' || method === 'OPTIONS' || method === 'HEAD' || path === '/health' || path === '/status' || path.startsWith('/sign/')) return next();
  const apiKey = c.req.header('X-Echo-API-Key') || '';
  const bearer = (c.req.header('Authorization') || '').replace('Bearer ', '');
  const expected = c.env.ECHO_API_KEY;
  if (!expected || (apiKey !== expected && bearer !== expected)) {
    return json({ error: 'Unauthorized', message: 'Valid X-Echo-API-Key or Bearer token required for write operations' }, 401);
  }
  return next();
});

app.get('/', (c) => c.redirect('/health'));
app.get('/health', (c) => json({ status: 'ok', service: 'echo-contracts', version: '1.0.0', time: new Date().toISOString() }));

// ═══════════════ TENANTS ═══════════════
app.post('/tenants', async (c) => {
  const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO tenants (id,name,email,plan,company_name,company_address) VALUES (?,?,?,?,?,?)').bind(id, b.name, b.email||null, b.plan||'free', b.company_name||null, b.company_address||null).run();
  return json({ id }, 201);
});
app.get('/tenants/:id', async (c) => {
  const r = await c.env.DB.prepare('SELECT * FROM tenants WHERE id=?').bind(c.req.param('id')).first();
  return r ? json(r) : json({ error: 'Not found' }, 404);
});

// ═══════════════ CONTACTS ═══════════════
app.get('/contacts', async (c) => {
  const search = c.req.query('q');
  let q = 'SELECT * FROM contacts WHERE tenant_id=?'; const p: unknown[] = [tid(c)];
  if (search) { q += ' AND (name LIKE ? OR email LIKE ? OR company LIKE ?)'; const s = `%${sanitize(search,100)}%`; p.push(s,s,s); }
  q += ' ORDER BY name LIMIT 200'; return json((await c.env.DB.prepare(q).bind(...p).all()).results);
});
app.post('/contacts', async (c) => {
  const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO contacts (id,tenant_id,name,email,company,phone,role,notes) VALUES (?,?,?,?,?,?,?,?)').bind(id, tid(c), b.name, b.email||null, b.company||null, b.phone||null, b.role||null, b.notes||null).run();
  return json({ id }, 201);
});

// ═══════════════ TEMPLATES ═══════════════
app.get('/templates', async (c) => {
  const cat = c.req.query('category');
  let q = 'SELECT * FROM templates WHERE tenant_id=?'; const p: unknown[] = [tid(c)];
  if (cat) { q += ' AND category=?'; p.push(cat); }
  q += ' ORDER BY use_count DESC, name'; return json((await c.env.DB.prepare(q).bind(...p).all()).results);
});
app.post('/templates', async (c) => {
  const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO templates (id,tenant_id,name,description,category,content_json,variables_json) VALUES (?,?,?,?,?,?,?)').bind(id, tid(c), b.name, b.description||null, b.category||null, typeof b.content === 'object' ? JSON.stringify(b.content) : b.content_json||'{}', typeof b.variables === 'object' ? JSON.stringify(b.variables) : b.variables_json||'[]').run();
  return json({ id }, 201);
});
app.get('/templates/:id', async (c) => {
  const r = await c.env.DB.prepare('SELECT * FROM templates WHERE id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).first();
  return r ? json(r) : json({ error: 'Not found' }, 404);
});

// ═══════════════ CLAUSE LIBRARY ═══════════════
app.get('/clauses', async (c) => {
  const cat = c.req.query('category'); const risk = c.req.query('risk_level');
  let q = 'SELECT * FROM clauses WHERE tenant_id=?'; const p: unknown[] = [tid(c)];
  if (cat) { q += ' AND category=?'; p.push(cat); }
  if (risk) { q += ' AND risk_level=?'; p.push(risk); }
  q += ' ORDER BY name'; return json((await c.env.DB.prepare(q).bind(...p).all()).results);
});
app.post('/clauses', async (c) => {
  const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO clauses (id,tenant_id,name,category,content,is_standard,risk_level,notes) VALUES (?,?,?,?,?,?,?,?)').bind(id, tid(c), b.name, b.category||null, b.content, b.is_standard ? 1 : 0, b.risk_level||'low', b.notes||null).run();
  return json({ id }, 201);
});

// ═══════════════ CONTRACTS ═══════════════
app.get('/contracts', async (c) => {
  const t = tid(c); const status = c.req.query('status'); const type = c.req.query('type'); const search = c.req.query('q');
  let q = 'SELECT c.*, co.name as counterparty_contact_name FROM contracts c LEFT JOIN contacts co ON c.counterparty_id=co.id WHERE c.tenant_id=?'; const p: unknown[] = [t];
  if (status) { q += ' AND c.status=?'; p.push(status); }
  if (type) { q += ' AND c.type=?'; p.push(type); }
  if (search) { q += ' AND (c.title LIKE ? OR c.contract_number LIKE ? OR c.counterparty_name LIKE ?)'; const s = `%${sanitize(search,100)}%`; p.push(s,s,s); }
  q += ' ORDER BY c.updated_at DESC LIMIT 200'; return json((await c.env.DB.prepare(q).bind(...p).all()).results);
});
app.get('/contracts/:id', async (c) => {
  const r = await c.env.DB.prepare('SELECT c.*, co.name as counterparty_contact_name, co.email as counterparty_email FROM contracts c LEFT JOIN contacts co ON c.counterparty_id=co.id WHERE c.id=? AND c.tenant_id=?').bind(c.req.param('id'), tid(c)).first();
  return r ? json(r) : json({ error: 'Not found' }, 404);
});
app.post('/contracts', async (c) => {
  const b = sanitizeBody(await c.req.json()); const id = uid(); const t = tid(c);
  const num = b.contract_number || `CTR-${Date.now().toString(36).toUpperCase()}`;
  let contentJson = b.content_json || '{}';
  // If creating from template, copy template content
  if (b.template_id) {
    const tpl = await c.env.DB.prepare('SELECT content_json FROM templates WHERE id=? AND tenant_id=?').bind(b.template_id, t).first() as any;
    if (tpl) { contentJson = tpl.content_json; await c.env.DB.prepare('UPDATE templates SET use_count=use_count+1 WHERE id=?').bind(b.template_id).run(); }
  }
  await c.env.DB.prepare('INSERT INTO contracts (id,tenant_id,contract_number,title,description,type,status,template_id,content_json,variables_json,counterparty_id,counterparty_name,value,currency,start_date,end_date,renewal_type,renewal_notice_days,auto_renew,tags,owner_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id, t, num, b.title, b.description||null, b.type||'general', 'draft', b.template_id||null, typeof b.content === 'object' ? JSON.stringify(b.content) : contentJson, typeof b.variables === 'object' ? JSON.stringify(b.variables) : b.variables_json||'{}', b.counterparty_id||null, b.counterparty_name||null, b.value||0, b.currency||'USD', b.start_date||null, b.end_date||null, b.renewal_type||'manual', b.renewal_notice_days||30, b.auto_renew ? 1 : 0, b.tags||null, b.owner_id||null).run();
  // Create v1
  await c.env.DB.prepare('INSERT INTO contract_versions (id,contract_id,tenant_id,version,content_json,change_summary,created_by) VALUES (?,?,?,1,?,?,?)').bind(uid(), id, t, typeof b.content === 'object' ? JSON.stringify(b.content) : contentJson, 'Initial draft', b.owner_id||'system').run();
  return json({ id, contract_number: num }, 201);
});
app.put('/contracts/:id', async (c) => {
  const b = sanitizeBody(await c.req.json()); const cid = c.req.param('id'); const t = tid(c);
  await c.env.DB.prepare("UPDATE contracts SET title=COALESCE(?,title),description=COALESCE(?,description),type=COALESCE(?,type),content_json=COALESCE(?,content_json),variables_json=COALESCE(?,variables_json),counterparty_id=COALESCE(?,counterparty_id),counterparty_name=COALESCE(?,counterparty_name),value=COALESCE(?,value),start_date=COALESCE(?,start_date),end_date=COALESCE(?,end_date),renewal_type=COALESCE(?,renewal_type),tags=COALESCE(?,tags),updated_at=datetime('now') WHERE id=? AND tenant_id=?").bind(b.title||null, b.description||null, b.type||null, typeof b.content === 'object' ? JSON.stringify(b.content) : b.content_json||null, typeof b.variables === 'object' ? JSON.stringify(b.variables) : b.variables_json||null, b.counterparty_id||null, b.counterparty_name||null, b.value||null, b.start_date||null, b.end_date||null, b.renewal_type||null, b.tags||null, cid, t).run();
  // Create new version if content changed
  if (b.content || b.content_json) {
    const contract = await c.env.DB.prepare('SELECT current_version FROM contracts WHERE id=?').bind(cid).first() as any;
    const newVersion = (contract?.current_version || 1) + 1;
    await c.env.DB.batch([
      c.env.DB.prepare('INSERT INTO contract_versions (id,contract_id,tenant_id,version,content_json,change_summary,created_by) VALUES (?,?,?,?,?,?,?)').bind(uid(), cid, t, newVersion, typeof b.content === 'object' ? JSON.stringify(b.content) : b.content_json, b.change_summary||'Updated', b.updated_by||'system'),
      c.env.DB.prepare('UPDATE contracts SET current_version=? WHERE id=?').bind(newVersion, cid),
    ]);
  }
  return json({ updated: true });
});

// Contract lifecycle
app.post('/contracts/:id/submit', async (c) => {
  await c.env.DB.prepare("UPDATE contracts SET status='review',updated_at=datetime('now') WHERE id=? AND tenant_id=? AND status='draft'").bind(c.req.param('id'), tid(c)).run();
  return json({ submitted: true });
});
app.post('/contracts/:id/send', async (c) => {
  await c.env.DB.prepare("UPDATE contracts SET status='sent',updated_at=datetime('now') WHERE id=? AND tenant_id=?").bind(c.req.param('id'), tid(c)).run();
  return json({ sent: true });
});
app.post('/contracts/:id/execute', async (c) => {
  await c.env.DB.prepare("UPDATE contracts SET status='active',signed_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND tenant_id=?").bind(c.req.param('id'), tid(c)).run();
  return json({ executed: true });
});
app.post('/contracts/:id/terminate', async (c) => {
  const b = sanitizeBody(await c.req.json());
  await c.env.DB.prepare("UPDATE contracts SET status='terminated',terminated_at=datetime('now'),termination_reason=?,updated_at=datetime('now') WHERE id=? AND tenant_id=?").bind(b.reason||null, c.req.param('id'), tid(c)).run();
  return json({ terminated: true });
});
app.post('/contracts/:id/clone', async (c) => {
  const orig = await c.env.DB.prepare('SELECT * FROM contracts WHERE id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).first() as any;
  if (!orig) return json({ error: 'Not found' }, 404);
  const id = uid(); const num = `CTR-${Date.now().toString(36).toUpperCase()}`;
  await c.env.DB.prepare('INSERT INTO contracts (id,tenant_id,contract_number,title,description,type,status,template_id,content_json,variables_json,counterparty_id,counterparty_name,value,currency,renewal_type,renewal_notice_days,owner_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id, tid(c), num, `${orig.title} (Copy)`, orig.description, orig.type, 'draft', orig.template_id, orig.content_json, orig.variables_json, orig.counterparty_id, orig.counterparty_name, orig.value, orig.currency, orig.renewal_type, orig.renewal_notice_days, orig.owner_id).run();
  return json({ id, contract_number: num }, 201);
});

// Versions
app.get('/contracts/:id/versions', async (c) => {
  return json((await c.env.DB.prepare('SELECT id,version,change_summary,created_by,created_at FROM contract_versions WHERE contract_id=? AND tenant_id=? ORDER BY version DESC').bind(c.req.param('id'), tid(c)).all()).results);
});
app.get('/contracts/:id/versions/:version', async (c) => {
  const r = await c.env.DB.prepare('SELECT * FROM contract_versions WHERE contract_id=? AND version=? AND tenant_id=?').bind(c.req.param('id'), parseInt(c.req.param('version')), tid(c)).first();
  return r ? json(r) : json({ error: 'Not found' }, 404);
});

// ═══════════════ APPROVALS ═══════════════
app.get('/contracts/:id/approvals', async (c) => {
  return json((await c.env.DB.prepare('SELECT * FROM approvals WHERE contract_id=? AND tenant_id=? ORDER BY order_num').bind(c.req.param('id'), tid(c)).all()).results);
});
app.post('/contracts/:id/approvals', async (c) => {
  const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO approvals (id,contract_id,tenant_id,approver_name,approver_email,order_num) VALUES (?,?,?,?,?,?)').bind(id, c.req.param('id'), tid(c), b.approver_name, b.approver_email||null, b.order_num||0).run();
  return json({ id }, 201);
});
app.post('/approvals/:id/approve', async (c) => {
  const b = sanitizeBody(await c.req.json());
  await c.env.DB.prepare("UPDATE approvals SET status='approved',comments=?,approved_at=datetime('now') WHERE id=? AND tenant_id=?").bind(b.comments||null, c.req.param('id'), tid(c)).run();
  return json({ approved: true });
});
app.post('/approvals/:id/reject', async (c) => {
  const b = sanitizeBody(await c.req.json());
  await c.env.DB.prepare("UPDATE approvals SET status='rejected',comments=?,approved_at=datetime('now') WHERE id=? AND tenant_id=?").bind(b.comments||null, c.req.param('id'), tid(c)).run();
  return json({ rejected: true });
});

// ═══════════════ SIGNATURES ═══════════════
app.get('/contracts/:id/signatures', async (c) => {
  return json((await c.env.DB.prepare('SELECT * FROM signatures WHERE contract_id=? AND tenant_id=? ORDER BY created_at').bind(c.req.param('id'), tid(c)).all()).results);
});
app.post('/contracts/:id/signatures', async (c) => {
  const b = sanitizeBody(await c.req.json()); const id = uid();
  const token = crypto.randomUUID().replace(/-/g, '');
  await c.env.DB.prepare('INSERT INTO signatures (id,contract_id,tenant_id,signer_name,signer_email,signer_role,token) VALUES (?,?,?,?,?,?,?)').bind(id, c.req.param('id'), tid(c), b.signer_name, b.signer_email, b.signer_role||'signer', token).run();
  return json({ id, sign_url: `/sign/${token}` }, 201);
});
// Public signing endpoint (no tenant auth needed)
app.get('/sign/:token', async (c) => {
  const sig = await c.env.DB.prepare('SELECT s.*, ct.title as contract_title, ct.content_json FROM signatures s JOIN contracts ct ON s.contract_id=ct.id WHERE s.token=? AND s.status=\'pending\'').bind(c.req.param('token')).first();
  return sig ? json(sig) : json({ error: 'Invalid or already signed' }, 404);
});
app.post('/sign/:token', async (c) => {
  const sig = await c.env.DB.prepare("SELECT * FROM signatures WHERE token=? AND status='pending'").bind(c.req.param('token')).first() as any;
  if (!sig) return json({ error: 'Invalid or already signed' }, 404);
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  const ua = c.req.header('user-agent') || 'unknown';
  // Batch sign + pending check atomically to prevent race condition with concurrent signers
  const results = await c.env.DB.batch([
    c.env.DB.prepare("UPDATE signatures SET status='signed',ip_address=?,user_agent=?,signed_at=datetime('now') WHERE id=? AND status='pending'").bind(ip, ua, sig.id),
    c.env.DB.prepare("SELECT COUNT(*) as c FROM signatures WHERE contract_id=? AND status='pending'").bind(sig.contract_id),
  ]);
  // Verify the signature update actually happened (prevent double-sign)
  const signResult = results[0] as D1Result;
  if (!signResult.meta?.changes) return json({ error: 'Already signed' }, 409);
  const pending = (results[1] as D1Result<{ c: number }>).results?.[0];
  const allSigned = pending?.c === 0;
  if (allSigned) {
    await c.env.DB.prepare("UPDATE contracts SET status='active',signed_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND status!='active'").bind(sig.contract_id).run();
  }
  return json({ signed: true, all_signed: allSigned });
});
app.post('/sign/:token/decline', async (c) => {
  const b = sanitizeBody(await c.req.json());
  await c.env.DB.prepare("UPDATE signatures SET status='declined',decline_reason=?,declined_at=datetime('now') WHERE token=? AND status='pending'").bind(b.reason||null, c.req.param('token')).run();
  return json({ declined: true });
});
app.post('/contracts/:id/remind-signers', async (c) => {
  const updated = await c.env.DB.prepare("UPDATE signatures SET reminder_count=reminder_count+1,last_reminder_at=datetime('now') WHERE contract_id=? AND tenant_id=? AND status='pending'").bind(c.req.param('id'), tid(c)).run();
  return json({ reminders_sent: updated.meta.changes });
});

// ═══════════════ COMMENTS ═══════════════
app.get('/contracts/:id/comments', async (c) => {
  return json((await c.env.DB.prepare('SELECT * FROM comments WHERE contract_id=? AND tenant_id=? ORDER BY created_at').bind(c.req.param('id'), tid(c)).all()).results);
});
app.post('/contracts/:id/comments', async (c) => {
  const b = sanitizeBody(await c.req.json()); const id = uid();
  await c.env.DB.prepare('INSERT INTO comments (id,contract_id,tenant_id,author_name,content,section_ref) VALUES (?,?,?,?,?,?)').bind(id, c.req.param('id'), tid(c), b.author_name, b.content, b.section_ref||null).run();
  return json({ id }, 201);
});
app.post('/comments/:id/resolve', async (c) => {
  await c.env.DB.prepare('UPDATE comments SET is_resolved=1 WHERE id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).run();
  return json({ resolved: true });
});

// ═══════════════ ANALYTICS ═══════════════
app.get('/analytics/overview', async (c) => {
  const t = tid(c);
  const [stats, valueByStatus, expiringContracts] = await Promise.all([
    c.env.DB.prepare("SELECT COUNT(*) as total, COUNT(CASE WHEN status='draft' THEN 1 END) as drafts, COUNT(CASE WHEN status='review' THEN 1 END) as in_review, COUNT(CASE WHEN status='sent' THEN 1 END) as sent, COUNT(CASE WHEN status='active' THEN 1 END) as active, COUNT(CASE WHEN status='expired' THEN 1 END) as expired, SUM(CASE WHEN status='active' THEN value ELSE 0 END) as active_value FROM contracts WHERE tenant_id=?").bind(t).first(),
    c.env.DB.prepare("SELECT status, SUM(value) as total_value, COUNT(*) as count FROM contracts WHERE tenant_id=? GROUP BY status").bind(t).all(),
    c.env.DB.prepare("SELECT id,title,contract_number,counterparty_name,end_date,value FROM contracts WHERE tenant_id=? AND status='active' AND end_date <= date('now','+30 days') AND end_date >= date('now') ORDER BY end_date LIMIT 20").bind(t).all(),
  ]);
  return json({ stats, value_by_status: valueByStatus.results, expiring_soon: expiringContracts.results });
});
app.get('/analytics/expiry-calendar', async (c) => {
  const t = tid(c); const months = parseInt(c.req.query('months') || '6');
  return json((await c.env.DB.prepare(`SELECT id,title,contract_number,counterparty_name,end_date,value,auto_renew FROM contracts WHERE tenant_id=? AND status='active' AND end_date IS NOT NULL AND end_date <= date('now','+'||?||' months') ORDER BY end_date`).bind(t, months).all()).results);
});

// ═══════════════ AI ═══════════════
app.post('/ai/risk-analysis', async (c) => {
  const b = await c.req.json() as { contract_id: string }; const t = tid(c);
  try {
    const contract = await c.env.DB.prepare('SELECT * FROM contracts WHERE id=? AND tenant_id=?').bind(b.contract_id, t).first() as any;
    if (!contract) return json({ error: 'Not found' }, 404);
    const aiRes = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ engine_id: 'LG-01', query: `Analyze contract risk: Title "${contract.title}", type: ${contract.type}, value: $${contract.value}, counterparty: ${contract.counterparty_name}, start: ${contract.start_date}, end: ${contract.end_date}, renewal: ${contract.renewal_type}. Content: ${contract.content_json?.substring(0, 3000)}. Identify risk factors, missing clauses, and recommendations.` }) });
    const ai = await aiRes.json() as any;
    return json({ contract_title: contract.title, analysis: ai.response || ai });
  } catch { return json({ analysis: 'AI unavailable' }); }
});
app.post('/ai/clause-suggestions', async (c) => {
  const b = await c.req.json() as { contract_type: string; existing_clauses?: string };
  try {
    const aiRes = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ engine_id: 'LG-01', query: `Suggest essential clauses for a ${b.contract_type} contract. ${b.existing_clauses ? `Already included: ${b.existing_clauses}` : ''} Recommend missing clauses with standard language, risk level, and importance.` }) });
    const ai = await aiRes.json() as any;
    return json({ suggestions: ai.response || ai });
  } catch { return json({ suggestions: 'AI unavailable' }); }
});

// ═══════════════ ACTIVITY LOG ═══════════════
app.get('/activity', async (c) => {
  return json((await c.env.DB.prepare('SELECT * FROM activity_log WHERE tenant_id=? ORDER BY created_at DESC LIMIT 100').bind(tid(c)).all()).results);
});

app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  console.error(`[echo-contracts] ${err.message}`);
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    // Mark expired contracts
    await env.DB.prepare("UPDATE contracts SET status='expired',updated_at=datetime('now') WHERE status='active' AND end_date < date('now') AND auto_renew=0").run();
    // Clean old activity logs
    await env.DB.prepare("DELETE FROM activity_log WHERE created_at < datetime('now','-90 days')").run();
  }
};
