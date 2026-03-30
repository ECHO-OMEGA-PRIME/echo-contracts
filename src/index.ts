/**
 * Echo Contracts v2.0.0 — AI-Powered Contract Management, E-Signatures & Stripe Payments
 * Cloudflare Worker with Hono, D1, KV, service bindings
 */
import { Hono } from 'hono';
import { cors } from 'hono/cors';

interface Env { DB: D1Database; CACHE: KVNamespace; ENGINE_RUNTIME: Fetcher; SHARED_BRAIN: Fetcher; EMAIL_SENDER: Fetcher; ECHO_API_KEY?: string; STRIPE_SECRET_KEY?: string; STRIPE_WEBHOOK_SECRET?: string; CONTRACT_HMAC_KEY?: string; SITE_URL?: string; }
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
const ALLOWED_ORIGINS = ['https://echo-ept.com','https://www.echo-ept.com','https://echo-op.com','https://profinishusa.com','https://bgat.echo-op.com'];
app.use('*', cors({ origin: (o) => ALLOWED_ORIGINS.includes(o) ? o : ALLOWED_ORIGINS[0], allowMethods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'], allowHeaders: ['Content-Type','Authorization','X-Tenant-ID','X-Echo-API-Key'] }));

const uid = () => crypto.randomUUID();
const sanitize = (s: string, max = 10000) => s?.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').slice(0, max) ?? '';
const sanitizeBody = (o: Record<string, unknown>) => { const r: Record<string, unknown> = {}; for (const [k, v] of Object.entries(o)) r[k] = typeof v === 'string' ? sanitize(v) : v; return r; };
const tid = (c: any) => c.req.header('X-Tenant-ID') || c.req.query('tenant_id') || '';
const json = (d: unknown, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json' } });

function slog(level: 'info' | 'warn' | 'error', msg: string, data?: Record<string, unknown>) {
  const entry = { ts: new Date().toISOString(), level, worker: 'echo-contracts', version: '2.0.0', msg, ...data };
  if (level === 'error') console.error(JSON.stringify(entry));
  else console.log(JSON.stringify(entry));
}

// CORS headers (auto-added by Evolution Engine)
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': 'https://echo-ept.com',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Echo-API-Key',
};

async function generatePaymentToken(contractId: string, tenantId: string, hmacKey: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(hmacKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${contractId}:${tenantId}`));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyStripeSignature(payload: string, header: string, secret: string): Promise<boolean> {
  const parts = header.split(',').reduce((acc: Record<string, string>, p) => { const [k, v] = p.split('='); acc[k.trim()] = v; return acc; }, {});
  const timestamp = parts['t']; const signature = parts['v1'];
  if (!timestamp || !signature) return false;
  const age = Math.floor(Date.now() / 1000) - parseInt(timestamp);
  if (age > 300 || age < -60) return false;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${timestamp}.${payload}`));
  const expected = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  if (expected.length !== signature.length) return false;
  let result = 0;
  for (let i = 0; i < expected.length; i++) result |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  return result === 0;
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
  if (path === '/health' || path === '/status' || path.startsWith('/sign/') || path.startsWith('/public/') || path === '/webhooks/stripe') return next();
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  const isWrite = ['POST','PUT','PATCH','DELETE'].includes(c.req.method);
  if (await rateLimit(c.env.CACHE, `${ip}:${isWrite ? 'w' : 'r'}`, isWrite ? 60 : 200)) return json({ error: 'Rate limited' }, 429);
  return next();
});

// Auth middleware — require API key for write operations (public signing exempt)
app.use('*', async (c, next) => {
  const method = c.req.method;
  const path = new URL(c.req.url).pathname;
  if (method === 'GET' || method === 'OPTIONS' || method === 'HEAD' || path === '/health' || path === '/status' || path.startsWith('/sign/') || path.startsWith('/public/') || path === '/webhooks/stripe') return next();
  const apiKey = c.req.header('X-Echo-API-Key') || '';
  const bearer = (c.req.header('Authorization') || '').replace('Bearer ', '');
  const expected = c.env.ECHO_API_KEY;
  if (!expected || (apiKey !== expected && bearer !== expected)) {
    return json({ error: 'Unauthorized', message: 'Valid X-Echo-API-Key or Bearer token required for write operations' }, 401);
  }
  return next();
});

app.get('/', (c) => c.json({ service: 'echo-contracts', version: '2.0.0', status: 'operational', features: ['stripe-checkout', 'payment-links', 'public-portal', 'e-signatures', 'version-control'] }));
app.get('/health', (c) => json({ status: 'ok', service: 'echo-contracts', version: '2.0.0', stripe: !!c.env.STRIPE_SECRET_KEY, time: new Date().toISOString() }));

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
  // Create new version if content changed (atomic version increment to prevent collision)
  if (b.content || b.content_json) {
    const versionId = uid();
    const contentVal = typeof b.content === 'object' ? JSON.stringify(b.content) : b.content_json;
    await c.env.DB.batch([
      c.env.DB.prepare(
        `INSERT INTO contract_versions (id,contract_id,tenant_id,version,content_json,change_summary,created_by)
         SELECT ?,?,?,COALESCE(MAX(version),0)+1,?,?,?
         FROM contract_versions WHERE contract_id=?`
      ).bind(versionId, cid, t, contentVal, b.change_summary||'Updated', b.updated_by||'system', cid),
      c.env.DB.prepare(
        'UPDATE contracts SET current_version=(SELECT MAX(version) FROM contract_versions WHERE contract_id=?) WHERE id=?'
      ).bind(cid, cid),
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

// ═══════════════ STRIPE CHECKOUT ═══════════════
// Generate payment link for a contract
app.post('/contracts/:id/payment-link', async (c) => {
  if (!c.env.CONTRACT_HMAC_KEY) return json({ error: 'Payment links not configured' }, 503);
  const contract = await c.env.DB.prepare('SELECT * FROM contracts WHERE id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).first() as any;
  if (!contract) return json({ error: 'Contract not found' }, 404);
  if (!contract.value || contract.value <= 0) return json({ error: 'Contract has no payment value' }, 400);
  const token = await generatePaymentToken(contract.id, contract.tenant_id, c.env.CONTRACT_HMAC_KEY);
  await c.env.DB.prepare("UPDATE contracts SET payment_token=?,payment_required=1,updated_at=datetime('now') WHERE id=?").bind(token, contract.id).run();
  const base = c.env.SITE_URL || new URL(c.req.url).origin;
  const paymentUrl = `${base}/public/contract/${contract.id}?token=${token}`;
  slog('info', 'Payment link generated', { contract_id: contract.id, value: contract.value });
  return json({ payment_url: paymentUrl, token, contract_number: contract.contract_number, value: contract.value, currency: contract.currency });
});

// Create Stripe Checkout session for contract payment
app.post('/contracts/:id/checkout', async (c) => {
  if (!c.env.STRIPE_SECRET_KEY) return json({ error: 'Stripe not configured' }, 503);
  const contract = await c.env.DB.prepare('SELECT c.*, co.email as counterparty_email FROM contracts c LEFT JOIN contacts co ON c.counterparty_id=co.id WHERE c.id=? AND c.tenant_id=?').bind(c.req.param('id'), tid(c)).first() as any;
  if (!contract) return json({ error: 'Contract not found' }, 404);
  if (contract.status === 'terminated' || contract.status === 'expired') return json({ error: `Cannot pay ${contract.status} contract` }, 400);
  if (!contract.value || contract.value <= 0) return json({ error: 'No payment amount' }, 400);
  const amountCents = Math.round(Number(contract.value) * 100);
  const base = c.env.SITE_URL || new URL(c.req.url).origin;
  const params = new URLSearchParams();
  params.set('mode', 'payment');
  params.set('payment_method_types[]', 'card');
  params.set('line_items[0][price_data][currency]', (contract.currency || 'usd').toLowerCase());
  params.set('line_items[0][price_data][unit_amount]', String(amountCents));
  params.set('line_items[0][price_data][product_data][name]', `Contract: ${contract.title}`);
  params.set('line_items[0][price_data][product_data][description]', `Contract #${contract.contract_number}`);
  params.set('line_items[0][quantity]', '1');
  params.set('success_url', `${base}/public/contract/${contract.id}?paid=true`);
  params.set('cancel_url', `${base}/public/contract/${contract.id}?token=${contract.payment_token || ''}`);
  params.set('metadata[contract_id]', contract.id);
  params.set('metadata[tenant_id]', contract.tenant_id);
  params.set('metadata[contract_number]', contract.contract_number);
  if (contract.counterparty_email) params.set('customer_email', contract.counterparty_email);
  try {
    const res = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${c.env.STRIPE_SECRET_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    const session = await res.json() as any;
    if (!res.ok) { slog('error', 'Stripe checkout failed', { status: res.status, error: session }); return json({ error: session.error?.message || 'Stripe error' }, 502); }
    await c.env.DB.prepare("UPDATE contracts SET stripe_checkout_id=?,updated_at=datetime('now') WHERE id=?").bind(session.id, contract.id).run();
    slog('info', 'Stripe checkout created', { contract_id: contract.id, session_id: session.id, amount: amountCents });
    return json({ checkout_url: session.url, session_id: session.id });
  } catch (e) { slog('error', 'Stripe API error', { error: String(e) }); return json({ error: 'Stripe unavailable' }, 502); }
});

// Public contract portal — token-verified, no auth needed
app.get('/public/contract/:id', async (c) => {
  const id = c.req.param('id');
  const token = c.req.query('token') || '';
  const contract = await c.env.DB.prepare('SELECT c.*, co.name as counterparty_contact_name, co.email as counterparty_email FROM contracts c LEFT JOIN contacts co ON c.counterparty_id=co.id WHERE c.id=?').bind(id).first() as any;
  if (!contract) return json({ error: 'Contract not found' }, 404);
  if (!contract.payment_token || contract.payment_token !== token) {
    if (c.req.query('paid') !== 'true') return json({ error: 'Invalid payment token' }, 403);
  }
  const signatures = (await c.env.DB.prepare('SELECT signer_name,signer_role,status,signed_at FROM signatures WHERE contract_id=?').bind(id).all()).results;
  const isPaid = contract.payment_status === 'paid';
  const accept = c.req.header('Accept') || '';
  if (accept.includes('application/json')) {
    return json({ contract: { id: contract.id, title: contract.title, contract_number: contract.contract_number, status: contract.status, value: contract.value, currency: contract.currency, counterparty_name: contract.counterparty_name, start_date: contract.start_date, end_date: contract.end_date, payment_status: contract.payment_status || 'unpaid', payment_required: contract.payment_required }, signatures });
  }
  // Render HTML portal
  const statusColors: Record<string, string> = { draft: '#6b7280', review: '#f59e0b', sent: '#3b82f6', active: '#10b981', expired: '#ef4444', terminated: '#dc2626' };
  const statusColor = statusColors[contract.status] || '#6b7280';
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Contract ${contract.contract_number}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;color:#1e293b}
.top{background:#0f172a;color:#fff;padding:16px 24px;display:flex;justify-content:space-between;align-items:center}.top h1{font-size:18px;font-weight:600}
.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:700;text-transform:uppercase;color:#fff}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.1);margin:24px auto;max-width:700px;padding:32px}
.row{display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid #f1f5f9}.row:last-child{border:none}
.label{color:#64748b;font-size:14px}.val{font-weight:600;font-size:14px}
.total{font-size:28px;font-weight:700;color:#0f172a;text-align:center;padding:24px 0}
.btn{display:block;width:100%;padding:16px;border:none;border-radius:8px;font-size:16px;font-weight:700;cursor:pointer;text-align:center;text-decoration:none;margin-top:16px}
.btn-pay{background:#4f46e5;color:#fff}.btn-pay:hover{background:#4338ca}
.btn-paid{background:#10b981;color:#fff;cursor:default}
.sigs{margin-top:16px}.sig{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f1f5f9;font-size:13px}
.sig-signed{color:#10b981}.sig-pending{color:#f59e0b}
</style></head><body>
<div class="top"><h1>Contract ${sanitize(contract.contract_number, 50)}</h1><span class="badge" style="background:${statusColor}">${contract.status}</span></div>
<div class="card">
<h2 style="margin-bottom:16px">${sanitize(contract.title, 200)}</h2>
<div class="row"><span class="label">Counterparty</span><span class="val">${sanitize(contract.counterparty_name || 'N/A', 100)}</span></div>
<div class="row"><span class="label">Type</span><span class="val">${contract.type || 'general'}</span></div>
<div class="row"><span class="label">Start Date</span><span class="val">${contract.start_date || 'TBD'}</span></div>
<div class="row"><span class="label">End Date</span><span class="val">${contract.end_date || 'TBD'}</span></div>
<div class="row"><span class="label">Renewal</span><span class="val">${contract.auto_renew ? 'Auto-renew' : contract.renewal_type || 'Manual'}</span></div>
${contract.value ? `<div class="total">${(contract.currency || 'USD').toUpperCase()} $${Number(contract.value).toLocaleString('en-US', { minimumFractionDigits: 2 })}</div>` : ''}
${signatures.length ? `<div class="sigs"><h3 style="margin-bottom:8px;font-size:14px;color:#64748b">Signatures</h3>${(signatures as any[]).map((s: any) => `<div class="sig"><span>${sanitize(s.signer_name, 100)} (${s.signer_role})</span><span class="${s.status === 'signed' ? 'sig-signed' : 'sig-pending'}">${s.status === 'signed' ? 'Signed ' + (s.signed_at || '') : s.status}</span></div>`).join('')}</div>` : ''}
${isPaid ? '<a class="btn btn-paid">Payment Received</a>' : (contract.value > 0 && contract.payment_required) ? `<form method="POST" action="/public/contract/${contract.id}/pay?token=${token}"><button type="submit" class="btn btn-pay">Pay $${Number(contract.value).toLocaleString('en-US', { minimumFractionDigits: 2 })} Now</button></form>` : ''}
</div>
<p style="text-align:center;color:#94a3b8;font-size:12px;padding:16px">Powered by Echo Contracts</p>
</body></html>`;
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
});

// Public payment trigger — creates Stripe Checkout and redirects
app.post('/public/contract/:id/pay', async (c) => {
  if (!c.env.STRIPE_SECRET_KEY) return json({ error: 'Payments not configured' }, 503);
  const id = c.req.param('id');
  const token = c.req.query('token') || '';
  const contract = await c.env.DB.prepare('SELECT c.*, co.email as counterparty_email FROM contracts c LEFT JOIN contacts co ON c.counterparty_id=co.id WHERE c.id=?').bind(id).first() as any;
  if (!contract) return json({ error: 'Not found' }, 404);
  if (!contract.payment_token || contract.payment_token !== token) return json({ error: 'Invalid token' }, 403);
  if (contract.payment_status === 'paid') return json({ error: 'Already paid' }, 400);
  if (!contract.value || contract.value <= 0) return json({ error: 'No amount' }, 400);
  const amountCents = Math.round(Number(contract.value) * 100);
  const base = c.env.SITE_URL || new URL(c.req.url).origin;
  const params = new URLSearchParams();
  params.set('mode', 'payment');
  params.set('payment_method_types[]', 'card');
  params.set('line_items[0][price_data][currency]', (contract.currency || 'usd').toLowerCase());
  params.set('line_items[0][price_data][unit_amount]', String(amountCents));
  params.set('line_items[0][price_data][product_data][name]', `Contract: ${contract.title}`);
  params.set('line_items[0][price_data][product_data][description]', `#${contract.contract_number}`);
  params.set('line_items[0][quantity]', '1');
  params.set('success_url', `${base}/public/contract/${id}?paid=true`);
  params.set('cancel_url', `${base}/public/contract/${id}?token=${token}`);
  params.set('metadata[contract_id]', id);
  params.set('metadata[tenant_id]', contract.tenant_id);
  params.set('metadata[contract_number]', contract.contract_number);
  if (contract.counterparty_email) params.set('customer_email', contract.counterparty_email);
  try {
    const res = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${c.env.STRIPE_SECRET_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    const session = await res.json() as any;
    if (!res.ok) { slog('error', 'Stripe public checkout failed', { error: session }); return json({ error: 'Payment service error' }, 502); }
    await c.env.DB.prepare("UPDATE contracts SET stripe_checkout_id=?,updated_at=datetime('now') WHERE id=?").bind(session.id, id).run();
    return new Response(null, { status: 303, headers: { Location: session.url } });
  } catch (e) { slog('error', 'Stripe API error', { error: String(e) }); return json({ error: 'Payment unavailable' }, 502); }
});

// Stripe Webhook — verify signature, process payment events
app.post('/webhooks/stripe', async (c) => {
  const body = await c.req.text();
  const sigHeader = c.req.header('Stripe-Signature') || '';
  if (c.env.STRIPE_WEBHOOK_SECRET) {
    if (!sigHeader) { slog('warn', 'Webhook missing signature'); return json({ error: 'Missing signature' }, 401); }
    const valid = await verifyStripeSignature(body, sigHeader, c.env.STRIPE_WEBHOOK_SECRET);
    if (!valid) { slog('warn', 'Webhook invalid signature', { ip: c.req.header('cf-connecting-ip') || '' }); return json({ error: 'Invalid signature' }, 401); }
  }
  let event: any;
  try { event = JSON.parse(body); } catch { return json({ error: 'Invalid JSON' }, 400); }
  slog('info', 'Stripe webhook received', { type: event.type, id: event.id });
  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const contractId = session.metadata?.contract_id;
      const tenantId = session.metadata?.tenant_id;
      if (contractId && session.payment_status === 'paid') {
        await c.env.DB.batch([
          c.env.DB.prepare("UPDATE contracts SET payment_status='paid',stripe_payment_intent=?,updated_at=datetime('now') WHERE id=?").bind(session.payment_intent || session.id, contractId),
          c.env.DB.prepare("INSERT INTO activity_log (id,tenant_id,contract_id,action,actor,details) VALUES (?,?,?,?,?,?)").bind(uid(), tenantId || '', contractId, 'payment_received', 'stripe', JSON.stringify({ amount: session.amount_total, currency: session.currency, session_id: session.id, payment_intent: session.payment_intent })),
        ]);
        slog('info', 'Contract payment recorded', { contract_id: contractId, amount: session.amount_total });
      }
    } else if (event.type === 'checkout.session.expired') {
      const session = event.data.object;
      const contractId = session.metadata?.contract_id;
      if (contractId) {
        await c.env.DB.prepare("UPDATE contracts SET stripe_checkout_id=NULL,updated_at=datetime('now') WHERE id=? AND stripe_checkout_id=?").bind(contractId, session.id).run();
        slog('info', 'Checkout expired', { contract_id: contractId });
      }
    }
  } catch (e) { slog('error', 'Webhook processing error', { error: String(e), type: event.type }); }
  return json({ received: true });
});

// Schema migration for Stripe payment columns
app.post('/admin/migrate-stripe', async (c) => {
  const cols = [
    { name: 'payment_token', sql: "ALTER TABLE contracts ADD COLUMN payment_token TEXT" },
    { name: 'payment_required', sql: "ALTER TABLE contracts ADD COLUMN payment_required INTEGER DEFAULT 0" },
    { name: 'payment_status', sql: "ALTER TABLE contracts ADD COLUMN payment_status TEXT DEFAULT 'unpaid'" },
    { name: 'stripe_checkout_id', sql: "ALTER TABLE contracts ADD COLUMN stripe_checkout_id TEXT" },
    { name: 'stripe_payment_intent', sql: "ALTER TABLE contracts ADD COLUMN stripe_payment_intent TEXT" },
  ];
  const results: string[] = [];
  for (const col of cols) {
    try { await c.env.DB.prepare(col.sql).run(); results.push(`${col.name}: added`); }
    catch (e: any) { results.push(`${col.name}: ${e.message?.includes('duplicate') ? 'exists' : e.message}`); }
  }
  slog('info', 'Stripe migration completed', { results });
  return json({ migrated: true, results });
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
