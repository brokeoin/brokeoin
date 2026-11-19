import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { z, ZodError } from 'zod';
import { q, one, scalar, tx, ensureSchema } from './db.js';
import { saveDataUrl, removeFile, isDataUrl, httpError } from './files.js';
import { sendSms } from './sms.js';

/* ------------------------------ config ------------------------------ */
const PROD = process.env.NODE_ENV === 'production' || !!process.env.VERCEL;
const JWT_SECRET = process.env.JWT_SECRET || '';
if (JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be set (32+ characters).');
const ADMIN_HASH = process.env.ADMIN_PASSWORD_HASH || '';
if (PROD && !ADMIN_HASH) console.error('WARNING: ADMIN_PASSWORD_HASH is not set, so nobody can log in to the verification desk.');
if (PROD && (process.env.SMS_PROVIDER || 'console') === 'console') console.error('WARNING: SMS_PROVIDER is "console": OTPs are only written to the server log and no SMS is sent. Set SMS_PROVIDER=twilio for real users.');

const PHONE = /^[6-9]\d{9}$/;
const TYPES = ['Apartment / Flat', 'Independent House', 'Villa', 'Plot / Land', 'Commercial Space', 'Farm Land'];
const now = () => Date.now();
const uid = () => crypto.randomUUID();

/* ------------------------------ app ------------------------------ */
const app = express();
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],            // the frontend is a single file with inline JS
      scriptSrcAttr: ["'unsafe-inline'"],                  // ...and inline onclick="" handlers
      upgradeInsecureRequests: PROD ? [] : null,
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ['https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https://*.tile.openstreetmap.org'],
      connectSrc: ["'self'"]
    }
  }
}));

// Make sure the tables exist before any request touches the database.
app.use('/api', async (_req, _res, next) => { await ensureSchema(); next(); });

// Listing photos are public (unguessable ids) and cached hard. Registered before the rate limiter so a page full of photos is never throttled.
app.get('/api/photos/:id', async (req, res) => {
  const f = await one("SELECT mime, data FROM files WHERE id=$1 AND kind='photo'", [req.params.id]);
  if (!f) throw httpError(404, 'Not found');
  res.set({ 'Content-Type': f.mime, 'Cache-Control': 'public, max-age=604800, immutable' }).send(f.data);
});

// Vercel rejects bodies over 4.5 MB before they reach this code; the frontend compresses images to stay well below that.
app.use(express.json({ limit: '4mb' }));

const limiter = (windowMs, max) => rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests. Try again later.' } });
app.use('/api', limiter(60_000, 240));

/* ------------------------------ auth ------------------------------ */
const sign = (payload, expiresIn) => jwt.sign(payload, JWT_SECRET, { expiresIn });

function auth(...roles) {
  return async (req, _res, next) => {
    let p;
    try {
      p = jwt.verify((req.headers.authorization || '').replace(/^Bearer /, ''), JWT_SECRET);
      if (!roles.includes(p.role)) throw 0;
    } catch { return next(httpError(401, 'Please log in again')); }
    req.user = p;
    if (p.role === 'owner' && !(await one('SELECT 1 FROM owners WHERE phone=$1', [p.phone]))) return next(httpError(401, 'Please log in again'));
    if (p.role === 'agent' && !(await one('SELECT 1 FROM agents WHERE phone=$1', [p.phone]))) return next(httpError(401, 'Please log in again'));
    next();
  };
}
/** Approval is read from the database on every request, so "revoke access" takes effect immediately. */
async function approvedAgent(req, _res, next) {
  const a = await one('SELECT status FROM agents WHERE phone=$1', [req.user.phone]);
  if (a?.status !== 'approved') return next(httpError(403, 'Your agent account is not approved yet'));
  next();
}

const hashOtp = (role, phone, code) => crypto.createHmac('sha256', JWT_SECRET).update(`${role}:${phone}:${code}`).digest('hex');

app.post('/api/auth/otp/request', limiter(15 * 60_000, 10), async (req, res) => {
  const { role, phone } = z.object({ role: z.enum(['owner', 'agent']), phone: z.string().regex(PHONE) }).parse(req.body);
  const prev = await one('SELECT sent_at FROM otps WHERE phone=$1 AND role=$2', [phone, role]);
  if (prev && now() - prev.sent_at < 30_000) throw httpError(429, 'Please wait 30 seconds before requesting another OTP');
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  await q(`INSERT INTO otps (phone, role, code_hash, expires_at, tries, sent_at) VALUES ($1,$2,$3,$4,0,$5)
           ON CONFLICT (phone, role) DO UPDATE SET code_hash=EXCLUDED.code_hash, expires_at=EXCLUDED.expires_at, tries=0, sent_at=EXCLUDED.sent_at`,
    [phone, role, hashOtp(role, phone, code), now() + 5 * 60_000, now()]);
  try {
    await sendSms(phone, `Your Brokeo OTP is ${code}. It is valid for 5 minutes. Do not share it with anyone.`, { otp: code });
  } catch (e) {
    console.error('OTP SMS failed:', e.message);
    await q('DELETE FROM otps WHERE phone=$1 AND role=$2', [phone, role]);
    throw httpError(502, 'We could not send the OTP right now. Please try again in a moment.');
  }
  res.json({ ok: true });
});

app.post('/api/auth/otp/verify', limiter(15 * 60_000, 30), async (req, res) => {
  const { role, phone, code } = z.object({ role: z.enum(['owner', 'agent']), phone: z.string().regex(PHONE), code: z.string().regex(/^\d{6}$/) }).parse(req.body);
  const row = await one('SELECT * FROM otps WHERE phone=$1 AND role=$2', [phone, role]);
  if (!row) throw httpError(400, 'Request a new OTP');
  if (now() > row.expires_at) throw httpError(400, 'This OTP has expired. Request a new one.');
  if (row.tries >= 5) { await q('DELETE FROM otps WHERE phone=$1 AND role=$2', [phone, role]); throw httpError(429, 'Too many wrong attempts. Request a new OTP.'); }
  await q('UPDATE otps SET tries = tries + 1 WHERE phone=$1 AND role=$2', [phone, role]);
  const a = Buffer.from(hashOtp(role, phone, code)), b = Buffer.from(row.code_hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw httpError(400, 'That OTP is incorrect');
  await q('DELETE FROM otps WHERE phone=$1 AND role=$2', [phone, role]);
  if (role === 'owner') await q('INSERT INTO owners (phone, created_at) VALUES ($1,$2) ON CONFLICT DO NOTHING', [phone, now()]);
  else await q('INSERT INTO agents (phone, created_at) VALUES ($1,$2) ON CONFLICT DO NOTHING', [phone, now()]);
  res.json({ token: sign({ role, phone }, '14d'), user: role === 'owner' ? await ownerOut(phone) : await agentOut(phone) });
});

app.post('/api/auth/admin/login', limiter(15 * 60_000, 10), async (req, res) => {
  const { password } = z.object({ password: z.string().min(1).max(200) }).parse(req.body);
  if (!ADMIN_HASH || !bcrypt.compareSync(password, ADMIN_HASH)) throw httpError(401, 'That password is incorrect');
  res.json({ token: sign({ role: 'admin' }, '8h') });
});

app.get('/api/me', auth('owner', 'agent', 'admin'), async (req, res) => {
  const { role, phone } = req.user;
  res.json(role === 'owner' ? { role, ...(await ownerOut(phone)) } : role === 'agent' ? { role, ...(await agentOut(phone)) } : { role });
});

/* ------------------------------ mappers ------------------------------ */
async function ownerOut(phone) {
  const o = await one('SELECT * FROM owners WHERE phone=$1', [phone]);
  return { phone: o.phone, name: o.name, email: o.email, createdAt: o.created_at };
}
/** What an agent sees about themselves (no raw documents). */
const agentRow = a => ({
  phone: a.phone, status: a.status, name: a.name, email: a.email, agency: a.agency, city: a.city, pan: a.pan,
  aadhaarMasked: a.aadhaar_masked, hasRera: !!a.has_rera, reraNo: a.rera_no, reraState: a.rera_state,
  officeName: a.office_name, officeAddress: a.office_address, officeLat: a.office_lat, officeLng: a.office_lng,
  inspDate: a.insp_date, inspSlot: a.insp_slot, note: a.note, submittedAt: a.submitted_at, approvedAt: a.approved_at,
  docs: { panDoc: !!a.pan_doc, aadhaarDoc: !!a.aadhaar_doc, reraDoc: !!a.rera_doc, officePhoto: !!a.office_photo }
});
const agentOut = async phone => agentRow(await one('SELECT * FROM agents WHERE phone=$1', [phone]));
/** Agent info shown to an owner whose listing the agent has a buyer for. */
const agentPublic = a => ({ phone: a.phone, name: a.name, agency: a.agency, city: a.city, hasRera: !!a.has_rera, reraNo: a.rera_no, officeName: a.office_name });

const photoUrl = id => '/api/photos/' + id;
function propOut(r, { contact = true } = {}) {
  const out = {
    id: r.id, status: r.status, title: r.title, type: r.type, bhk: r.bhk, area: r.area, extra: r.extra, desc: r.description,
    price: r.price, nego: r.nego, commission: { type: r.comm_type, value: r.comm_value },
    address: r.address, locality: r.locality, city: r.city, pincode: r.pincode, lat: r.lat, lng: r.lng,
    photos: JSON.parse(r.photos).map(photoUrl),
    createdAt: r.created_at, updatedAt: r.updated_at, soldAt: r.sold_at, soldTo: r.sold_to, soldCommission: r.sold_commission
  };
  if (contact) {
    out.ownerPhone = r.owner_phone;
    out.contact = { name: r.contact_name, phone: r.contact_phone, alt: r.contact_alt, email: r.contact_email, time: r.contact_time };
  }
  return out;
}
const commAmt = p => (p.comm_type === 'percent' ? (p.price * p.comm_value) / 100 : p.comm_value);

/* ------------------------------ validation ------------------------------ */
const str = (min, max) => z.string().trim().min(min).max(max);
const optStr = max => z.string().trim().max(max).optional().default('');
const PropertyIn = z.object({
  title: str(5, 120), type: z.enum(TYPES), bhk: optStr(20), area: z.number().positive().max(1e9),
  extra: optStr(200), desc: optStr(3000),
  price: z.number().positive().max(1e12), nego: z.enum(['yes', 'no']),
  commission: z.object({ type: z.enum(['percent', 'fixed']), value: z.number().positive() }),
  address: str(1, 250), locality: str(1, 100), city: str(1, 80), pincode: z.string().regex(/^[1-9]\d{5}$/),
  lat: z.number().min(-90).max(90), lng: z.number().min(-180).max(180),
  contact: z.object({
    name: str(1, 80), phone: z.string().regex(PHONE),
    alt: z.union([z.string().regex(PHONE), z.literal('')]).optional().default(''),
    email: z.union([z.string().email().max(80), z.literal('')]).optional().default(''),
    time: optStr(60)
  }),
  photos: z.array(z.string()).max(6).default([])
}).superRefine((d, ctx) => {
  const c = d.commission;
  if (c.type === 'percent' && c.value > 10) ctx.addIssue({ code: 'custom', message: 'Keep the commission at 10% or less' });
  if (c.type === 'fixed' && c.value >= d.price) ctx.addIssue({ code: 'custom', message: 'The commission must be less than the property price' });
});

/** New data-URL photos are saved; existing ones must already belong to this listing. Returns { names, stale }. */
async function resolvePhotos(list, existing = []) {
  const names = [];
  for (const p of list) {
    if (isDataUrl(p)) names.push(await saveDataUrl(p, 'photo'));
    else {
      const n = path.basename(p);
      if (!existing.includes(n)) throw httpError(400, 'Unknown photo');
      names.push(n);
    }
  }
  return { names, stale: existing.filter(n => !names.includes(n)) };
}

/* ------------------------------ owner ------------------------------ */
const owner = [auth('owner')];
const myProperty = async req => {
  const p = await one('SELECT * FROM properties WHERE id=$1 AND owner_phone=$2', [req.params.id, req.user.phone]);
  if (!p) throw httpError(404, 'Listing not found');
  return p;
};

app.put('/api/owner/profile', owner, async (req, res) => {
  const d = z.object({ name: optStr(60), email: z.union([z.string().email().max(80), z.literal('')]).default('') }).parse(req.body);
  await q('UPDATE owners SET name=$1, email=$2 WHERE phone=$3', [d.name, d.email, req.user.phone]);
  res.json(await ownerOut(req.user.phone));
});

app.get('/api/owner/properties', owner, async (req, res) => {
  res.json((await q('SELECT * FROM properties WHERE owner_phone=$1 ORDER BY created_at DESC', [req.user.phone])).map(r => propOut(r)));
});

async function writeProperty(id, phone, d, photos, isNew) {
  const v = [d.title, d.type, d.bhk, d.area, d.extra, d.desc, d.price, d.nego, d.commission.type, d.commission.value,
    d.address, d.locality, d.city, d.pincode, d.lat, d.lng,
    d.contact.name, d.contact.phone, d.contact.alt, d.contact.email, d.contact.time, JSON.stringify(photos)];
  if (isNew) {
    const ph = Array.from({ length: 25 }, (_, i) => '$' + (i + 1)).join(',');
    await q(`INSERT INTO properties (title,type,bhk,area,extra,description,price,nego,comm_type,comm_value,address,locality,city,pincode,lat,lng,
      contact_name,contact_phone,contact_alt,contact_email,contact_time,photos,id,owner_phone,created_at) VALUES (${ph})`, [...v, id, phone, now()]);
  } else {
    await q(`UPDATE properties SET title=$1,type=$2,bhk=$3,area=$4,extra=$5,description=$6,price=$7,nego=$8,comm_type=$9,comm_value=$10,address=$11,locality=$12,city=$13,pincode=$14,lat=$15,lng=$16,
      contact_name=$17,contact_phone=$18,contact_alt=$19,contact_email=$20,contact_time=$21,photos=$22,updated_at=$23 WHERE id=$24`, [...v, now(), id]);
  }
}

app.post('/api/owner/properties', owner, limiter(60_000, 20), async (req, res) => {
  const d = PropertyIn.parse(req.body);
  const id = uid();
  const { names } = await resolvePhotos(d.photos);
  await writeProperty(id, req.user.phone, d, names, true);
  await q("UPDATE owners SET name = CASE WHEN name='' THEN $1 ELSE name END, email = CASE WHEN email='' THEN $2 ELSE email END WHERE phone=$3",
    [d.contact.name, d.contact.email, req.user.phone]);
  res.status(201).json(propOut(await one('SELECT * FROM properties WHERE id=$1', [id])));
});

app.put('/api/owner/properties/:id', owner, async (req, res) => {
  const p = await myProperty(req);
  if (p.status !== 'active') throw httpError(409, 'Re-list this property before editing it');
  const d = PropertyIn.parse(req.body);
  const { names, stale } = await resolvePhotos(d.photos, JSON.parse(p.photos));
  await writeProperty(p.id, req.user.phone, d, names, false);
  for (const n of stale) await removeFile(n, 'photo');
  res.json(propOut(await one('SELECT * FROM properties WHERE id=$1', [p.id])));
});

/** Mark sold outside Brokeo / re-list. */
app.post('/api/owner/properties/:id/sold', owner, async (req, res) => {
  const p = await myProperty(req);
  const { sold } = z.object({ sold: z.boolean() }).parse(req.body);
  await tx(async c => {
    if (sold) {
      await c.query("UPDATE properties SET status='sold', sold_at=$1, sold_to=NULL, sold_commission=0 WHERE id=$2", [now(), p.id]);
      await c.query("UPDATE leads SET status='lost' WHERE property_id=$1 AND status='interested'", [p.id]);
    } else {
      await c.query("UPDATE properties SET status='active', sold_at=NULL, sold_to=NULL, sold_commission=0 WHERE id=$1", [p.id]);
      await c.query("UPDATE leads SET status='interested' WHERE property_id=$1 AND status IN ('lost','closed')", [p.id]);
    }
  });
  res.json(propOut(await one('SELECT * FROM properties WHERE id=$1', [p.id])));
});

app.delete('/api/owner/properties/:id', owner, async (req, res) => {
  const p = await myProperty(req);
  await tx(async c => {
    await c.query("UPDATE leads SET status='removed' WHERE property_id=$1", [p.id]);
    await c.query('DELETE FROM properties WHERE id=$1', [p.id]);
  });
  for (const n of JSON.parse(p.photos)) await removeFile(n, 'photo');
  res.json({ ok: true });
});

app.get('/api/owner/leads', owner, async (req, res) => {
  const rows = await q(`SELECT l.*, a.name a_name, a.phone a_phone, a.agency, a.city a_city, a.has_rera, a.rera_no, a.office_name
      FROM leads l JOIN agents a ON a.phone = l.agent_phone
      WHERE l.owner_phone=$1 AND l.status != 'removed' ORDER BY l.created_at DESC`, [req.user.phone]);
  res.json(rows.map(l => ({
    id: l.id, propertyId: l.property_id, note: l.note, status: l.status, createdAt: l.created_at,
    agent: agentPublic({ phone: l.a_phone, name: l.a_name, agency: l.agency, city: l.a_city, has_rera: l.has_rera, rera_no: l.rera_no, office_name: l.office_name })
  })));
});

/** "Sold via this agent": credits the agent and closes every other request. */
app.post('/api/owner/leads/:id/close', owner, async (req, res) => {
  const l = await one('SELECT * FROM leads WHERE id=$1 AND owner_phone=$2', [req.params.id, req.user.phone]);
  if (!l) throw httpError(404, 'Request not found');
  const p = await one('SELECT * FROM properties WHERE id=$1 AND owner_phone=$2', [l.property_id, req.user.phone]);
  if (!p || p.status !== 'active' || l.status !== 'interested') throw httpError(409, 'This request can no longer be closed');
  await tx(async c => {
    await c.query("UPDATE properties SET status='sold', sold_at=$1, sold_to=$2, sold_commission=$3 WHERE id=$4", [now(), l.agent_phone, commAmt(p), p.id]);
    await c.query("UPDATE leads SET status = CASE WHEN id=$1 THEN 'closed' ELSE 'lost' END WHERE property_id=$2 AND status != 'removed'", [l.id, p.id]);
  });
  res.json({ ok: true, commission: commAmt(p) });
});

/* ------------------------------ agent ------------------------------ */
const today = () => new Date(Date.now() + 5.5 * 3600e3).toISOString().slice(0, 10);   // IST date
const DOC_KEYS = { panDoc: 'pan_doc', aadhaarDoc: 'aadhaar_doc', reraDoc: 'rera_doc', officePhoto: 'office_photo' };

const KycIn = z.object({
  name: str(3, 80), email: z.union([z.string().email().max(80), z.literal('')]).default(''),
  agency: optStr(100), city: str(1, 80),
  pan: z.string().regex(/^[A-Z]{5}[0-9]{4}[A-Z]$/), aadhaar: z.string().regex(/^[2-9]\d{11}$/),
  hasRera: z.boolean(),
  reraNo: z.string().regex(/^[A-Za-z0-9/-]{6,30}$/).optional(), reraState: optStr(40),
  officeName: optStr(100), officeAddress: optStr(250),
  officeLat: z.number().min(-90).max(90).optional(), officeLng: z.number().min(-180).max(180).optional(),
  inspDate: optStr(10), inspSlot: optStr(30),
  panDoc: z.string().optional(), aadhaarDoc: z.string().optional(), reraDoc: z.string().optional(), officePhoto: z.string().optional()
}).superRefine((d, ctx) => {
  const bad = message => ctx.addIssue({ code: 'custom', message });
  if (d.hasRera) {
    if (!d.reraNo) bad('Enter a valid RERA registration number');
    if (!d.reraState) bad('Select your RERA state');
  } else {
    if (d.officeAddress.length < 10) bad('Enter your full office address');
    if (d.officeLat == null || d.officeLng == null) bad('Pin your office location');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d.inspDate) || d.inspDate < today()) bad('Pick an inspection date from today onwards');
  }
});

app.get('/api/agent/profile', auth('agent'), async (req, res) => res.json(await agentOut(req.user.phone)));

app.post('/api/agent/kyc', auth('agent'), limiter(60_000, 10), async (req, res) => {
  const cur = await one('SELECT * FROM agents WHERE phone=$1', [req.user.phone]);
  if (cur.status === 'approved') throw httpError(409, 'Your account is already approved');
  const d = KycIn.parse(req.body);

  // A document is either newly uploaded or must already be on file from an earlier submission.
  const need = d.hasRera ? ['panDoc', 'aadhaarDoc', 'reraDoc'] : ['panDoc', 'aadhaarDoc'];
  for (const k of need) if (!isDataUrl(d[k]) && !cur[DOC_KEYS[k]]) throw httpError(400, 'Upload your ' + { panDoc: 'PAN card', aadhaarDoc: 'Aadhaar card', reraDoc: 'RERA certificate' }[k]);

  const files = {}, toDelete = [];
  for (const [k, col] of Object.entries(DOC_KEYS)) {
    const wanted = !((k === 'reraDoc' && !d.hasRera) || (k === 'officePhoto' && d.hasRera));
    if (!wanted) { files[col] = null; if (cur[col]) toDelete.push(cur[col]); continue; }
    if (isDataUrl(d[k])) { files[col] = await saveDataUrl(d[k], 'kyc', 3 * 1024 * 1024); if (cur[col]) toDelete.push(cur[col]); }
    else files[col] = cur[col];
  }

  await q(`UPDATE agents SET name=$1, email=$2, agency=$3, city=$4, pan=$5, aadhaar_masked=$6, has_rera=$7,
      rera_no=$8, rera_state=$9, office_name=$10, office_address=$11, office_lat=$12, office_lng=$13, insp_date=$14, insp_slot=$15,
      pan_doc=$16, aadhaar_doc=$17, rera_doc=$18, office_photo=$19, status=$20, note='', submitted_at=$21 WHERE phone=$22`,
    [d.name, d.email, d.agency, d.city, d.pan, 'XXXX XXXX ' + d.aadhaar.slice(-4), d.hasRera,
      d.hasRera ? d.reraNo.toUpperCase() : null, d.hasRera ? d.reraState : null,
      d.hasRera ? null : d.officeName, d.hasRera ? null : d.officeAddress, d.hasRera ? null : d.officeLat, d.hasRera ? null : d.officeLng,
      d.hasRera ? null : d.inspDate, d.hasRera ? null : d.inspSlot,
      files.pan_doc, files.aadhaar_doc, files.rera_doc, files.office_photo,
      d.hasRera ? 'pending_docs' : 'pending_inspection', now(), req.user.phone]);
  for (const id of toDelete) await removeFile(id, 'kyc');
  res.json(await agentOut(req.user.phone));
});

const agentOnly = [auth('agent'), approvedAgent];
const SORTS = { new: 'p.created_at DESC', pa: 'p.price ASC', pd: 'p.price DESC',
  cd: "(CASE p.comm_type WHEN 'percent' THEN p.price * p.comm_value / 100 ELSE p.comm_value END) DESC" };

/** Owner contact details are only included once this agent has sent a request for that property. */
app.get('/api/agent/properties', agentOnly, async (req, res) => {
  const f = z.object({
    q: z.string().max(100).optional(), type: z.enum(TYPES).optional(),
    min: z.coerce.number().nonnegative().optional(), max: z.coerce.number().nonnegative().optional(),
    sort: z.enum(['new', 'pa', 'pd', 'cd']).default('new')
  }).parse(req.query);
  const where = ["p.status='active'"], args = [req.user.phone];
  if (f.q) {
    args.push(`%${f.q.replace(/[\\%_]/g, '\\$&')}%`);
    const n = '$' + args.length;
    where.push(`(p.title ILIKE ${n} OR p.locality ILIKE ${n} OR p.city ILIKE ${n} OR p.address ILIKE ${n} OR p.pincode ILIKE ${n})`);
  }
  if (f.type) { args.push(f.type); where.push('p.type=$' + args.length); }
  if (f.min != null) { args.push(f.min); where.push('p.price>=$' + args.length); }
  if (f.max != null) { args.push(f.max); where.push('p.price<=$' + args.length); }
  const rows = await q(`SELECT p.*, EXISTS (SELECT 1 FROM leads l WHERE l.property_id=p.id AND l.agent_phone=$1) AS has_lead
      FROM properties p WHERE ${where.join(' AND ')} ORDER BY ${SORTS[f.sort]}`, args);
  res.json(rows.map(r => ({ ...propOut(r, { contact: r.has_lead }), hasLead: r.has_lead })));
});

app.get('/api/agent/properties/:id', agentOnly, async (req, res) => {
  const r = await one('SELECT * FROM properties WHERE id=$1', [req.params.id]);
  const lead = r && await one('SELECT * FROM leads WHERE property_id=$1 AND agent_phone=$2', [r.id, req.user.phone]);
  if (!r || (r.status !== 'active' && !lead)) throw httpError(404, 'This property is no longer available');
  res.json({ ...propOut(r, { contact: !!lead }), lead: lead ? { id: lead.id, note: lead.note, status: lead.status, createdAt: lead.created_at } : null });
});

app.post('/api/agent/properties/:id/lead', agentOnly, limiter(60_000, 30), async (req, res) => {
  const { note } = z.object({ note: str(10, 600) }).parse(req.body);
  const p = await one("SELECT * FROM properties WHERE id=$1 AND status='active'", [req.params.id]);
  if (!p) throw httpError(404, 'This property is no longer available');
  const id = uid();
  try {
    await q('INSERT INTO leads (id, property_id, agent_phone, owner_phone, note, created_at) VALUES ($1,$2,$3,$4,$5,$6)',
      [id, p.id, req.user.phone, p.owner_phone, note, now()]);
  } catch (e) {
    if (e.code === '23505') throw httpError(409, 'You have already sent a request for this property');
    throw e;
  }
  res.status(201).json({ id, property: propOut(p) });   // contact details are now unlocked
});

app.get('/api/agent/leads', agentOnly, async (req, res) => {
  const rows = await q(`SELECT l.id lid, l.note, l.status lstatus, l.created_at lcreated, p.*
      FROM leads l JOIN properties p ON p.id = l.property_id
      WHERE l.agent_phone=$1 AND l.status != 'removed' ORDER BY l.created_at DESC`, [req.user.phone]);
  res.json(rows.map(r => ({ id: r.lid, note: r.note, status: r.lstatus, createdAt: r.lcreated, property: propOut(r) })));
});

/* ------------------------------ admin ------------------------------ */
const admin = [auth('admin')];

app.get('/api/admin/stats', admin, async (_req, res) => {
  res.json({
    pendingAgents: await scalar("SELECT COUNT(*) FROM agents WHERE status IN ('pending_docs','pending_inspection')"),
    approvedAgents: await scalar("SELECT COUNT(*) FROM agents WHERE status='approved'"),
    activeListings: await scalar("SELECT COUNT(*) FROM properties WHERE status='active'"),
    soldProperties: await scalar("SELECT COUNT(*) FROM properties WHERE status='sold'")
  });
});

app.get('/api/admin/agents', admin, async (req, res) => {
  const { status } = z.object({ status: z.enum(['new', 'pending_docs', 'pending_inspection', 'approved', 'rejected']).optional() }).parse(req.query);
  const rows = status
    ? await q('SELECT * FROM agents WHERE status=$1 ORDER BY submitted_at DESC NULLS LAST', [status])
    : await q("SELECT * FROM agents WHERE status != 'new' ORDER BY submitted_at DESC NULLS LAST");
  res.json(rows.map(agentRow));
});

const agentFor = async req => {
  const a = await one('SELECT * FROM agents WHERE phone=$1', [req.params.phone]);
  if (!a) throw httpError(404, 'Agent not found');
  return a;
};

app.post('/api/admin/agents/:phone/approve', admin, async (req, res) => {
  const a = await agentFor(req);
  if (!a.status.startsWith('pending')) throw httpError(409, 'This agent has no pending application');
  await q("UPDATE agents SET status='approved', approved_at=$1, note='' WHERE phone=$2", [now(), a.phone]);
  sendSms(a.phone, 'Brokeo: your agent account is approved. You can now view listings.').catch(e => console.error('sms failed', e.message));
  res.json(await agentOut(a.phone));
});

app.post('/api/admin/agents/:phone/reject', admin, async (req, res) => {
  const a = await agentFor(req);
  const { note } = z.object({ note: str(5, 400) }).parse(req.body);
  if (!a.status.startsWith('pending')) throw httpError(409, 'This agent has no pending application');
  await q("UPDATE agents SET status='rejected', note=$1 WHERE phone=$2", [note, a.phone]);
  sendSms(a.phone, 'Brokeo: your agent application needs changes. Log in to see the reason.').catch(e => console.error('sms failed', e.message));
  res.json(await agentOut(a.phone));
});

app.post('/api/admin/agents/:phone/revoke', admin, async (req, res) => {
  const a = await agentFor(req);
  if (a.status !== 'approved') throw httpError(409, 'This agent is not approved');
  await q("UPDATE agents SET status='rejected', note='Access revoked by the Brokeo team. Contact support.' WHERE phone=$1", [a.phone]);
  res.json(await agentOut(a.phone));
});

/** Everyone who has registered (logged in at least once), owners and agents together. */
app.get('/api/admin/users', admin, async (_req, res) => {
  const owners = await q(`SELECT o.phone, o.name, o.email, o.created_at,
      (SELECT COUNT(*) FROM properties p WHERE p.owner_phone = o.phone) AS listings FROM owners o`);
  const agents = await q('SELECT phone, name, email, agency, city, status, created_at FROM agents');
  res.json([
    ...owners.map(o => ({ role: 'owner', phone: o.phone, name: o.name || '', email: o.email || '', joinedAt: o.created_at, listings: o.listings })),
    ...agents.map(a => ({ role: 'agent', phone: a.phone, name: a.name || '', email: a.email || '', agency: a.agency || '', city: a.city || '', status: a.status, joinedAt: a.created_at }))
  ].sort((a, b) => b.joinedAt - a.joinedAt));
});

/** Every listing with its seller and the agents who have sent a buyer request. */
app.get('/api/admin/properties', admin, async (_req, res) => {
  const rows = await q(`SELECT p.*, o.name AS owner_name, o.email AS owner_email
      FROM properties p LEFT JOIN owners o ON o.phone = p.owner_phone ORDER BY p.created_at DESC`);
  const leads = await q(`SELECT l.property_id, l.status, a.name, a.phone, a.agency
      FROM leads l JOIN agents a ON a.phone = l.agent_phone WHERE l.status != 'removed' ORDER BY l.created_at`);
  res.json(rows.map(r => ({
    ...propOut(r),
    owner: { name: r.owner_name || '', email: r.owner_email || '', phone: r.owner_phone },
    agents: leads.filter(l => l.property_id === r.id).map(l => ({ name: l.name, phone: l.phone, agency: l.agency, status: l.status }))
  })));
});

/** Moderation: remove a listing (e.g. spam or a fake listing). */
app.delete('/api/admin/properties/:id', admin, async (req, res) => {
  const p = await one('SELECT * FROM properties WHERE id=$1', [req.params.id]);
  if (!p) throw httpError(404, 'Listing not found');
  await tx(async c => {
    await c.query("UPDATE leads SET status='removed' WHERE property_id=$1", [p.id]);
    await c.query('DELETE FROM properties WHERE id=$1', [p.id]);
  });
  for (const n of JSON.parse(p.photos)) await removeFile(n, 'photo');
  res.json({ ok: true });
});

/** KYC documents are never public; only a logged-in admin can open them, and nothing is cached. */
app.get('/api/admin/agents/:phone/docs/:kind', admin, async (req, res) => {
  const col = DOC_KEYS[req.params.kind];
  const a = await agentFor(req);
  if (!col || !a[col]) throw httpError(404, 'Not uploaded');
  const f = await one("SELECT mime, data FROM files WHERE id=$1 AND kind='kyc'", [a[col]]);
  if (!f) throw httpError(404, 'Not uploaded');
  res.set({ 'Content-Type': f.mime, 'Cache-Control': 'private, no-store' }).send(f.data);
});

/* ------------------------------ static + errors ------------------------------ */
// The website is served by this app on every host. Reading it with new URL(..., import.meta.url)
// lets Vercel's bundler include public/index.html in the function.
const INDEX_HTML = fs.readFileSync(new URL('../public/index.html', import.meta.url));
app.get(['/', '/index.html'], (_req, res) => res.type('html').set('Cache-Control', 'no-cache').send(INDEX_HTML));
if (!process.env.VERCEL) {
  const PUBLIC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
  app.use(express.static(PUBLIC));
}
app.use('/api', (_req, _res, next) => next(httpError(404, 'Not found')));

app.use((err, _req, res, _next) => {
  if (err instanceof ZodError) {
    const msg = err.issues.map(i => (i.path.length ? i.path.join('.') + ': ' : '') + i.message).join('; ');
    return res.status(400).json({ error: msg });
  }
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Upload is too large. Try smaller photos.' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid request' });
  if (err.status && err.status < 500) return res.status(err.status).json({ error: err.message });
  if (err.status) return res.status(err.status).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong' });
});

export default app;
