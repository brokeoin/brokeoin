import crypto from 'node:crypto';
import { pool } from './db.js';

const TYPES = {
  jpg: { mime: 'image/jpeg', ok: b => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  png: { mime: 'image/png', ok: b => b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 },
  webp: { mime: 'image/webp', ok: b => b.toString('ascii', 0, 4) === 'RIFF' && b.toString('ascii', 8, 12) === 'WEBP' }
};
const MIME = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };

export const isDataUrl = s => typeof s === 'string' && s.startsWith('data:image/');

export function httpError(status, message) {
  return Object.assign(new Error(message), { status });
}

/** Saves a base64 image data URL into the files table and returns its id. Throws on anything odd. */
export async function saveDataUrl(dataUrl, kind, maxBytes = 3 * 1024 * 1024) {
  const comma = dataUrl.indexOf(',');
  const head = dataUrl.slice(0, comma);                 // data:image/jpeg;base64
  const mime = head.slice(5, head.indexOf(';'));
  const type = MIME[mime];
  if (comma < 0 || !type || !head.endsWith(';base64')) throw httpError(400, 'Upload a JPG, PNG or WebP image');
  const buf = Buffer.from(dataUrl.slice(comma + 1), 'base64');
  if (!buf.length || buf.length > maxBytes) throw httpError(400, 'Image is empty or larger than ' + maxBytes / 1048576 + ' MB');
  if (!TYPES[type].ok(buf)) throw httpError(400, 'That file is not a valid image');
  const id = crypto.randomUUID();                       // random id: never trust client file names
  await pool.query('INSERT INTO files (id, kind, mime, data, created_at) VALUES ($1,$2,$3,$4,$5)', [id, kind, TYPES[type].mime, buf, Date.now()]);
  return id;
}

export async function removeFile(id, kind) {
  if (!id) return;
  await pool.query('DELETE FROM files WHERE id=$1 AND kind=$2', [id, kind]).catch(e => console.error('removeFile failed', e.message));
}
