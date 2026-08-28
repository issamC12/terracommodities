/**
 * Terra Commodities — traitement du formulaire de contact.
 *
 * Fonction serverless Vercel, à l'adresse /api/contact.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │  AUCUNE DÉPENDANCE                                                      │
 * │                                                                         │
 * │  Ce fichier n'utilise que les modules livrés avec Node : node:tls et    │
 * │  node:buffer. Ni nodemailer, ni formidable, ni npm install.             │
 * │                                                                         │
 * │  Raison : sur un projet composé de fichiers statiques, Vercel ne lance  │
 * │  pas toujours l'installation des paquets. La fonction plantait alors    │
 * │  au démarrage sur un module introuvable, et le formulaire renvoyait     │
 * │  une erreur sans explication. Sans dépendance, ce cas ne peut plus      │
 * │  se produire.                                                           │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Deux variables d'environnement à déclarer dans Vercel :
 *     SMTP_USER = ichr@terracommodities.fr
 *     SMTP_PASS = mot de passe d'application Google (16 caractères)
 */

import tls from 'node:tls';
import net from 'node:net';

const DEST = 'ichr@terracommodities.fr';
const SITE_NAME = 'Terra Commodities';
const MAX_BODY = 11 * 1024 * 1024;      // 11 Mo, marge sur la limite de 10
const MAX_FILE = 10 * 1024 * 1024;
const MAX_PER_HOUR = 5;

const hits = new Map();

function rateLimited(ip) {
  const slot = Math.floor(Date.now() / 3600000);
  const key = `${ip}:${slot}`;
  const n = (hits.get(key) || 0) + 1;
  hits.set(key, n);
  for (const k of hits.keys()) if (!k.endsWith(`:${slot}`)) hits.delete(k);
  return n > MAX_PER_HOUR;
}

/* Retire les retours à la ligne : un champ du formulaire ne doit pas pouvoir
   injecter d'en-têtes SMTP supplémentaires. */
const oneLine = v => String(v || '').replace(/[\r\n\t]+/g, ' ').trim();
const clean = (v, max = 2000) =>
  String(v || '').replace(/\0/g, '').trim().slice(0, max);

/* ── Lecture du corps de la requête ─────────────────────────────────────── */

function readBody(req) {
  return new Promise((resolve, reject) => {
    if (req.body && Buffer.isBuffer(req.body)) return resolve(req.body);
    const parts = [];
    let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('too_large')); req.destroy(); return; }
      parts.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(parts)));
    req.on('error', reject);
  });
}

/* ── Analyse d'un envoi multipart/form-data ─────────────────────────────── */

function parseMultipart(buf, boundary) {
  const fields = {};
  let file = null;
  const sep = Buffer.from(`--${boundary}`);
  const positions = [];
  let idx = buf.indexOf(sep, 0);
  while (idx !== -1) { positions.push(idx); idx = buf.indexOf(sep, idx + sep.length); }

  for (let i = 0; i < positions.length - 1; i++) {
    const start = positions[i] + sep.length;
    const end = positions[i + 1];
    let seg = buf.subarray(start, end);
    // retire le CRLF de tête et de queue
    if (seg[0] === 0x0d && seg[1] === 0x0a) seg = seg.subarray(2);
    if (seg[seg.length - 2] === 0x0d) seg = seg.subarray(0, seg.length - 2);

    const headEnd = seg.indexOf('\r\n\r\n');
    if (headEnd === -1) continue;
    const head = seg.subarray(0, headEnd).toString('utf8');
    const body = seg.subarray(headEnd + 4);

    const nameMatch = /name="([^"]*)"/i.exec(head);
    if (!nameMatch) continue;
    const name = nameMatch[1];
    const fileMatch = /filename="([^"]*)"/i.exec(head);

    if (fileMatch && fileMatch[1]) {
      if (body.length > 0 && body.length <= MAX_FILE) {
        file = { field: name, filename: fileMatch[1], content: body };
      } else if (body.length > MAX_FILE) {
        file = { tooLarge: true };
      }
    } else {
      fields[name] = body.toString('utf8');
    }
  }
  return { fields, file };
}

/* ── Contrôle du type réel d'une pièce jointe ───────────────────────────── */

const SIGNATURES = [
  { ext: ['pdf'],         mime: 'application/pdf',        magic: [0x25, 0x50, 0x44, 0x46] },
  { ext: ['jpg', 'jpeg'], mime: 'image/jpeg',             magic: [0xFF, 0xD8, 0xFF] },
  { ext: ['png'],         mime: 'image/png',              magic: [0x89, 0x50, 0x4E, 0x47] },
  { ext: ['webp'],        mime: 'image/webp',             magic: [0x52, 0x49, 0x46, 0x46] },
  { ext: ['docx', 'xlsx'], mime: 'application/octet-stream', magic: [0x50, 0x4B, 0x03, 0x04] },
  { ext: ['doc', 'xls'],  mime: 'application/msword',     magic: [0xD0, 0xCF, 0x11, 0xE0] },
];

function identify(buf, ext) {
  for (const s of SIGNATURES) {
    if (!s.ext.includes(ext)) continue;
    if (s.magic.every((b, i) => buf[i] === b)) return s.mime;
  }
  if (['txt', 'csv'].includes(ext) && !buf.subarray(0, 512).includes(0)) {
    return ext === 'csv' ? 'text/csv' : 'text/plain';
  }
  return null;
}

/* Nom entièrement reconstruit : le nom d'origine finit dans un en-tête MIME,
   où un guillemet ou un retour à la ligne permettrait une injection. */
function safeName(raw, ext) {
  let base = String(raw || '').replace(/\\/g, '/').split('/').pop().replace(/\.[^.]*$/, '');
  base = base.replace(/[^A-Za-z0-9 _-]+/g, '').replace(/\s+/g, ' ').trim();
  if (base.length < 2) base = 'piece-jointe';
  const name = `${base.slice(0, 60)}.${ext}`;
  return /^[A-Za-z0-9 _-]{2,60}\.[a-z]{2,4}$/.test(name) ? name : `piece-jointe.${ext}`;
}

/* ── Client SMTP minimal ────────────────────────────────────────────────── */

function smtpSend({ user, pass, to, subject, body, replyName, replyMail, attachment }) {
  return new Promise((resolve, reject) => {
    let sock = net.connect(587, 'smtp.gmail.com');
    let secure = null;
    let buffer = '';
    let step = 0;
    let done = false;

    const finish = (err) => {
      if (done) return;
      done = true;
      try { (secure || sock).end(); } catch (e) {}
      err ? reject(err) : resolve(true);
    };

    const timer = setTimeout(() => finish(new Error('timeout')), 20000);

    const send = line => (secure || sock).write(line + '\r\n');

    const mime = () => {
      const common = [
        `From: =?UTF-8?B?${Buffer.from(SITE_NAME).toString('base64')}?= <${user}>`,
        `To: <${to}>`,
        `Reply-To: =?UTF-8?B?${Buffer.from(oneLine(replyName)).toString('base64')}?= <${oneLine(replyMail)}>`,
        `Subject: =?UTF-8?B?${Buffer.from(subject).toString('base64')}?=`,
        `Date: ${new Date().toUTCString()}`,
        'MIME-Version: 1.0',
      ];
      // un point seul en début de ligne clôt le message : il faut le doubler
      const safe = body.replace(/\n/g, '\r\n').replace(/^\./gm, '..');
      if (!attachment) {
        return common.concat([
          'Content-Type: text/plain; charset=UTF-8',
          'Content-Transfer-Encoding: 8bit', '', safe,
        ]).join('\r\n');
      }
      const b = 'tc' + Date.now().toString(36);
      const enc = attachment.content.toString('base64').replace(/(.{76})/g, '$1\r\n');
      return common.concat([
        `Content-Type: multipart/mixed; boundary="${b}"`, '',
        `--${b}`,
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit', '', safe, '',
        `--${b}`,
        `Content-Type: ${attachment.mime}; name="${attachment.name}"`,
        `Content-Disposition: attachment; filename="${attachment.name}"`,
        'Content-Transfer-Encoding: base64', '', enc, '',
        `--${b}--`,
      ]).join('\r\n');
    };

    const handle = (chunk) => {
      buffer += chunk.toString('utf8');
      if (!/\r\n$/.test(buffer)) return;
      // les réponses multi-lignes se terminent par « 250 » sans tiret
      const lines = buffer.trim().split('\r\n');
      const last = lines[lines.length - 1];
      if (/^\d{3}-/.test(last)) return;
      const code = parseInt(last.slice(0, 3), 10);
      buffer = '';

      try {
        switch (step) {
          case 0:
            if (code !== 220) return finish(new Error('greeting ' + code));
            send('EHLO terracommodities.fr'); step = 1; break;
          case 1:
            if (code !== 250) return finish(new Error('ehlo ' + code));
            send('STARTTLS'); step = 2; break;
          case 2: {
            if (code !== 220) return finish(new Error('starttls ' + code));
            secure = tls.connect({ socket: sock, servername: 'smtp.gmail.com',
                                   minVersion: 'TLSv1.2' }, () => {
              if (!secure.authorized && secure.authorizationError) {
                return finish(new Error('tls ' + secure.authorizationError));
              }
              step = 3;
              send('EHLO terracommodities.fr');
            });
            secure.on('data', handle);
            secure.on('error', e => finish(e));
            break;
          }
          case 3:
            if (code !== 250) return finish(new Error('ehlo2 ' + code));
            send('AUTH LOGIN'); step = 4; break;
          case 4:
            if (code !== 334) return finish(new Error('auth ' + code));
            send(Buffer.from(user).toString('base64')); step = 5; break;
          case 5:
            if (code !== 334) return finish(new Error('user ' + code));
            send(Buffer.from(pass).toString('base64')); step = 6; break;
          case 6:
            if (code !== 235) return finish(new Error('pass ' + code));
            send(`MAIL FROM:<${user}>`); step = 7; break;
          case 7:
            if (code !== 250) return finish(new Error('from ' + code));
            send(`RCPT TO:<${to}>`); step = 8; break;
          case 8:
            if (code !== 250) return finish(new Error('rcpt ' + code));
            send('DATA'); step = 9; break;
          case 9:
            if (code !== 354) return finish(new Error('data ' + code));
            send(mime() + '\r\n.'); step = 10; break;
          case 10:
            clearTimeout(timer);
            if (code !== 250) return finish(new Error('send ' + code));
            send('QUIT'); finish(null); break;
        }
      } catch (e) { finish(e); }
    };

    sock.on('data', handle);
    sock.on('error', e => finish(e));
  });
}

/* ── Point d'entrée ─────────────────────────────────────────────────────── */

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');

  const reply = (code, obj) => { res.status(code); res.end(JSON.stringify(obj)); };

  if (req.method !== 'POST') return reply(405, { ok: false, error: 'method_not_allowed' });

  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || '0.0.0.0';
  if (rateLimited(ip)) return reply(429, { ok: false, error: 'too_many_requests' });

  let fields = {}, file = null;
  try {
    const ct = String(req.headers['content-type'] || '');
    const raw = await readBody(req);
    const bm = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(ct);
    if (bm) {
      const parsed = parseMultipart(raw, (bm[1] || bm[2]).trim());
      fields = parsed.fields; file = parsed.file;
    } else {
      new URLSearchParams(raw.toString('utf8')).forEach((v, k) => { fields[k] = v; });
    }
  } catch (e) {
    return reply(400, { ok: false, error: 'bad_request' });
  }

  if (file && file.tooLarge) return reply(422, { ok: false, error: 'file_rejected' });

  /* Champ piège, puis contrôle de délai : on répond « ok » sans envoyer,
     pour ne pas renseigner un robot sur ce qui l'a fait échouer. */
  if (clean(fields.website)) return reply(200, { ok: true });
  const ts = parseInt(fields.ts || '0', 10);
  if (ts > 0 && Date.now() / 1000 - ts < 3) return reply(200, { ok: true });

  const name    = clean(fields.name, 120);
  const company = clean(fields.company, 160);
  const email   = clean(fields.email, 180);
  const phone   = clean(fields.phone, 60);
  const country = clean(fields.country, 80);
  const ref     = clean(fields.ref, 80);
  const div     = clean(fields.division, 40);
  const message = clean(fields.message, 5000);
  const lang    = clean(fields.lang, 8);

  if (!name || !company || !email || !message) return reply(422, { ok: false, error: 'missing_fields' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return reply(422, { ok: false, error: 'invalid_email' });
  if (!fields.consent) return reply(422, { ok: false, error: 'consent_required' });

  const LABELS = { agriculture: 'Agriculture', metaux: 'Métaux', energy: 'Energy', autre: 'Autre' };
  const divLabel = LABELS[div] || 'Non précisée';

  let attachment = null;
  if (file && file.content) {
    const ext = String(file.filename).toLowerCase().split('.').pop();
    const allowed = ['pdf','jpg','jpeg','png','webp','doc','docx','xls','xlsx','txt','csv'];
    if (!allowed.includes(ext)) return reply(422, { ok: false, error: 'file_rejected' });
    const mime = identify(file.content, ext);
    if (!mime) return reply(422, { ok: false, error: 'file_rejected' });
    attachment = { name: safeName(file.filename, ext), mime, content: file.content };
  }

  const line = '-'.repeat(52);
  let body = [
    'Nouvelle demande depuis terracommodities.fr', line, '',
    `Division      : ${divLabel}`,
    `Nom           : ${name}`,
    `Société       : ${company}`,
    `Email         : ${email}`,
    `Téléphone     : ${phone || '—'}`,
    `Pays          : ${country || '—'}`,
    `Réf. interne  : ${ref || '—'}`,
    '', 'Demande :', line, message, '', line,
    `Consentement  : accordé le ${new Date().toLocaleString('fr-FR')}`,
    `Langue du site: ${lang || 'fr'}`,
  ].join('\n');
  if (attachment) {
    body += `\nPièce jointe  : ${attachment.name} (${Math.round(attachment.content.length / 1024)} Ko)`;
  }

  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!user || !pass) return reply(500, { ok: false, error: 'not_configured' });

  try {
    await smtpSend({
      user, pass, to: DEST,
      subject: `[${SITE_NAME}] Demande ${divLabel} — ${oneLine(name)}`,
      body, replyName: name, replyMail: email, attachment,
    });
    return reply(200, { ok: true });
  } catch (e) {
    // Le détail remonte dans les journaux Vercel pour permettre le diagnostic,
    // sans jamais être exposé au visiteur.
    console.error('SMTP:', e && e.message);
    return reply(500, { ok: false, error: 'send_failed' });
  }
}
