/**
 * Terra Commodities — traitement du formulaire de contact sur Vercel.
 *
 * Remplace contact.php : Vercel n'exécute pas de PHP, mais accepte des
 * fonctions serverless en JavaScript. Ce fichier doit être placé dans un
 * dossier nommé exactement « api » à la racine du projet :
 *
 *     api/contact.js
 *
 * Vercel l'expose alors automatiquement à l'adresse /api/contact, sans
 * configuration supplémentaire.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │  DEUX CHOSES À FAIRE DANS L'INTERFACE VERCEL                            │
 * │                                                                         │
 * │  Projet → Settings → Environment Variables, ajouter :                   │
 * │                                                                         │
 * │    SMTP_USER  =  ichr@terracommodities.fr                               │
 * │    SMTP_PASS  =  le mot de passe d'application Google (16 caractères)   │
 * │                                                                         │
 * │  Les variables d'environnement ne figurent dans aucun fichier : c'est   │
 * │  la raison pour laquelle le secret n'est pas écrit ici. Personne ne     │
 * │  peut le lire, même en accédant au code du projet.                      │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Avant de déployer, installer la dépendance d'envoi :
 *     npm install nodemailer
 */

import nodemailer from 'nodemailer';

const DEST = 'ichr@terracommodities.fr';
const SITE_NAME = 'Terra Commodities';
const MAX_FILE_BYTES = 10 * 1024 * 1024;   // 10 Mo
const MAX_PER_HOUR = 5;                     // par adresse IP

/* Limitation par IP. La mémoire d'une fonction serverless n'est pas partagée
   entre toutes les instances, donc ce compteur est indicatif : il freine un
   envoi répété depuis un même client sans prétendre à une protection
   distribuée. Le champ piège et le contrôle de délai font le reste. */
const hits = new Map();

function rateLimited(ip) {
  const now = Date.now();
  const slot = Math.floor(now / 3600000);
  const key = `${ip}:${slot}`;
  const n = (hits.get(key) || 0) + 1;
  hits.set(key, n);
  // purge des créneaux passés
  for (const k of hits.keys()) {
    if (!k.endsWith(`:${slot}`)) hits.delete(k);
  }
  return n > MAX_PER_HOUR;
}

/** Supprime les retours à la ligne : sans cela, un champ du formulaire peut
 *  injecter des en-têtes SMTP arbitraires et transformer le formulaire en
 *  relais de spam. */
function oneLine(v) {
  return String(v || '').replace(/[\r\n\t]+/g, ' ').trim();
}

function clean(v, max = 2000) {
  return String(v || '').replace(/\0/g, '').trim().slice(0, max);
}

/* Types réellement acceptés, contrôlés sur la signature binaire du fichier et
   non sur ce que le navigateur déclare. Un script renommé en .pdf ne passe
   donc pas ce filtre. */
const SIGNATURES = [
  { ext: ['pdf'],          mime: 'application/pdf',  magic: [0x25, 0x50, 0x44, 0x46] },
  { ext: ['jpg', 'jpeg'],  mime: 'image/jpeg',       magic: [0xFF, 0xD8, 0xFF] },
  { ext: ['png'],          mime: 'image/png',        magic: [0x89, 0x50, 0x4E, 0x47] },
  { ext: ['webp'],         mime: 'image/webp',       magic: [0x52, 0x49, 0x46, 0x46] },
  { ext: ['docx', 'xlsx'], mime: 'application/zip',  magic: [0x50, 0x4B, 0x03, 0x04] },
  { ext: ['doc', 'xls'],   mime: 'application/msword', magic: [0xD0, 0xCF, 0x11, 0xE0] },
];

function identify(buf, declaredExt) {
  for (const s of SIGNATURES) {
    if (!s.ext.includes(declaredExt)) continue;
    if (s.magic.every((b, i) => buf[i] === b)) return s.mime;
  }
  // txt et csv n'ont pas de signature : on vérifie l'absence d'octets nuls
  if (['txt', 'csv'].includes(declaredExt)) {
    const head = buf.subarray(0, 512);
    if (!head.includes(0)) return declaredExt === 'csv' ? 'text/csv' : 'text/plain';
  }
  return null;
}

/** Nom entièrement reconstruit. Le nom d'origine finit dans un en-tête MIME,
 *  où un guillemet ou un retour à la ligne permettrait une injection. */
function safeName(raw, ext) {
  let base = String(raw || '').replace(/\\/g, '/').split('/').pop();
  base = base.replace(/\.[^.]*$/, '');
  base = base.replace(/[^A-Za-z0-9 _-]+/g, '').replace(/\s+/g, ' ').trim();
  if (base.length < 2) base = 'piece-jointe';
  const name = `${base.slice(0, 60)}.${ext}`;
  return /^[A-Za-z0-9 _-]{2,60}\.[a-z]{2,4}$/.test(name) ? name : `piece-jointe.${ext}`;
}

export const config = {
  api: { bodyParser: false },   // on lit le flux nous-mêmes, multipart inclus
};

export default async function handler(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'method_not_allowed' });
  }

  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || '0.0.0.0';
  if (rateLimited(ip)) {
    return res.status(429).json({ ok: false, error: 'too_many_requests' });
  }

  let fields = {};
  let file = null;

  try {
    const { formidable } = await import('formidable');
    const form = formidable({
      maxFileSize: MAX_FILE_BYTES,
      maxFiles: 1,
      keepExtensions: false,
    });
    const [f, fl] = await form.parse(req);
    // formidable renvoie des tableaux : on prend la première valeur
    for (const [k, v] of Object.entries(f)) fields[k] = Array.isArray(v) ? v[0] : v;
    const up = fl.attachment;
    if (up) file = Array.isArray(up) ? up[0] : up;
  } catch (e) {
    return res.status(400).json({ ok: false, error: 'bad_request' });
  }

  /* Champ piège : invisible pour un humain, rempli par la plupart des robots.
     On répond « ok » sans rien envoyer, pour ne pas les renseigner. */
  if (clean(fields.website)) {
    return res.status(200).json({ ok: true });
  }

  /* Un formulaire soumis en moins de trois secondes n'a pas été lu. */
  const started = parseInt(fields.ts || '0', 10);
  if (started > 0 && Date.now() / 1000 - started < 3) {
    return res.status(200).json({ ok: true });
  }

  const name    = clean(fields.name, 120);
  const company = clean(fields.company, 160);
  const email   = clean(fields.email, 180);
  const phone   = clean(fields.phone, 60);
  const country = clean(fields.country, 80);
  const ref     = clean(fields.ref, 80);
  const div     = clean(fields.division, 40);
  const message = clean(fields.message, 5000);
  const lang    = clean(fields.lang, 8);
  const consent = !!fields.consent;

  if (!name || !company || !email || !message) {
    return res.status(422).json({ ok: false, error: 'missing_fields' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(422).json({ ok: false, error: 'invalid_email' });
  }
  if (!consent) {
    return res.status(422).json({ ok: false, error: 'consent_required' });
  }

  const LABELS = {
    agriculture: 'Agriculture', metaux: 'Métaux',
    energy: 'Energy', autre: 'Autre',
  };
  const divLabel = LABELS[div] || 'Non précisée';

  /* Pièce jointe : lue, contrôlée sur sa signature, jointe au message.
     Rien n'est conservé — l'espace de la fonction est éphémère par nature. */
  let attachment = null;
  if (file && file.size > 0) {
    if (file.size > MAX_FILE_BYTES) {
      return res.status(422).json({ ok: false, error: 'file_rejected' });
    }
    const fs = await import('node:fs/promises');
    const buf = await fs.readFile(file.filepath);
    const ext = String(file.originalFilename || '').toLowerCase().split('.').pop();
    const ok = ['pdf','jpg','jpeg','png','webp','doc','docx','xls','xlsx','txt','csv'];
    if (!ok.includes(ext)) {
      return res.status(422).json({ ok: false, error: 'file_rejected' });
    }
    const mime = identify(buf, ext);
    if (!mime) {
      return res.status(422).json({ ok: false, error: 'file_rejected' });
    }
    attachment = {
      filename: safeName(file.originalFilename, ext),
      content: buf,
      contentType: mime,
    };
    await fs.unlink(file.filepath).catch(() => {});
  }

  const line = '-'.repeat(52);
  let body = [
    'Nouvelle demande depuis terracommodities.fr',
    line, '',
    `Division      : ${divLabel}`,
    `Nom           : ${name}`,
    `Société       : ${company}`,
    `Email         : ${email}`,
    `Téléphone     : ${phone || '—'}`,
    `Pays          : ${country || '—'}`,
    `Réf. interne  : ${ref || '—'}`,
    '', 'Demande :', line,
    message,
    '', line,
    `Consentement  : accordé le ${new Date().toLocaleString('fr-FR')}`,
    `Langue du site: ${lang || 'fr'}`,
  ].join('\n');

  if (attachment) {
    body += `\nPièce jointe  : ${attachment.filename} (${Math.round(attachment.content.length / 1024)} Ko)`;
  }

  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!user || !pass) {
    // Configuration incomplète : on le dit plutôt que d'échouer en silence.
    return res.status(500).json({ ok: false, error: 'not_configured' });
  }

  try {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false,          // STARTTLS négocié après la connexion
      auth: { user, pass },
      requireTLS: true,       // refuse d'envoyer si le chiffrement échoue
      tls: { minVersion: 'TLSv1.2' },
    });

    await transporter.sendMail({
      from: `${SITE_NAME} <${user}>`,
      to: DEST,
      replyTo: `${oneLine(name)} <${oneLine(email)}>`,
      subject: `[${SITE_NAME}] Demande ${divLabel} — ${oneLine(name)}`,
      text: body,
      attachments: attachment ? [attachment] : [],
    });

    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'send_failed' });
  }
}
