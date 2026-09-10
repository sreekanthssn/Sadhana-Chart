require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

// ============================================================
//  DATABASE  (Neon Postgres, via the DATABASE_URL in your .env)
// ============================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Neon requires SSL
});

// ============================================================
//  EMAIL  (Resend). If no API key is set yet, codes are printed
//  to the server console instead, so you can still test locally.
// ============================================================
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const EMAIL_FROM = process.env.EMAIL_FROM || 'onboarding@resend.dev';

async function sendCodeEmail(to, subject, code) {
  if (!resend) {
    console.log(`\n[EMAIL DISABLED] would send to ${to} | ${subject} | code: ${code}\n`);
    return;
  }
  try {
    await resend.emails.send({
      from: EMAIL_FROM,
      to,
      subject,
      html: `<p>Your Varenium verification code is <strong>${code}</strong>.</p>
             <p>It expires in 15 minutes. If you didn't request this, you can ignore this email.</p>`
    });
  } catch (err) {
    console.error('Email send failed:', err.message);
  }
}

// ============================================================
//  MIDDLEWARE
// ============================================================
app.set('trust proxy', 1); // required on Vercel so secure cookies work
app.use(express.json({ limit: '6mb' })); // large limit allows base64 avatar uploads
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new PgSession({ pool, tableName: 'session', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'dev-only-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProd,       // https-only in production (Vercel), off locally
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 1 week
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
//  HELPERS
// ============================================================

// Shape a raw DB row into the fields the frontend expects. Never
// includes password_hash.
function toClientUser(row) {
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    firstName: row.first_name,
    lastName: row.last_name,
    role: row.role,
    avatar: row.avatar_url,
    themeMode: row.theme_mode,
    colorTheme: row.color_theme
  };
}

async function getUserById(id) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return rows[0] || null;
}

// Block a route unless the visitor is logged in.
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}

// Block a route unless the visitor is an admin or root. Attaches the
// current user to req.currentUser for the handler to use.
async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const me = await getUserById(req.session.userId);
  if (!me || (me.role !== 'admin' && me.role !== 'root')) {
    return res.status(403).json({ error: 'Admins only' });
  }
  req.currentUser = me;
  next();
}

// Who is allowed to manage whom. Root manages everyone; an admin
// manages only ordinary users.
function canManage(actor, target) {
  if (actor.role === 'root') return true;
  if (actor.role === 'admin' && target.role === 'user') return true;
  return false;
}

// The score is computed on the SERVER so a user can't submit a fake one.
// (Same formula as the original page.)
function computeScore(rounds, reading, lecture, service) {
  const score = Math.round(
    (Math.min(rounds, 16) * 2.5) +
    (Math.min(reading, 60) / 3) +
    (Math.min(lecture, 60) / 3) +
    (Math.min(service, 60) / 3)
  );
  return Math.min(score, 100);
}

// Start of the current week (most recent Sunday, midnight UTC).
function getWeekStartUTC() {
  const now = new Date();
  const day = now.getUTCDay();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - day));
}

// Generate a 6-digit code, store its hash, and return the plain code to email.
async function issueCode(userId, purpose) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = bcrypt.hashSync(code, 10);
  const expires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
  await pool.query(
    `INSERT INTO verification_codes (user_id, code_hash, purpose, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [userId, codeHash, purpose, expires]
  );
  return code;
}

// Find a matching, unused, unexpired code for this user + purpose.
async function findValidCode(userId, purpose, code) {
  const { rows } = await pool.query(
    `SELECT * FROM verification_codes
     WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > now()
     ORDER BY created_at DESC`,
    [userId, purpose]
  );
  for (const row of rows) {
    if (bcrypt.compareSync(String(code), row.code_hash)) return row;
  }
  return null;
}

function shapeLog(r) {
  return {
    date: r.date,
    rounds: Number(r.rounds),
    reading: Number(r.reading),
    lecture: Number(r.lecture),
    service: Number(r.service),
    score: r.score
  };
}

// ============================================================
//  AUTH ROUTES
// ============================================================
app.post('/api/signup', async (req, res) => {
  try {
    const { firstName, lastName, username, password, email } = req.body;
    if (!username || !password || !email) {
      return res.status(400).json({ error: 'Username, email and password are required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    const dupe = await pool.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );
    if (dupe.rows.length) {
      return res.status(409).json({ error: 'That username or email is already taken' });
    }
    const hash = bcrypt.hashSync(password, 10);
    const avatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(((firstName || '') + ' ' + (lastName || '')).trim())}`;
    const { rows } = await pool.query(
      `INSERT INTO users (username, email, password_hash, first_name, last_name, role, avatar_url)
       VALUES ($1, $2, $3, $4, $5, 'user', $6)
       RETURNING *`,
      [username, email, hash, firstName || null, lastName || null, avatar]
    );
    req.session.userId = rows[0].id;
    res.json(toClientUser(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong during signup' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = rows[0];
    if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    req.session.userId = user.id;
    res.json(toClientUser(user));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong during login' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', requireAuth, async (req, res) => {
  const user = await getUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  res.json(toClientUser(user));
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    // Respond the same way whether or not the email exists, so we don't
    // reveal which addresses are registered.
    if (rows.length) {
      const code = await issueCode(rows[0].id, 'password_reset');
      await sendCodeEmail(email, 'Your Varenium password reset code', code);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
    }
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: 'Invalid or expired code' });
    const valid = await findValidCode(user.id, 'password_reset', code);
    if (!valid) return res.status(400).json({ error: 'Invalid or expired code' });
    const hash = bcrypt.hashSync(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, user.id]);
    await pool.query('UPDATE verification_codes SET consumed_at = now() WHERE id = $1', [valid.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// ============================================================
//  LOG ROUTES  (a user's own daily sadhana entries)
// ============================================================
app.get('/api/logs', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT to_char(log_date, 'YYYY-MM-DD') AS date, rounds, reading, lecture, service, score
     FROM logs WHERE user_id = $1 ORDER BY log_date DESC`,
    [req.session.userId]
  );
  res.json(rows.map(shapeLog));
});

app.post('/api/logs', requireAuth, async (req, res) => {
  try {
    const { date, rounds = 0, reading = 0, lecture = 0, service = 0 } = req.body;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date || '')) {
      return res.status(400).json({ error: 'A valid date (YYYY-MM-DD) is required' });
    }
    const r = Math.max(0, Number(rounds) || 0);
    const rd = Math.max(0, Number(reading) || 0);
    const l = Math.max(0, Number(lecture) || 0);
    const s = Math.max(0, Number(service) || 0);
    const score = computeScore(r, rd, l, s);

    // Server-side "history locked": block edits to an existing entry from a past week.
    const existing = await pool.query(
      'SELECT id FROM logs WHERE user_id = $1 AND log_date = $2',
      [req.session.userId, date]
    );
    const entryDate = new Date(date + 'T00:00:00Z');
    if (existing.rows.length && entryDate < getWeekStartUTC()) {
      return res.status(403).json({ error: 'History locked: entries from previous weeks cannot be edited' });
    }

    const { rows } = await pool.query(
      `INSERT INTO logs (user_id, log_date, rounds, reading, lecture, service, score)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (user_id, log_date)
       DO UPDATE SET rounds = $3, reading = $4, lecture = $5, service = $6, score = $7, updated_at = now()
       RETURNING to_char(log_date, 'YYYY-MM-DD') AS date, rounds, reading, lecture, service, score`,
      [req.session.userId, date, r, rd, l, s, score]
    );
    res.json(shapeLog(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not save the entry' });
  }
});

app.delete('/api/logs/:date', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM logs WHERE user_id = $1 AND log_date = $2', [req.session.userId, req.params.date]);
  res.json({ ok: true });
});

// Clear ALL of the current user's logs.
app.delete('/api/logs', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM logs WHERE user_id = $1', [req.session.userId]);
  res.json({ ok: true });
});

// ============================================================
//  JOURNAL ROUTES
// ============================================================
app.get('/api/journal', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT to_char(entry_date, 'YYYY-MM-DD') AS date, text
     FROM journals WHERE user_id = $1 ORDER BY entry_date DESC`,
    [req.session.userId]
  );
  res.json(rows);
});

app.post('/api/journal', requireAuth, async (req, res) => {
  const { date, text = '' } = req.body;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date || '')) {
    return res.status(400).json({ error: 'A valid date (YYYY-MM-DD) is required' });
  }
  const { rows } = await pool.query(
    `INSERT INTO journals (user_id, entry_date, text)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id, entry_date)
     DO UPDATE SET text = $3, updated_at = now()
     RETURNING to_char(entry_date, 'YYYY-MM-DD') AS date, text`,
    [req.session.userId, date, text]
  );
  res.json(rows[0]);
});

app.delete('/api/journal/:date', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM journals WHERE user_id = $1 AND entry_date = $2', [req.session.userId, req.params.date]);
  res.json({ ok: true });
});

// ============================================================
//  LEADERBOARD  (weekly score totals, visible to all logged-in users)
// ============================================================
app.get('/api/leaderboard', requireAuth, async (req, res) => {
  const weekStart = getWeekStartUTC().toISOString().slice(0, 10); // YYYY-MM-DD
  const { rows } = await pool.query(
    `SELECT u.username,
            COALESCE(NULLIF(TRIM(COALESCE(u.first_name, '') || ' ' || COALESCE(u.last_name, '')), ''), u.username) AS "displayName",
            COALESCE(SUM(l.score), 0)::int AS score
     FROM users u
     LEFT JOIN logs l ON l.user_id = u.id AND l.log_date >= $1
     GROUP BY u.id
     ORDER BY score DESC, "displayName" ASC`,
    [weekStart]
  );
  res.json(rows);
});

// ============================================================
//  ACCOUNT ROUTES  (the logged-in user editing their own profile)
// ============================================================

// Non-sensitive updates: name, avatar, theme. Any field left out is unchanged.
app.patch('/api/me', requireAuth, async (req, res) => {
  const { firstName, lastName, avatar, themeMode, colorTheme } = req.body;
  const { rows } = await pool.query(
    `UPDATE users SET
       first_name  = COALESCE($2, first_name),
       last_name   = COALESCE($3, last_name),
       avatar_url  = COALESCE($4, avatar_url),
       theme_mode  = COALESCE($5, theme_mode),
       color_theme = COALESCE($6, color_theme)
     WHERE id = $1
     RETURNING *`,
    [req.session.userId, firstName ?? null, lastName ?? null, avatar ?? null, themeMode ?? null, colorTheme ?? null]
  );
  res.json(toClientUser(rows[0]));
});

// Sensitive change (email or username): step 1, request a code sent to the
// email currently on file.
app.post('/api/me/request-change', requireAuth, async (req, res) => {
  try {
    const { type, newValue } = req.body;
    if (!['email', 'username'].includes(type) || !newValue) {
      return res.status(400).json({ error: 'type must be "email" or "username", with a newValue' });
    }
    const me = await getUserById(req.session.userId);
    const column = type === 'email' ? 'email' : 'username';
    const taken = await pool.query(`SELECT id FROM users WHERE ${column} = $1 AND id <> $2`, [newValue, me.id]);
    if (taken.rows.length) return res.status(409).json({ error: `That ${type} is already in use` });

    const purpose = type === 'email' ? 'email_change' : 'username_change';
    const code = await issueCode(me.id, purpose);
    // Sent to the CURRENT email on file, which proves control of the account.
    await sendCodeEmail(me.email, `Confirm your ${type} change`, code);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// Sensitive change: step 2, confirm the code and apply the change.
app.post('/api/me/confirm-change', requireAuth, async (req, res) => {
  try {
    const { type, newValue, code } = req.body;
    if (!['email', 'username'].includes(type) || !newValue) {
      return res.status(400).json({ error: 'Bad request' });
    }
    const me = await getUserById(req.session.userId);

    // Optional username-change cooldown. Set to 0 to disable.
    const COOLDOWN_DAYS = 7;
    if (type === 'username' && me.last_username_change_at) {
      const nextAllowed = new Date(me.last_username_change_at).getTime() + COOLDOWN_DAYS * 86400000;
      if (Date.now() < nextAllowed) {
        return res.status(429).json({ error: `You can change your username again after ${COOLDOWN_DAYS} days` });
      }
    }

    const purpose = type === 'email' ? 'email_change' : 'username_change';
    const valid = await findValidCode(me.id, purpose, code);
    if (!valid) return res.status(400).json({ error: 'Invalid or expired code' });

    const column = type === 'email' ? 'email' : 'username';
    const taken = await pool.query(`SELECT id FROM users WHERE ${column} = $1 AND id <> $2`, [newValue, me.id]);
    if (taken.rows.length) return res.status(409).json({ error: `That ${type} is already in use` });

    if (type === 'email') {
      await pool.query('UPDATE users SET email = $1 WHERE id = $2', [newValue, me.id]);
    } else {
      await pool.query('UPDATE users SET username = $1, last_username_change_at = now() WHERE id = $2', [newValue, me.id]);
    }
    await pool.query('UPDATE verification_codes SET consumed_at = now() WHERE id = $1', [valid.id]);
    res.json(toClientUser(await getUserById(me.id)));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// ============================================================
//  ADMIN ROUTES  (every check is enforced here on the server)
// ============================================================
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users ORDER BY created_at ASC');
  res.json(rows.map(toClientUser));
});

app.post('/api/admin/users/:id/promote', requireAdmin, async (req, res) => {
  const target = await getUserById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (!canManage(req.currentUser, target)) return res.status(403).json({ error: 'Not allowed' });
  if (target.role !== 'user') return res.status(400).json({ error: 'Only ordinary users can be promoted' });

  const count = await pool.query(`SELECT COUNT(*) FROM users WHERE role IN ('admin', 'root')`);
  if (Number(count.rows[0].count) >= 19) return res.status(400).json({ error: 'Admin limit reached' });

  await pool.query(`UPDATE users SET role = 'admin' WHERE id = $1`, [target.id]);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/demote', requireAdmin, async (req, res) => {
  if (req.currentUser.role !== 'root') return res.status(403).json({ error: 'Only root can demote admins' });
  const target = await getUserById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.role !== 'admin') return res.status(400).json({ error: 'Only admins can be demoted' });

  await pool.query(`UPDATE users SET role = 'user' WHERE id = $1`, [target.id]);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/reset-password', requireAdmin, async (req, res) => {
  const target = await getUserById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (!canManage(req.currentUser, target)) return res.status(403).json({ error: 'Not allowed' });

  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, target.id]);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const target = await getUserById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.id === req.currentUser.id) return res.status(400).json({ error: 'You cannot delete yourself' });
  if (!canManage(req.currentUser, target)) return res.status(403).json({ error: 'Not allowed' });

  await pool.query('DELETE FROM users WHERE id = $1', [target.id]);
  res.json({ ok: true });
});

// Read-only views of a devotee's entries / journal, for admins.
app.get('/api/admin/users/:username/logs', requireAdmin, async (req, res) => {
  const u = await pool.query('SELECT id FROM users WHERE username = $1', [req.params.username]);
  if (!u.rows.length) return res.status(404).json({ error: 'User not found' });
  const { rows } = await pool.query(
    `SELECT to_char(log_date, 'YYYY-MM-DD') AS date, rounds, reading, lecture, service, score
     FROM logs WHERE user_id = $1 ORDER BY log_date DESC`,
    [u.rows[0].id]
  );
  res.json(rows.map(shapeLog));
});

app.get('/api/admin/users/:username/journal', requireAdmin, async (req, res) => {
  const u = await pool.query('SELECT id FROM users WHERE username = $1', [req.params.username]);
  if (!u.rows.length) return res.status(404).json({ error: 'User not found' });
  const { rows } = await pool.query(
    `SELECT to_char(entry_date, 'YYYY-MM-DD') AS date, text
     FROM journals WHERE user_id = $1 ORDER BY entry_date DESC`,
    [u.rows[0].id]
  );
  res.json(rows);
});

// ============================================================
//  START (local) / EXPORT (Vercel)
// ============================================================
if (require.main === module) {
  app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
}
module.exports = app;
