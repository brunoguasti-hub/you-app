const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const { checkEmail } = require('../lib/emailCheck');
const { signToken, requireAuth } = require('../lib/auth');

const router = express.Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas tentativas. Espere um pouco e tente de novo.' }
});

const NAME_RE = /\S/;

function yearsSince(dateStr) {
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return null;
  const now = new Date();
  let age = now.getFullYear() - d.getFullYear();
  const m = now.getMonth() - d.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < d.getDate())) age--;
  return age;
}

router.post('/check-email', authLimiter, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'informe um e-mail' });
  const result = await checkEmail(email);
  const inUse = result.valid && !!db.prepare('SELECT id FROM users WHERE email = ?')
  .get(String(email).trim().toLowerCase());
  res.json({ ...result, inUse });
});

router.post('/signup', authLimiter, async (req, res) => {
  const { name, email, birth, password } = req.body || {};

            if (!name || !NAME_RE.test(name) || String(name).trim().length < 2) {
              return res.status(400).json({ error: 'nome invalido', field: 'name' });
            }
  const age = birth ? yearsSince(birth) : null;
  if (age === null || age < 13 || age > 120) {
    return res.status(400).json({ error: 'data de nascimento invalida', field: 'birth' });
  }
  if (!password || String(password).length < 8 ||
      !/[a-zA-Z]/.test(password) || !/\d/.test(password)) {
    return res.status(400).json({ error: 'senha fraca demais', field: 'pass' });
  }

            const emailCheck = await checkEmail(email);
  if (!emailCheck.valid) {
    return res.status(400).json({ error: 'e-mail invalido (' + emailCheck.reason + ')', field: 'email' });
  }
  const emailNorm = String(email).trim().toLowerCase();

            const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(emailNorm);
  if (exists) return res.status(409).json({ error: 'ja existe conta com esse e-mail', field: 'email' });

            const hash = await bcrypt.hash(String(password), 12);
  const info = db.prepare(
    'INSERT INTO users (name, email, password_hash, birth_date) VALUES (?, ?, ?, ?)'
    ).run(String(name).trim(), emailNorm, hash, String(birth));

            const user = { id: info.lastInsertRowid, name: String(name).trim(), email: emailNorm };
  res.status(201).json({ token: signToken(user), user });
});

router.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'informe e-mail e senha' });

            const emailNorm = String(email).trim().toLowerCase();
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(emailNorm);
  if (!row) return res.status(401).json({ error: 'e-mail ou senha incorretos' });

            const ok = await bcrypt.compare(String(password), row.password_hash);
  if (!ok) return res.status(401).json({ error: 'e-mail ou senha incorretos' });

            const user = { id: row.id, name: row.name, email: row.email };
  res.json({ token: signToken(user), user });
});

router.get('/me', requireAuth, (req, res) => {
  const row = db.prepare('SELECT id, name, email, birth_date, avatar_json, created_at FROM users WHERE id = ?')
  .get(req.user.sub);
  if (!row) return res.status(404).json({ error: 'usuario nao encontrado' });
  res.json({
    id: row.id, name: row.name, email: row.email, birthDate: row.birth_date,
    avatar: row.avatar_json ? JSON.parse(row.avatar_json) : null,
    createdAt: row.created_at
  });
});

router.put('/me/avatar', requireAuth, (req, res) => {
  const avatar = req.body && req.body.avatar;
  if (!avatar || typeof avatar !== 'object') {
    return res.status(400).json({ error: 'avatar invalido' });
  }
  db.prepare('UPDATE users SET avatar_json = ? WHERE id = ?')
  .run(JSON.stringify(avatar), req.user.sub);
  res.json({ ok: true });
});

const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

function addDays(dayStr, delta) {
  const d = new Date(dayStr + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + delta);
  return d.toISOString().slice(0, 10);
}

function computeStreak(userId, todayStr) {
  const rows = db.prepare(
    `SELECT day, COUNT(*) as n FROM task_logs
    WHERE user_id = ? AND done = 1 GROUP BY day`
    ).all(userId);
  const doneDays = new Set(rows.filter(r => r.n > 0).map(r => r.day));
  let cursor = doneDays.has(todayStr) ? todayStr : addDays(todayStr, -1);
  let streak = 0;
  while (doneDays.has(cursor)) {
    streak++;
    cursor = addDays(cursor, -1);
  }
  return streak;
}

router.get('/tasks/summary', requireAuth, (req, res) => {
  const day = String(req.query.day || '');
  const days = Math.min(31, Math.max(1, parseInt(req.query.days, 10) || 7));
  if (!DAY_RE.test(day)) return res.status(400).json({ error: 'parametro day invalido' });

           const todayRows = db.prepare(
             'SELECT task_key, done FROM task_logs WHERE user_id = ? AND day = ?'
             ).all(req.user.sub, day);
  const done = {};
  todayRows.forEach(r => { if (r.done) done[r.task_key] = true; });

           const history = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = addDays(day, -i);
    const row = db.prepare(
      'SELECT COUNT(*) as n FROM task_logs WHERE user_id = ? AND day = ? AND done = 1'
      ).get(req.user.sub, d);
    history.push({ day: d, doneCount: row.n });
  }

           res.json({ day, done, history, streak: computeStreak(req.user.sub, day) });
});

router.put('/tasks/toggle', requireAuth, (req, res) => {
  const { taskKey, done, day, onTime } = req.body || {};
  if (!taskKey || typeof taskKey !== 'string' || taskKey.length > 200) {
    return res.status(400).json({ error: 'taskKey invalida' });
  }
  if (!DAY_RE.test(String(day || ''))) {
    return res.status(400).json({ error: 'parametro day invalido' });
  }
  const onTimeVal = (done && (onTime === true || onTime === false)) ? (onTime ? 1 : 0) : null;
  db.prepare(`
  INSERT INTO task_logs (user_id, day, task_key, done, done_at, on_time)
  VALUES (@uid, @day, @key, @done, datetime('now'), @onTime)
  ON CONFLICT(user_id, day, task_key) DO UPDATE SET done = @done, done_at = datetime('now'), on_time = @onTime
  `).run({ uid: req.user.sub, day, key: taskKey, done: done ? 1 : 0, onTime: onTimeVal });
  res.json({ ok: true });
});

const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;
const RECURRENCE_RE = /^(daily|weekdays|weekends|custom:[0-6](,[0-6])*)$/;
const ACTION_VALUES = ['eat', 'skincare', 'work', 'exercise'];

function normTime(v) {
  if (v === null || v === undefined || v === '') return null;
  const s = String(v).trim();
  return TIME_RE.test(s) ? s : undefined;
}
function normRecurrence(v) {
  const s = String(v || 'daily').trim();
  return RECURRENCE_RE.test(s) ? s : undefined;
}
function normAction(v) {
  if (v === null || v === undefined || v === '') return null;
  return ACTION_VALUES.includes(String(v)) ? String(v) : undefined;
}

function ensureBaselineTasks(userId) {
  const autoCount = db.prepare('SELECT COUNT(*) n FROM task_defs WHERE user_id = ? AND auto = 1').get(userId).n;
  if (autoCount > 0) return;
  const insCat = db.prepare('INSERT INTO task_categories (user_id, name, icon, sort_order) VALUES (?, ?, ?, ?)');
  const insTask = db.prepare(`
  INSERT INTO task_defs (user_id, category_id, title, subtitle, time, recurrence, action, auto, sort_order)
  VALUES (?, ?, ?, ?, ?, 'daily', ?, 1, 0)
  `);
  const rotina = insCat.run(userId, 'Rotina', '', 0);
  insTask.run(userId, rotina.lastInsertRowid, 'Acordar', 'Acontece sozinho assim que voce abre o app de manha', '07:00', 'wake');
  const sono = insCat.run(userId, 'Sono', '', 900);
  insTask.run(userId, sono.lastInsertRowid, 'Dormir', 'Eu aviso na hora', '22:30', 'sleep');
}

function loadCatalog(userId) {
  const cats = db.prepare('SELECT * FROM task_categories WHERE user_id = ? ORDER BY sort_order, id').all(userId);
  const tasks = db.prepare('SELECT * FROM task_defs WHERE user_id = ? ORDER BY sort_order, id').all(userId);
  return cats.map(c => ({
    id: c.id, name: c.name, icon: c.icon, sortOrder: c.sort_order,
    tasks: tasks.filter(t => t.category_id === c.id).map(t => ({
      id: t.id, categoryId: t.category_id, title: t.title, subtitle: t.subtitle,
      time: t.time, recurrence: t.recurrence, action: t.action,
      auto: !!t.auto, sortOrder: t.sort_order
    }))
  }));
}

router.get('/task-defs', requireAuth, (req, res) => {
  ensureBaselineTasks(req.user.sub);
  const user = db.prepare('SELECT tasks_onboarded FROM users WHERE id = ?').get(req.user.sub);
  res.json({ categories: loadCatalog(req.user.sub), onboarded: !!(user && user.tasks_onboarded) });
});

router.post('/task-defs/onboarding-done', requireAuth, (req, res) => {
  db.prepare('UPDATE users SET tasks_onboarded = 1 WHERE id = ?').run(req.user.sub);
  res.json({ ok: true });
});

router.post('/task-categories', requireAuth, (req, res) => {
  const name = String((req.body && req.body.name) || '').trim();
  const icon = String((req.body && req.body.icon) || '').trim().slice(0, 8) || '';
  if (!name || name.length > 40) return res.status(400).json({ error: 'nome da categoria invalido' });
  const max = db.prepare('SELECT COALESCE(MAX(sort_order), -1) m FROM task_categories WHERE user_id = ?').get(req.user.sub).m;
  const info = db.prepare('INSERT INTO task_categories (user_id, name, icon, sort_order) VALUES (?, ?, ?, ?)')
  .run(req.user.sub, name, icon, max + 1);
  res.status(201).json({ id: info.lastInsertRowid, name, icon, sortOrder: max + 1, tasks: [] });
});

router.put('/task-categories/:id', requireAuth, (req, res) => {
  const cat = db.prepare('SELECT * FROM task_categories WHERE id = ? AND user_id = ?').get(req.params.id, req.user.sub);
  if (!cat) return res.status(404).json({ error: 'categoria nao encontrada' });
  const name = req.body && req.body.name !== undefined ? String(req.body.name).trim() : cat.name;
  const icon = req.body && req.body.icon !== undefined ? String(req.body.icon).trim().slice(0, 8) : cat.icon;
  if (!name || name.length > 40) return res.status(400).json({ error: 'nome da categoria invalido' });
  db.prepare('UPDATE task_categories SET name = ?, icon = ? WHERE id = ?').run(name, icon || '', cat.id);
  res.json({ ok: true });
});

router.delete('/task-categories/:id', requireAuth, (req, res) => {
  const cat = db.prepare('SELECT * FROM task_categories WHERE id = ? AND user_id = ?').get(req.params.id, req.user.sub);
  if (!cat) return res.status(404).json({ error: 'categoria nao encontrada' });
  const hasAuto = db.prepare('SELECT COUNT(*) n FROM task_defs WHERE category_id = ? AND auto = 1').get(cat.id).n;
  if (hasAuto) {
    return res.status(400).json({ error: 'essa categoria tem uma tarefa automatica' });
  }
  db.prepare('DELETE FROM task_categories WHERE id = ?').run(cat.id);
  res.json({ ok: true });
});

router.post('/task-defs', requireAuth, (req, res) => {
  const b = req.body || {};
  const cat = db.prepare('SELECT * FROM task_categories WHERE id = ? AND user_id = ?').get(b.categoryId, req.user.sub);
  if (!cat) return res.status(400).json({ error: 'categoria invalida' });
  const title = String(b.title || '').trim();
  if (!title || title.length > 60) return res.status(400).json({ error: 'titulo da tarefa invalido' });
  const subtitle = String(b.subtitle || '').trim().slice(0, 140);
  const time = normTime(b.time);
  if (time === undefined) return res.status(400).json({ error: 'horario invalido' });
  const recurrence = normRecurrence(b.recurrence);
  if (recurrence === undefined) return res.status(400).json({ error: 'recorrencia invalida' });
  const action = normAction(b.action);
  if (action === undefined) return res.status(400).json({ error: 'acao invalida' });
  const max = db.prepare('SELECT COALESCE(MAX(sort_order), -1) m FROM task_defs WHERE category_id = ?').get(cat.id).m;
  const info = db.prepare(`
  INSERT INTO task_defs (user_id, category_id, title, subtitle, time, recurrence, action, auto, sort_order)
  VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
  `).run(req.user.sub, cat.id, title, subtitle, time, recurrence, action, max + 1);
  res.status(201).json({
    id: info.lastInsertRowid, categoryId: cat.id, title, subtitle, time,
    recurrence, action, auto: false, sortOrder: max + 1
  });
});

router.put('/task-defs/reorder', requireAuth, (req, res) => {
  const b = req.body || {};
  const tx = db.transaction(() => {
    if (Array.isArray(b.categories)) {
      const stmt = db.prepare('UPDATE task_categories SET sort_order = ? WHERE id = ? AND user_id = ?');
      b.categories.forEach((id, i) => stmt.run(i, id, req.user.sub));
    }
    if (b.tasksByCategory && typeof b.tasksByCategory === 'object') {
      const stmt = db.prepare('UPDATE task_defs SET sort_order = ? WHERE id = ? AND user_id = ? AND category_id = ?');
      Object.keys(b.tasksByCategory).forEach(catId => {
        const ids = b.tasksByCategory[catId];
        if (Array.isArray(ids)) ids.forEach((id, i) => stmt.run(i, id, req.user.sub, catId));
      });
    }
  });
  tx();
  res.json({ ok: true });
});

router.put('/task-defs/:id', requireAuth, (req, res) => {
  const task = db.prepare('SELECT * FROM task_defs WHERE id = ? AND user_id = ?').get(req.params.id, req.user.sub);
  if (!task) return res.status(404).json({ error: 'tarefa nao encontrada' });
  const b = req.body || {};

           let categoryId = task.category_id;
  if (b.categoryId !== undefined && Number(b.categoryId) !== task.category_id) {
    const cat = db.prepare('SELECT id FROM task_categories WHERE id = ? AND user_id = ?').get(b.categoryId, req.user.sub);
    if (!cat) return res.status(400).json({ error: 'categoria invalida' });
    categoryId = cat.id;
  }

           const subtitle = b.subtitle !== undefined ? String(b.subtitle).trim().slice(0, 140) : task.subtitle;
  let time = task.time;
  if (b.time !== undefined) {
    time = normTime(b.time);
    if (time === undefined) return res.status(400).json({ error: 'horario invalido' });
  }

           if (task.auto) {
             if (!time) return res.status(400).json({ error: 'Acordar/Dormir sempre precisam de um horario' });
             db.prepare('UPDATE task_defs SET subtitle = ?, time = ?, category_id = ? WHERE id = ?')
             .run(subtitle, time, categoryId, task.id);
             return res.json({ ok: true });
           }

           const title = b.title !== undefined ? String(b.title).trim() : task.title;
  if (!title || title.length > 60) return res.status(400).json({ error: 'titulo da tarefa invalido' });
  const recurrence = b.recurrence !== undefined ? normRecurrence(b.recurrence) : task.recurrence;
  if (recurrence === undefined) return res.status(400).json({ error: 'recorrencia invalida' });
  const action = b.action !== undefined ? normAction(b.action) : task.action;
  if (action === undefined) return res.status(400).json({ error: 'acao invalida' });

           db.prepare('UPDATE task_defs SET category_id = ?, title = ?, subtitle = ?, time = ?, recurrence = ?, action = ? WHERE id = ?')
  .run(categoryId, title, subtitle, time, recurrence, action, task.id);
  res.json({ ok: true });
});

router.delete('/task-defs/:id', requireAuth, (req, res) => {
  const task = db.prepare('SELECT * FROM task_defs WHERE id = ? AND user_id = ?').get(req.params.id, req.user.sub);
  if (!task) return res.status(404).json({ error: 'tarefa nao encontrada' });
  if (task.auto) return res.status(400).json({ error: 'Acordar e Dormir nao podem ser excluidos' });
  db.prepare('DELETE FROM task_defs WHERE id = ?').run(task.id);
  res.json({ ok: true });
});

router.post('/task-defs/bulk', requireAuth, (req, res) => {
  const groups = (req.body && req.body.categories) || [];
  if (!Array.isArray(groups) || !groups.length) return res.status(400).json({ error: 'nada pra adicionar' });

            const tx = db.transaction(() => {
              groups.forEach(g => {
                const name = String(g.name || '').trim().slice(0, 40);
                if (!name) return;
                const icon = String(g.icon || '').trim().slice(0, 8) || '';
                let cat = db.prepare('SELECT * FROM task_categories WHERE user_id = ? AND lower(name) = lower(?)')
                .get(req.user.sub, name);
                if (!cat) {
                  const max = db.prepare('SELECT COALESCE(MAX(sort_order), -1) m FROM task_categories WHERE user_id = ?').get(req.user.sub).m;
                  const info = db.prepare('INSERT INTO task_categories (user_id, name, icon, sort_order) VALUES (?, ?, ?, ?)')
                  .run(req.user.sub, name, icon, max + 1);
                  cat = { id: info.lastInsertRowid };
                }
                const tasks = Array.isArray(g.tasks) ? g.tasks : [];
                let max = db.prepare('SELECT COALESCE(MAX(sort_order), -1) m FROM task_defs WHERE category_id = ?').get(cat.id).m;
                tasks.forEach(t => {
                  const title = String(t.title || '').trim().slice(0, 60);
                  if (!title) return;
                  const subtitle = String(t.subtitle || '').trim().slice(0, 140);
                  const time = normTime(t.time) || null;
                  const recurrence = normRecurrence(t.recurrence) || 'daily';
                  const action = normAction(t.action) || null;
                  max++;
                  db.prepare(`
                  INSERT INTO task_defs (user_id, category_id, title, subtitle, time, recurrence, action, auto, sort_order)
                  VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
                  `).run(req.user.sub, cat.id, title, subtitle, time, recurrence, action, max);
                });
              });
            });
  tx();
  res.json({ categories: loadCatalog(req.user.sub) });
});

function isScheduledOnDate(task, dayStr) {
  if (task.auto) return true;
  const dow = new Date(dayStr + 'T00:00:00Z').getUTCDay();
  const rec = task.recurrence || 'daily';
  if (rec === 'daily') return true;
  if (rec === 'weekdays') return dow >= 1 && dow <= 5;
  if (rec === 'weekends') return dow === 0 || dow === 6;
  if (rec.indexOf('custom:') === 0) {
    const days = rec.slice(7).split(',').map(Number);
    return days.indexOf(dow) !== -1;
  }
  return true;
}

function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }

function computeDayScore(userId, dayStr, allTasks) {
  const total = allTasks.filter(t => isScheduledOnDate(t, dayStr)).length;
  const logRows = db.prepare(
    'SELECT task_key, on_time FROM task_logs WHERE user_id = ? AND day = ? AND done = 1'
    ).all(userId, dayStr);
  const done = logRows.length;

const completionPct = total === 0 ? 1 : clamp(done / total, 0, 1);

const streak = computeStreak(userId, dayStr);
  const consistencyPct = clamp(streak, 0, 7) / 7;

const withTime = logRows.filter(r => r.on_time === 1 || r.on_time === 0);
  const punctualityPct = withTime.length === 0
  ? 1
    : withTime.filter(r => r.on_time === 1).length / withTime.length;

const score = Math.round(clamp(
  completionPct * 70 + consistencyPct * 20 + punctualityPct * 10, 0, 100
  ));

return { day: dayStr, total, done, streak, score };
}

router.get('/scores/history', requireAuth, (req, res) => {
  const day = String(req.query.day || '');
  const days = Math.min(90, Math.max(1, parseInt(req.query.days, 10) || 7));
  if (!DAY_RE.test(day)) return res.status(400).json({ error: 'parametro day invalido' });

           ensureBaselineTasks(req.user.sub);
  const allTasks = db.prepare('SELECT * FROM task_defs WHERE user_id = ?').all(req.user.sub)
  .map(t => ({ auto: !!t.auto, recurrence: t.recurrence }));

           const history = [];
  for (let i = days - 1; i >= 0; i--) {
    history.push(computeDayScore(req.user.sub, addDays(day, -i), allTasks));
  }

           let bestScore = null, bestDay = null, longestStreak = 0;
  history.forEach(h => {
    if (bestScore === null || h.score > bestScore) { bestScore = h.score; bestDay = h.day; }
    if (h.streak > longestStreak) longestStreak = h.streak;
  });

           res.json({
             day, days, history,
             today: history[history.length - 1] || null,
             records: { bestScore, bestDay, longestStreak }
           });
});

const ITEM_CATALOG = [
  { key: 'poster_minimal', slot: 'poster', tier: 'free', name: 'Poster Minimalista', desc: 'Um quadro simples, cor solida.', icon: '', unlockStreak: 3 },
  { key: 'poster_motiv', slot: 'poster', tier: 'free', name: 'Poster Motivacional', desc: 'Uma frase pra lembrar', icon: '', unlockStreak: 7 },
  { key: 'poster_neon', slot: 'poster', tier: 'premium', name: 'Poster Neon', desc: 'Quadro com brilho neon suave.', icon: '', price: 60 },
  { key: 'poster_stars', slot: 'poster', tier: 'premium', name: 'Poster Constelacao', desc: 'Um mapa de estrelas na parede.', icon: '', price: 90 },
  { key: 'plant_small', slot: 'plant', tier: 'free', name: 'Vasinho Simples', desc: 'Uma plantinha pra dar vida ao canto.', icon: '', unlockStreak: 3 },
  { key: 'plant_succulent', slot: 'plant', tier: 'free', name: 'Suculenta', desc: 'Baixa manutencao, bonita sempre.', icon: '', unlockStreak: 7 },
  { key: 'plant_big', slot: 'plant', tier: 'premium', name: 'Planta Grande', desc: 'Uma arvore de interior, bem cheia.', icon: '', price: 70 },
  { key: 'plant_bonsai', slot: 'plant', tier: 'premium', name: 'Bonsai Dourado', desc: 'Detalhe dourado no vaso.', icon: '', price: 100 },
  { key: 'lamp_basic', slot: 'lamp', tier: 'free', name: 'Luminaria Basica', desc: 'Uma luz quentinha de mesa.', icon: '', unlockStreak: 3 },
  { key: 'lamp_desk', slot: 'lamp', tier: 'free', name: 'Luminaria de Mesa', desc: 'Articulada, boa pra estudar.', icon: '', unlockStreak: 7 },
  { key: 'lamp_neon_pink', slot: 'lamp', tier: 'premium', name: 'Luminaria Neon Rosa', desc: 'Um brilho rosa suave no quarto.', icon: '', price: 80 },
  { key: 'lamp_star', slot: 'lamp', tier: 'premium', name: 'Luminaria Estelar', desc: 'Projeta pontinhos de luz no teto.', icon: '', price: 110 }
  ];
const ITEM_SLOTS = ['poster', 'plant', 'lamp'];

function coinsForScore(score) {
  return Math.round(clamp(score, 0, 100) / 10);
}

function ensureWalletRow(userId, todayStr) {
  let w = db.prepare('SELECT * FROM wallet WHERE user_id = ?').get(userId);
  if (!w) {
    const startDay = addDays(todayStr, -1);
    db.prepare('INSERT INTO wallet (user_id, balance, claimed_through_day) VALUES (?, 0, ?)').run(userId, startDay);
    w = { user_id: userId, balance: 0, claimed_through_day: startDay };
  }
  return w;
}

function settleWallet(userId, todayStr, allTasks) {
  let w = ensureWalletRow(userId, todayStr);
  let cursor = addDays(w.claimed_through_day, 1);
  let earned = 0;
  let guard = 0;
  while (cursor < todayStr && guard < 400) {
    const s = computeDayScore(userId, cursor, allTasks);
    earned += coinsForScore(s.score);
    cursor = addDays(cursor, 1);
    guard++;
  }
  if (guard > 0) {
    db.prepare('UPDATE wallet SET balance = balance + ?, claimed_through_day = ? WHERE user_id = ?')
    .run(earned, addDays(cursor, -1), userId);
    w = db.prepare('SELECT * FROM wallet WHERE user_id = ?').get(userId);
  }
  return w;
}

router.get('/economy/state', requireAuth, (req, res) => {
  const day = String(req.query.day || '');
  if (!DAY_RE.test(day)) return res.status(400).json({ error: 'parametro day invalido' });

           ensureBaselineTasks(req.user.sub);
  const allTasks = db.prepare('SELECT * FROM task_defs WHERE user_id = ?').all(req.user.sub)
  .map(t => ({ auto: !!t.auto, recurrence: t.recurrence }));

           const wallet = settleWallet(req.user.sub, day, allTasks);
  const streak = computeStreak(req.user.sub, day);

           const ownedSet = new Set(
             db.prepare('SELECT item_key FROM user_items WHERE user_id = ?').all(req.user.sub).map(r => r.item_key)
             );
  const newlyUnlocked = [];
  ITEM_CATALOG.forEach((it) => {
    if (it.tier === 'free' && streak >= it.unlockStreak && !ownedSet.has(it.key)) {
      db.prepare('INSERT OR IGNORE INTO user_items (user_id, item_key) VALUES (?, ?)').run(req.user.sub, it.key);
      ownedSet.add(it.key);
      newlyUnlocked.push(it.key);
    }
  });

           const equipped = {};
  db.prepare('SELECT slot, item_key FROM user_equipped WHERE user_id = ?').all(req.user.sub)
  .forEach((r) => { equipped[r.slot] = r.item_key; });

           res.json({
             balance: wallet.balance,
             streak,
             owned: Array.from(ownedSet),
             equipped,
             newlyUnlocked
           });
});

router.post('/economy/buy', requireAuth, (req, res) => {
  const itemKey = String((req.body && req.body.itemKey) || '');
  const item = ITEM_CATALOG.find((i) => i.key === itemKey);
  if (!item) return res.status(404).json({ error: 'item nao encontrado' });
  if (item.tier !== 'premium') return res.status(400).json({ error: 'esse item e liberado por constancia' });

            const already = db.prepare('SELECT 1 FROM user_items WHERE user_id = ? AND item_key = ?').get(req.user.sub, itemKey);
  if (already) return res.status(400).json({ error: 'voce ja tem esse item' });

            ensureWalletRow(req.user.sub, new Date().toISOString().slice(0, 10));
  const wallet = db.prepare('SELECT * FROM wallet WHERE user_id = ?').get(req.user.sub);
  if (!wallet || wallet.balance < item.price) {
    return res.status(400).json({ error: 'saldo insuficiente', needed: item.price, balance: wallet ? wallet.balance : 0 });
  }

            const tx = db.transaction(() => {
              db.prepare('UPDATE wallet SET balance = balance - ? WHERE user_id = ?').run(item.price, req.user.sub);
              db.prepare('INSERT INTO user_items (user_id, item_key) VALUES (?, ?)').run(req.user.sub, itemKey);
            });
  tx();

            const w = db.prepare('SELECT * FROM wallet WHERE user_id = ?').get(req.user.sub);
  res.json({ ok: true, balance: w.balance, item: itemKey });
});

router.post('/economy/equip', requireAuth, (req, res) => {
  const slot = String((req.body && req.body.slot) || '');
  const itemKeyRaw = req.body && req.body.itemKey;
  const itemKey = itemKeyRaw ? String(itemKeyRaw) : null;
  if (ITEM_SLOTS.indexOf(slot) === -1) return res.status(400).json({ error: 'slot invalido' });

            if (itemKey) {
              const item = ITEM_CATALOG.find((i) => i.key === itemKey && i.slot === slot);
              if (!item) return res.status(404).json({ error: 'item nao encontrado nesse slot' });
              const owned = db.prepare('SELECT 1 FROM user_items WHERE user_id = ? AND item_key = ?').get(req.user.sub, itemKey);
              if (!owned) return res.status(400).json({ error: 'voce ainda nao tem esse item' });
            }

            db.prepare(`
            INSERT INTO user_equipped (user_id, slot, item_key) VALUES (?, ?, ?)
            ON CONFLICT(user_id, slot) DO UPDATE SET item_key = excluded.item_key
            `).run(req.user.sub, slot, itemKey);

            res.json({ ok: true, slot, itemKey });
});

module.exports = router;
