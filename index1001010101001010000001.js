const express    = require('express');
const multer     = require('multer');
const path       = require('path');
const fs         = require('fs');
const fsp        = require('fs').promises;
const bcrypt     = require('bcryptjs');
const session    = require('express-session');
const crypto     = require('crypto');
const cookieParser = require('cookie-parser');

const app  = express();
const PORT = process.env.PORT || 3469;

// ============================================================
// IN-MEMORY JSON CACHE — hindari baca disk tiap request
// ============================================================
const _cache     = new Map(); // path → { data, mtime }
const _writeLock = new Map(); // path → Promise

async function readJSON(filePath) {
  try {
    const stat = await fsp.stat(filePath).catch(() => null);
    if (!stat) return null;
    const mtime = stat.mtimeMs;
    const cached = _cache.get(filePath);
    if (cached && cached.mtime === mtime) return cached.data;
    const raw  = await fsp.readFile(filePath, 'utf8');
    const data = JSON.parse(raw);
    _cache.set(filePath, { data, mtime });
    return data;
  } catch { return null; }
}

async function writeJSON(filePath, data) {
  // Serialize writes per-file to avoid race conditions
  const prev = _writeLock.get(filePath) || Promise.resolve();
  const next  = prev.then(async () => {
    try {
      const str = JSON.stringify(data, null, 2);
      await fsp.writeFile(filePath, str);
      // Invalidate cache
      const stat = await fsp.stat(filePath).catch(() => null);
      _cache.set(filePath, { data, mtime: stat?.mtimeMs ?? Date.now() });
      return true;
    } catch { return false; }
  });
  _writeLock.set(filePath, next.catch(() => {}));
  return next;
}

// ============================================================
// SECURITY HELPER: Persistent session secret
// ============================================================
function getOrCreateSessionSecret() {
  const secretFile = './data/.session_secret';
  try {
    if (fs.existsSync(secretFile)) return fs.readFileSync(secretFile, 'utf8').trim();
  } catch {}
  const secret = crypto.randomBytes(64).toString('hex');
  if (!fs.existsSync('./data')) fs.mkdirSync('./data', { recursive: true });
  fs.writeFileSync(secretFile, secret, { mode: 0o600 });
  return secret;
}

// ============================================================
// IN-MEMORY RATE LIMITER
// ============================================================
const rateLimitStore = new Map();

function rateLimit({ windowMs = 60000, max = 10, keyFn = (req) => req.ip } = {}) {
  return (req, res, next) => {
    const key   = keyFn(req);
    const now   = Date.now();
    const entry = rateLimitStore.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + windowMs; }
    entry.count++;
    rateLimitStore.set(key, entry);
    res.setHeader('X-RateLimit-Limit',     max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - entry.count));
    res.setHeader('X-RateLimit-Reset',     Math.ceil(entry.resetAt / 1000));
    if (entry.count > max) {
      return res.status(429).json({
        error: 'Terlalu banyak permintaan. Coba lagi nanti.',
        retryAfter: Math.ceil((entry.resetAt - now) / 1000)
      });
    }
    next();
  };
}

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of rateLimitStore.entries()) {
    if (now > val.resetAt) rateLimitStore.delete(key);
  }
}, 10 * 60 * 1000);

// ============================================================
// BRUTE FORCE TRACKER
// ============================================================
const loginAttempts = new Map();

function checkBruteForce(req, res, next) {
  const ip    = req.ip;
  const now   = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, blockedUntil: 0 };
  if (entry.blockedUntil > now) {
    const wait = Math.ceil((entry.blockedUntil - now) / 1000);
    return res.status(429).json({ error: `Terlalu banyak percobaan login. Coba lagi dalam ${wait} detik.` });
  }
  req._loginEntry = entry;
  req._loginIp    = ip;
  next();
}

function recordLoginFailure(ip) {
  const entry = loginAttempts.get(ip) || { count: 0, blockedUntil: 0 };
  entry.count++;
  if      (entry.count >= 15) entry.blockedUntil = Date.now() + 30 * 60 * 1000;
  else if (entry.count >= 10) entry.blockedUntil = Date.now() +  5 * 60 * 1000;
  else if (entry.count >=  5) entry.blockedUntil = Date.now() +      60 * 1000;
  loginAttempts.set(ip, entry);
}

function clearLoginAttempts(ip) { loginAttempts.delete(ip); }

// ============================================================
// INPUT VALIDATION
// ============================================================
const ALLOWED_USERNAME = /^[a-zA-Z0-9_]{3,30}$/;
const ALLOWED_EMAIL    = /^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{1,63}$/;

function sanitizeText(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str.replace(/<[^>]*>/g, '').trim().substring(0, maxLen);
}
function validateUsername(u) {
  if (!u || typeof u !== 'string') return 'Username wajib diisi';
  if (!ALLOWED_USERNAME.test(u)) return 'Username hanya boleh huruf, angka, underscore (3-30 karakter)';
  return null;
}
function validatePassword(p) {
  if (!p || typeof p !== 'string') return 'Password wajib diisi';
  if (p.length < 8)   return 'Password minimal 8 karakter';
  if (p.length > 128) return 'Password terlalu panjang';
  return null;
}

// ============================================================
// FILE SECURITY
// ============================================================
const ALLOWED_IMAGE_EXT = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
const ALLOWED_VIDEO_EXT = ['.mp4', '.webm', '.mov', '.avi', '.mkv'];
const ALLOWED_AUDIO_EXT = ['.mp3', '.wav', '.ogg', '.m4a', '.aac', '.flac'];

function isAllowedExt(filename, allowed) {
  return allowed.includes(path.extname(filename).toLowerCase());
}

// ============================================================
// SECURITY HEADERS
// ============================================================
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.removeHeader('X-Powered-By');
  next();
});

// ============================================================
// BODY SIZE LIMIT
// ============================================================
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

// Static files dengan cache headers (1 hari untuk uploads)
app.use('/uploads', express.static('uploads', {
  maxAge: '1d',
  etag:   true,
  lastModified: true
}));
app.use(express.static('public', { maxAge: '1h' }));

// ============================================================
// SESSION CONFIG
// ============================================================
app.use(session({
  secret:            getOrCreateSessionSecret(),
  resave:            false,
  saveUninitialized: false,
  cookie: {
    maxAge:   7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
  },
  name: 'mio.sid'
}));

// ============================================================
// GLOBAL RATE LIMIT
// ============================================================
app.use(rateLimit({ windowMs: 60000, max: 300 }));

// ============================================================
// LEVEL CONFIGURATION
// ============================================================
function generateLevelConfig() {
  const config = {};
  for (let level = 1; level <= 999; level++) {
    const minXP = Math.floor(50 * (level - 1) * level);
    let name = '', icon = '';
    if (level <= 10) {
      const names = ['Newbie','Rookie','Explorer','Creator','Influencer','Elite','Legend','Mythic','Godlike','Immortal'];
      const icons = ['🌱','⭐','🚀','🎨','🌟','💎','🏆','⚡','👑','🔥'];
      name = names[level - 1]; icon = icons[level - 1];
    } else if (level <= 50)  { name = 'Master';      icon = '✨'; }
    else if (level <= 100)   { name = 'Grandmaster'; icon = '💫'; }
    else if (level <= 200)   { name = 'Legendary';   icon = '🏅'; }
    else if (level <= 500)   { name = 'Mythic';      icon = '🌌'; }
    else                     { name = 'Ascendant';   icon = '👁️'; }
    config[level] = { name, minXp: minXP, icon };
  }
  return config;
}

async function calculateLevel(xp) {
  const levelsData   = await readJSON('data/levels.json');
  const levelConfig  = levelsData.levelConfig;
  for (let i = 999; i >= 1; i--) {
    if (levelConfig[i] && xp >= levelConfig[i].minXp) return i;
  }
  return 1;
}

// ============================================================
// INITIALIZE DATA FILES (sync sekali saat startup)
// ============================================================
function initializeDataFiles() {
  const dirs = [
    './data','./uploads','./uploads/images','./uploads/videos',
    './uploads/profiles','./uploads/comments','./uploads/music',
    './uploads/wallpapers','./uploads/chat'
  ];
  dirs.forEach(dir => { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); });

  const fullLevelConfig = generateLevelConfig();
  const files = {
    'data/login.json':          { users: [], adminUsers: [] },
    'data/user.json':           {},
    'data/database.json':       { posts: [], comments: [], likes: [] },
    'data/setting.user.json':   {},
    'data/verified.users.json': { verified: [] },
    'data/saved.login.json':    { savedLogins: [], rememberTokens: {} },
    'data/follow.data.json':    { followers: {}, following: {}, followRequests: {} },
    'data/levels.json':         { userLevels: {}, levelConfig: fullLevelConfig },
    'data/badges.json':         { customBadges: {}, badgeColors: { gold:'#FFD700',silver:'#C0C0C0',bronze:'#CD7F32',platinum:'#E5E4E2',diamond:'#B9F2FF' } },
    'data/chats.json':          { conversations: {}, messages: {} }
  };

  Object.entries(files).forEach(([filePath, defaultData]) => {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2));
    } else {
      try {
        const existing = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (filePath === 'data/levels.json' && (!existing.levelConfig || Object.keys(existing.levelConfig).length < 100)) {
          existing.levelConfig = fullLevelConfig;
        }
        Object.keys(defaultData).forEach(key => { if (existing[key] === undefined) existing[key] = defaultData[key]; });
        fs.writeFileSync(filePath, JSON.stringify(existing, null, 2));
      } catch { fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2)); }
    }
  });

  try {
    const loginData = JSON.parse(fs.readFileSync('data/login.json', 'utf8'));
    if (!loginData.adminUsers) loginData.adminUsers = [];
    if (loginData.users.length > 0 && loginData.adminUsers.length === 0) {
      const firstUser = loginData.users[0];
      loginData.adminUsers.push(firstUser.id);
      const verifiedData = JSON.parse(fs.readFileSync('data/verified.users.json', 'utf8'));
      if (!verifiedData.verified) verifiedData.verified = [];
      if (!verifiedData.verified.includes(firstUser.id)) {
        verifiedData.verified.push(firstUser.id);
        fs.writeFileSync('data/verified.users.json', JSON.stringify(verifiedData, null, 2));
      }
      fs.writeFileSync('data/login.json', JSON.stringify(loginData, null, 2));
    }
  } catch {}
}

initializeDataFiles();

// ============================================================
// ASYNC HELPER FUNCTIONS
// ============================================================
async function getUserById(userId) {
  if (!userId || typeof userId !== 'string') return null;
  const userData = await readJSON('data/user.json');
  return userData?.[userId] || null;
}
async function isAdmin(userId) {
  const loginData = await readJSON('data/login.json');
  return !!(loginData?.adminUsers?.includes(userId));
}
async function isVerified(userId) {
  const verifiedData = await readJSON('data/verified.users.json');
  return !!(verifiedData?.verified?.includes(userId));
}
async function getUserLevel(userId) {
  const levelsData = await readJSON('data/levels.json');
  if (!levelsData.userLevels[userId]) {
    levelsData.userLevels[userId] = { xp: 0, level: 1, totalPosts: 0, totalLikes: 0 };
    await writeJSON('data/levels.json', levelsData);
  }
  return levelsData.userLevels[userId];
}
async function addXP(userId, amount) {
  const levelsData = await readJSON('data/levels.json');
  if (!levelsData.userLevels[userId]) levelsData.userLevels[userId] = { xp: 0, level: 1, totalPosts: 0, totalLikes: 0 };
  const userLevel   = levelsData.userLevels[userId];
  userLevel.xp     += amount;
  const newLevel    = await calculateLevel(userLevel.xp);
  const leveledUp   = newLevel > userLevel.level;
  userLevel.level   = newLevel;
  await writeJSON('data/levels.json', levelsData);
  return { leveledUp, newLevel };
}
async function getLevelInfo(userId) {
  const levelsData  = await readJSON('data/levels.json');
  const levelConfig = levelsData.levelConfig;
  const userLevel   = await getUserLevel(userId);
  const cur  = levelConfig[userLevel.level] || levelConfig[999];
  const next = levelConfig[userLevel.level + 1] || null;
  return {
    level:     userLevel.level,
    xp:        userLevel.xp,
    levelName: cur.name,
    levelIcon: cur.icon,
    xpNeeded:  next ? next.minXp - userLevel.xp : 0,
    xpForNext: next ? next.minXp : userLevel.xp,
    totalPosts: userLevel.totalPosts,
    totalLikes: userLevel.totalLikes,
    progress:  next ? (userLevel.xp - cur.minXp) / (next.minXp - cur.minXp) * 100 : 100
  };
}
async function getUserBadges(userId) {
  const badgesData  = await readJSON('data/badges.json');
  const userBadges  = badgesData?.customBadges?.[userId] || [];
  const badges      = [];
  if (await isVerified(userId)) badges.push({ name:'Verified', icon:'✓', color:'#1da1f2', isCustom:false });
  if (await isAdmin(userId))    badges.push({ name:'Developer', icon:'👑', color:'#FF4444', isCustom:false });
  userBadges.forEach(b => badges.push({ ...b, isCustom:true }));
  return badges;
}
async function assignBadge(userId, badgeName, badgeIcon, badgeColor) {
  const badgesData = await readJSON('data/badges.json');
  if (!badgesData.customBadges[userId]) badgesData.customBadges[userId] = [];
  const existing = badgesData.customBadges[userId].find(b => b.name === badgeName);
  if (existing) { existing.icon = badgeIcon; existing.color = badgeColor; }
  else badgesData.customBadges[userId].push({ name: badgeName, icon: badgeIcon, color: badgeColor });
  await writeJSON('data/badges.json', badgesData);
  return true;
}
async function removeBadge(userId, badgeName) {
  const badgesData = await readJSON('data/badges.json');
  if (badgesData.customBadges[userId]) {
    badgesData.customBadges[userId] = badgesData.customBadges[userId].filter(b => b.name !== badgeName);
    await writeJSON('data/badges.json', badgesData);
    return true;
  }
  return false;
}
async function getAllCustomBadges() {
  const badgesData = await readJSON('data/badges.json');
  const allBadges  = [];
  for (const [userId, badges] of Object.entries(badgesData?.customBadges || {})) {
    const user = await getUserById(userId);
    if (user) badges.forEach(b => allBadges.push({ ...b, userId, username: user.username }));
  }
  return allBadges;
}
function generateRememberToken() { return crypto.randomBytes(32).toString('hex'); }
async function saveRememberToken(userId, username) {
  const savedData = await readJSON('data/saved.login.json');
  const token     = generateRememberToken();
  const expires   = Date.now() + 30 * 24 * 60 * 60 * 1000;
  if (!savedData.rememberTokens) savedData.rememberTokens = {};
  savedData.rememberTokens[token] = { userId, username, expires };
  await writeJSON('data/saved.login.json', savedData);
  return token;
}
async function validateRememberToken(token) {
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const savedData = await readJSON('data/saved.login.json');
  if (!savedData?.rememberTokens?.[token]) return null;
  const tokenData = savedData.rememberTokens[token];
  if (tokenData.expires < Date.now()) {
    delete savedData.rememberTokens[token];
    await writeJSON('data/saved.login.json', savedData);
    return null;
  }
  tokenData.expires = Date.now() + 30 * 24 * 60 * 60 * 1000;
  savedData.rememberTokens[token] = tokenData;
  await writeJSON('data/saved.login.json', savedData);
  return tokenData;
}
async function removeRememberToken(token) {
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return;
  const savedData = await readJSON('data/saved.login.json');
  if (savedData?.rememberTokens?.[token]) {
    delete savedData.rememberTokens[token];
    await writeJSON('data/saved.login.json', savedData);
  }
}
async function getFollowStatus(userId, targetUserId) {
  const followData = await readJSON('data/follow.data.json');
  return {
    isFollowing:    !!(followData?.following?.[userId]?.includes(targetUserId)),
    isFollowedBack: !!(followData?.followers?.[userId]?.includes(targetUserId)),
    followersCount:  followData?.followers?.[targetUserId]?.length || 0,
    followingCount:  followData?.following?.[targetUserId]?.length || 0
  };
}
async function toggleFollow(userId, targetUserId) {
  const followData = await readJSON('data/follow.data.json');
  if (!followData.following[userId])      followData.following[userId]      = [];
  if (!followData.followers[targetUserId]) followData.followers[targetUserId] = [];
  const idx = followData.following[userId].indexOf(targetUserId);
  let action;
  if (idx === -1) {
    followData.following[userId].push(targetUserId);
    followData.followers[targetUserId].push(userId);
    action = 'follow';
  } else {
    followData.following[userId].splice(idx, 1);
    const fi = followData.followers[targetUserId].indexOf(userId);
    if (fi !== -1) followData.followers[targetUserId].splice(fi, 1);
    action = 'unfollow';
  }
  const userData = await readJSON('data/user.json');
  if (userData[userId])       userData[userId].following       = followData.following[userId].length;
  if (userData[targetUserId]) userData[targetUserId].followers = followData.followers[targetUserId].length;
  await Promise.all([
    writeJSON('data/user.json', userData),
    writeJSON('data/follow.data.json', followData)
  ]);
  return { success:true, action, followersCount: followData.followers[targetUserId]?.length || 0 };
}

// CHAT HELPERS
function getConversationId(a, b) { return [a, b].sort().join('_'); }
async function getChatData() { return await readJSON('data/chats.json') || { conversations:{}, messages:{} }; }
async function saveChatData(data) { return await writeJSON('data/chats.json', data); }
async function getUnreadCount(userId) {
  const chatData = await getChatData();
  let total = 0;
  for (const convId in chatData.conversations) {
    const conv = chatData.conversations[convId];
    if (conv.participants.includes(userId)) total += conv.unreadCount?.[userId] || 0;
  }
  return total;
}

// DELETE USER
async function deleteUserData(userId) {
  const [loginData, userData, verifiedData, database, followData, savedData, levelsData, badgesData, chatData] = await Promise.all([
    readJSON('data/login.json'),
    readJSON('data/user.json'),
    readJSON('data/verified.users.json'),
    readJSON('data/database.json'),
    readJSON('data/follow.data.json'),
    readJSON('data/saved.login.json'),
    readJSON('data/levels.json'),
    readJSON('data/badges.json'),
    getChatData()
  ]);

  loginData.users      = loginData.users.filter(u => u.id !== userId);
  loginData.adminUsers = (loginData.adminUsers || []).filter(id => id !== userId);
  delete userData[userId];
  verifiedData.verified = (verifiedData.verified || []).filter(id => id !== userId);
  database.posts    = (database.posts    || []).filter(p => p.userId !== userId);
  database.comments = (database.comments || []).filter(c => c.userId !== userId);
  delete followData.followers[userId];
  delete followData.following[userId];
  Object.keys(followData.followers || {}).forEach(k => { followData.followers[k] = followData.followers[k].filter(id => id !== userId); });
  Object.keys(followData.following || {}).forEach(k => { followData.following[k] = followData.following[k].filter(id => id !== userId); });
  if (savedData.rememberTokens) {
    Object.keys(savedData.rememberTokens).forEach(token => {
      if (savedData.rememberTokens[token].userId === userId) delete savedData.rememberTokens[token];
    });
  }
  delete levelsData.userLevels[userId];
  delete badgesData.customBadges[userId];
  for (const convId in chatData.conversations) {
    if (chatData.conversations[convId].participants.includes(userId)) {
      delete chatData.conversations[convId];
      delete chatData.messages[convId];
    }
  }

  await Promise.all([
    writeJSON('data/login.json',          loginData),
    writeJSON('data/user.json',           userData),
    writeJSON('data/verified.users.json', verifiedData),
    writeJSON('data/database.json',       database),
    writeJSON('data/follow.data.json',    followData),
    writeJSON('data/saved.login.json',    savedData),
    writeJSON('data/levels.json',         levelsData),
    writeJSON('data/badges.json',         badgesData),
    saveChatData(chatData)
  ]);
}

// ============================================================
// MULTER STORAGE
// ============================================================
const storage = multer.diskStorage({
  destination(req, file, cb) {
    let folder = 'uploads/';
    if      (file.mimetype.startsWith('image/')) folder += 'images/';
    else if (file.mimetype.startsWith('video/')) folder += 'videos/';
    else if (file.mimetype.startsWith('audio/')) folder += 'music/';
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
    cb(null, folder);
  },
  filename(req, file, cb) {
    const unique = Date.now() + '-' + crypto.randomBytes(8).toString('hex');
    const ext    = path.extname(file.originalname).toLowerCase();
    cb(null, 'media-' + unique + ext);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024, files: 6 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (file.fieldname.startsWith('media')) {
      if ((file.mimetype.startsWith('image/') && ALLOWED_IMAGE_EXT.includes(ext)) ||
          (file.mimetype.startsWith('video/') && ALLOWED_VIDEO_EXT.includes(ext))) return cb(null, true);
      return cb(new Error('Format media tidak didukung'));
    }
    if (file.fieldname === 'music') {
      if (file.mimetype.startsWith('audio/') && ALLOWED_AUDIO_EXT.includes(ext)) return cb(null, true);
      return cb(new Error('Format audio tidak didukung'));
    }
    cb(new Error('Field tidak dikenal'));
  }
});

const profileUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/profiles/'),
    filename(req, file, cb) {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `${req.session.userId}-${file.fieldname}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}${ext}`);
    }
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (file.mimetype.startsWith('image/') && ALLOWED_IMAGE_EXT.includes(ext)) return cb(null, true);
    cb(new Error('Hanya gambar yang diizinkan'));
  }
});

const wallpaperUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/wallpapers/'),
    filename(req, file, cb) {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `wallpaper-${req.session.userId}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}${ext}`);
    }
  }),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if ((file.mimetype.startsWith('image/') && ALLOWED_IMAGE_EXT.includes(ext)) ||
        (file.mimetype.startsWith('video/') && ALLOWED_VIDEO_EXT.includes(ext))) return cb(null, true);
    cb(new Error('Format tidak didukung'));
  }
});

const commentUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/comments/'),
    filename(req, file, cb) {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, 'comment-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if ((file.mimetype.startsWith('image/') && ALLOWED_IMAGE_EXT.includes(ext)) ||
        (file.mimetype.startsWith('video/') && ALLOWED_VIDEO_EXT.includes(ext))) return cb(null, true);
    cb(new Error('Format tidak didukung'));
  }
});

const chatMediaUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/chat/'),
    filename(req, file, cb) {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, 'chat-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext);
    }
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if ((file.mimetype.startsWith('image/') && ALLOWED_IMAGE_EXT.includes(ext)) ||
        (file.mimetype.startsWith('video/') && ALLOWED_VIDEO_EXT.includes(ext)) ||
        (file.mimetype.startsWith('audio/') && ALLOWED_AUDIO_EXT.includes(ext))) return cb(null, true);
    cb(new Error('Format tidak didukung'));
  }
});

// ============================================================
// MIDDLEWARE AUTH
// ============================================================
async function requireLogin(req, res, next) {
  if (req.session.userId) return next();
  const token = req.cookies?.rememberToken;
  if (token) {
    const tokenData = await validateRememberToken(token);
    if (tokenData) {
      req.session.userId   = tokenData.userId;
      req.session.username = tokenData.username;
      return next();
    }
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

async function requireAdmin(req, res, next) {
  if (req.session.userId && await isAdmin(req.session.userId)) return next();
  return res.status(403).json({ error: 'Forbidden' });
}

// ============================================================
// ROUTES
// ============================================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// REGISTER
app.post('/api/register',
  rateLimit({ windowMs: 60 * 60 * 1000, max: 5, keyFn: (req) => 'reg:' + req.ip }),
  async (req, res) => {
    const { username, password, email } = req.body;
    const unameErr = validateUsername(username);
    if (unameErr) return res.status(400).json({ error: unameErr });
    const passErr = validatePassword(password);
    if (passErr) return res.status(400).json({ error: passErr });
    if (email && email.length > 0 && !ALLOWED_EMAIL.test(email))
      return res.status(400).json({ error: 'Format email tidak valid' });

    const loginData = await readJSON('data/login.json');
    if (loginData.users.some(u => u.username.toLowerCase() === username.toLowerCase()))
      return res.status(400).json({ error: 'Username sudah digunakan' });

    const hashedPassword = await bcrypt.hash(password, 12);
    const userId         = 'user_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
    const cleanEmail     = email ? sanitizeText(email, 254) : '';

    loginData.users.push({
      id: userId, username: sanitizeText(username, 30),
      password: hashedPassword, email: cleanEmail,
      createdAt: new Date().toISOString(), registeredIp: req.ip
    });

    const userData   = await readJSON('data/user.json');
    userData[userId] = {
      id: userId, username: sanitizeText(username, 30), email: cleanEmail,
      profilePic: '', wallpaper: '', bio: '',
      followers: 0, following: 0, posts: 0, createdAt: new Date().toISOString()
    };
    const levelsData = await readJSON('data/levels.json');
    levelsData.userLevels[userId] = { xp: 0, level: 1, totalPosts: 0, totalLikes: 0 };

    await Promise.all([
      writeJSON('data/login.json',  loginData),
      writeJSON('data/user.json',   userData),
      writeJSON('data/levels.json', levelsData)
    ]);
    res.json({ success: true, userId });
  }
);

// LOGIN
app.post('/api/login',
  rateLimit({ windowMs: 15 * 60 * 1000, max: 10, keyFn: (req) => 'login:' + req.ip }),
  checkBruteForce,
  async (req, res) => {
    const { username, password, rememberMe } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username dan password wajib diisi' });
    if (typeof username !== 'string' || username.length > 30)
      return res.status(400).json({ error: 'Username tidak valid' });

    const loginData  = await readJSON('data/login.json');
    const user       = loginData.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    const dummyHash  = '$2a$12$invalidhashtopreventtimingattacksXXXXXXXXXXXXXXXXXXXXXX';
    const valid      = user ? await bcrypt.compare(password, user.password) : await bcrypt.compare(password, dummyHash);

    if (!user || !valid) {
      recordLoginFailure(req.ip);
      return res.status(401).json({ error: 'Username atau password salah' });
    }
    clearLoginAttempts(req.ip);
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      req.session.userId   = user.id;
      req.session.username = user.username;
      if (rememberMe === true || rememberMe === 'true') {
        saveRememberToken(user.id, user.username).then(token => {
          res.cookie('rememberToken', token, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' });
          res.json({ success: true, userId: user.id, username: user.username });
        });
      } else {
        res.json({ success: true, userId: user.id, username: user.username });
      }
    });
  }
);

app.post('/api/logout', async (req, res) => {
  const token = req.cookies?.rememberToken;
  if (token) await removeRememberToken(token);
  req.session.destroy();
  res.clearCookie('mio.sid');
  res.clearCookie('rememberToken');
  res.json({ success: true });
});

app.get('/api/me', requireLogin, async (req, res) => {
  const [user, levelInfo, badges, unreadChats, adminStatus, verifiedStatus] = await Promise.all([
    getUserById(req.session.userId),
    getLevelInfo(req.session.userId),
    getUserBadges(req.session.userId),
    getUnreadCount(req.session.userId),
    isAdmin(req.session.userId),
    isVerified(req.session.userId)
  ]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    id: user.id, username: user.username, profilePic: user.profilePic,
    wallpaper: user.wallpaper, wallpaperSettings: user.wallpaperSettings,
    bio: user.bio, followers: user.followers, following: user.following, posts: user.posts,
    isVerified: verifiedStatus, isAdmin: adminStatus,
    level: levelInfo.level, levelName: levelInfo.levelName, levelIcon: levelInfo.levelIcon,
    xp: levelInfo.xp, xpProgress: levelInfo.progress, badges, unreadChats
  });
});

// PROFILE
app.get('/api/profile/:userId', requireLogin, async (req, res) => {
  const targetId = sanitizeText(req.params.userId, 50);
  const [user, database, followStatus, levelInfo, badges, verifiedStatus, adminStatus] = await Promise.all([
    getUserById(targetId),
    readJSON('data/database.json'),
    getFollowStatus(req.session.userId, targetId),
    getLevelInfo(targetId),
    getUserBadges(targetId),
    isVerified(targetId),
    isAdmin(targetId)
  ]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const userPosts  = (database.posts || []).filter(p => p.userId === targetId);
  const totalLikes = userPosts.reduce((sum, p) => sum + (p.likes?.length || 0), 0);
  res.json({
    id: user.id, username: user.username, profilePic: user.profilePic,
    wallpaper: user.wallpaper, wallpaperSettings: user.wallpaperSettings,
    bio: user.bio, followers: followStatus.followersCount, following: followStatus.followingCount,
    posts: user.posts, totalLikes, isVerified: verifiedStatus, isAdmin: adminStatus,
    isFollowing: followStatus.isFollowing, isFollowedBack: followStatus.isFollowedBack,
    level: levelInfo.level, levelName: levelInfo.levelName, levelIcon: levelInfo.levelIcon,
    xp: levelInfo.xp, xpProgress: levelInfo.progress, badges
  });
});

app.post('/api/profile/update', requireLogin, async (req, res) => {
  const bio      = sanitizeText(req.body.bio || '', 150);
  const userData = await readJSON('data/user.json');
  if (!userData[req.session.userId]) return res.status(404).json({ error: 'User not found' });
  userData[req.session.userId].bio = bio;
  await writeJSON('data/user.json', userData);
  res.json({ success: true });
});

app.post('/api/profile/upload-pic', requireLogin,
  profileUpload.fields([{ name:'profilePic', maxCount:1 }, { name:'wallpaper', maxCount:1 }]),
  async (req, res) => {
    const userData = await readJSON('data/user.json');
    if (req.files['profilePic']) userData[req.session.userId].profilePic = '/uploads/profiles/' + req.files['profilePic'][0].filename;
    if (req.files['wallpaper']) {
      const url = '/uploads/profiles/' + req.files['wallpaper'][0].filename;
      userData[req.session.userId].wallpaper = url;
      if (!userData[req.session.userId].wallpaperSettings) userData[req.session.userId].wallpaperSettings = {};
      userData[req.session.userId].wallpaperSettings.type  = 'image';
      userData[req.session.userId].wallpaperSettings.image = url;
    }
    await writeJSON('data/user.json', userData);
    res.json({ success:true, profilePic: userData[req.session.userId].profilePic, wallpaper: userData[req.session.userId].wallpaper });
  }
);

app.post('/api/profile/upload-wallpaper', requireLogin, wallpaperUpload.single('wallpaper'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Tidak ada file' });
  const fileUrl  = '/uploads/wallpapers/' + req.file.filename;
  const fileType = req.file.mimetype.startsWith('image/') ? 'image' : 'video';
  const userData = await readJSON('data/user.json');
  if (!userData[req.session.userId]) return res.status(404).json({ error: 'User not found' });
  userData[req.session.userId].wallpaper = fileUrl;
  if (!userData[req.session.userId].wallpaperSettings) userData[req.session.userId].wallpaperSettings = {};
  userData[req.session.userId].wallpaperSettings.type      = 'media';
  userData[req.session.userId].wallpaperSettings.mediaUrl  = fileUrl;
  userData[req.session.userId].wallpaperSettings.mediaType = fileType;
  await writeJSON('data/user.json', userData);
  res.json({ success:true, wallpaperUrl: fileUrl, mediaType: fileType });
});

app.post('/api/profile/wallpaper', requireLogin, async (req, res) => {
  const { wallpaperType, wallpaperValue, blur } = req.body;
  const allowedTypes = ['image', 'color', 'gradient', 'media'];
  if (wallpaperType && !allowedTypes.includes(wallpaperType))
    return res.status(400).json({ error: 'wallpaperType tidak valid' });
  const userData = await readJSON('data/user.json');
  if (!userData[req.session.userId]) return res.status(404).json({ error: 'User not found' });
  userData[req.session.userId].wallpaperSettings = {
    type:  wallpaperType || 'image',
    value: sanitizeText(wallpaperValue || '', 500),
    blur:  blur === true || blur === 'true'
  };
  await writeJSON('data/user.json', userData);
  res.json({ success:true, settings: userData[req.session.userId].wallpaperSettings });
});

app.get('/api/profile/wallpaper', requireLogin, async (req, res) => {
  const userData = await readJSON('data/user.json');
  const user     = userData[req.session.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const settings = user.wallpaperSettings || { type:'image', value: user.wallpaper||'', blur:false };
  res.json({ success:true, settings });
});

// UPLOAD
app.post('/api/upload',
  requireLogin,
  rateLimit({ windowMs: 60 * 60 * 1000, max: 20, keyFn: (req) => 'upload:' + req.session.userId }),
  (req, res) => {
    const uploadMiddleware = upload.fields([
      { name:'media0', maxCount:1 }, { name:'media1', maxCount:1 }, { name:'media2', maxCount:1 },
      { name:'media3', maxCount:1 }, { name:'media4', maxCount:1 }, { name:'music',  maxCount:1 }
    ]);
    uploadMiddleware(req, res, async (err) => {
      if (err) return res.status(400).json({ error: err.message });
      try {
        const caption    = sanitizeText(req.body.caption || '', 2200);
        const files      = req.files;
        if (!files || Object.keys(files).length === 0) return res.status(400).json({ error: 'Tidak ada file' });
        const mediaFiles = [];
        const count      = Math.min(parseInt(req.body.fileCount) || 0, 5);
        for (let i = 0; i < count; i++) {
          if (files[`media${i}`]?.[0]) mediaFiles.push(files[`media${i}`][0]);
        }
        if (!mediaFiles.length) return res.status(400).json({ error: 'Tidak ada media valid' });
        const musicFile  = files.music?.[0] || null;
        const mediaArray = mediaFiles.map(f => ({
          mediaUrl:  '/uploads/' + (f.mimetype.startsWith('image/') ? 'images/' : 'videos/') + f.filename,
          mediaType: f.mimetype.startsWith('image/') ? 'image' : 'video'
        }));
        const [database, userData] = await Promise.all([
          readJSON('data/database.json'),
          readJSON('data/user.json')
        ]);
        const postId  = 'post_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
        const newPost = {
          id: postId, userId: req.session.userId, username: req.session.username,
          mediaArray, mediaUrl: mediaArray[0].mediaUrl, mediaType: mediaArray[0].mediaType,
          caption, likes: [], comments: [],
          musicUrl:  musicFile ? '/uploads/music/' + musicFile.filename : null,
          musicName: musicFile ? sanitizeText(musicFile.originalname, 100) : null,
          createdAt: new Date().toISOString()
        };
        if (!database.posts) database.posts = [];
        database.posts.push(newPost);
        userData[req.session.userId].posts = (userData[req.session.userId].posts || 0) + 1;
        const [,, levelResult] = await Promise.all([
          writeJSON('data/database.json', database),
          writeJSON('data/user.json',     userData),
          addXP(req.session.userId, 50)
        ]);
        res.json({ success:true, post: newPost, leveledUp: levelResult.leveledUp, newLevel: levelResult.newLevel });
      } catch { res.status(500).json({ error: 'Upload gagal' }); }
    });
  }
);

// COMMENTS
app.post('/api/comment/upload-media', requireLogin, commentUpload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Tidak ada file' });
  res.json({ success:true, mediaUrl: '/uploads/comments/' + req.file.filename, mediaType: req.file.mimetype.startsWith('image/') ? 'image' : 'video' });
});

app.post('/api/post/:postId/comment',
  requireLogin,
  rateLimit({ windowMs: 10 * 60 * 1000, max: 30, keyFn: (req) => 'comment:' + req.session.userId }),
  async (req, res) => {
    const postId   = sanitizeText(req.params.postId, 60);
    const text     = sanitizeText(req.body.text || '', 1000);
    const mediaUrl = req.body.mediaUrl ? sanitizeText(req.body.mediaUrl, 300) : null;
    const mediaType = ['image','video'].includes(req.body.mediaType) ? req.body.mediaType : null;
    if (!text && !mediaUrl) return res.status(400).json({ error: 'Komentar tidak boleh kosong' });
    const [database, user] = await Promise.all([readJSON('data/database.json'), getUserById(req.session.userId)]);
    const postIndex = database.posts.findIndex(p => p.id === postId);
    if (postIndex === -1) return res.status(404).json({ error: 'Post not found' });
    const commentId  = 'comment_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
    const newComment = {
      id: commentId, postId, userId: req.session.userId, username: req.session.username,
      text, mediaUrl, mediaType, profilePic: user?.profilePic || '',
      isVerified: await isVerified(req.session.userId), createdAt: new Date().toISOString()
    };
    if (!database.comments) database.comments = [];
    database.comments.push(newComment);
    if (!database.posts[postIndex].comments) database.posts[postIndex].comments = [];
    database.posts[postIndex].comments.push(commentId);
    await Promise.all([writeJSON('data/database.json', database), addXP(req.session.userId, 10)]);
    res.json({ success:true, comment: newComment });
  }
);

app.get('/api/post/:postId/comments', requireLogin, async (req, res) => {
  const postId   = sanitizeText(req.params.postId, 60);
  const database = await readJSON('data/database.json');
  const comments = (database.comments || [])
    .filter(c => c.postId === postId)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  res.json({ comments });
});

// FEED
app.get('/api/feed', requireLogin, async (req, res) => {
  const [database, followData, userData] = await Promise.all([
    readJSON('data/database.json'),
    readJSON('data/follow.data.json'),
    readJSON('data/user.json')
  ]);
  const verifiedData = await readJSON('data/verified.users.json');
  const following    = followData.following?.[req.session.userId] || [];
  const posts = (database.posts || [])
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .map(post => ({
      ...post,
      likesCount:      post.likes?.length || 0,
      commentsCount:   post.comments?.length || 0,
      isLiked:         post.likes?.includes(req.session.userId) || false,
      isFromFollowing: following.includes(post.userId) || post.userId === req.session.userId,
      userProfilePic:  userData[post.userId]?.profilePic || '',
      isVerified:      verifiedData.verified?.includes(post.userId) || false
    }));
  res.json({ posts });
});

app.get('/api/user/:userId/posts', requireLogin, async (req, res) => {
  const targetId = sanitizeText(req.params.userId, 50);
  const database = await readJSON('data/database.json');
  const posts = (database.posts || [])
    .filter(p => p.userId === targetId)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .map(p => ({ ...p, likesCount: p.likes?.length || 0, commentsCount: p.comments?.length || 0, isLiked: p.likes?.includes(req.session.userId) || false }));
  res.json({ posts });
});

app.post('/api/post/:postId/like', requireLogin,
  rateLimit({ windowMs: 60000, max: 60, keyFn: (req) => 'like:' + req.session.userId }),
  async (req, res) => {
    const postId   = sanitizeText(req.params.postId, 60);
    const database = await readJSON('data/database.json');
    const idx      = database.posts.findIndex(p => p.id === postId);
    if (idx === -1) return res.status(404).json({ error: 'Post not found' });
    const post = database.posts[idx];
    if (!post.likes) post.likes = [];
    const likeIdx = post.likes.indexOf(req.session.userId);
    let liked = false;
    if (likeIdx === -1) { post.likes.push(req.session.userId); liked = true; await Promise.all([addXP(req.session.userId, 5), addXP(post.userId, 10)]); }
    else { post.likes.splice(likeIdx, 1); liked = false; }
    database.posts[idx] = post;
    await writeJSON('data/database.json', database);
    res.json({ success:true, liked, likesCount: post.likes.length });
  }
);

app.get('/api/search', requireLogin,
  rateLimit({ windowMs: 60000, max: 30, keyFn: (req) => 'search:' + req.session.userId }),
  async (req, res) => {
    const query = sanitizeText(req.query.q || '', 50).toLowerCase();
    if (!query || query.length < 2) return res.json({ users: [] });
    const [userData, verifiedData] = await Promise.all([readJSON('data/user.json'), readJSON('data/verified.users.json')]);
    const users = Object.values(userData)
      .filter(u => u.username.toLowerCase().includes(query))
      .map(u => ({ id: u.id, username: u.username, profilePic: u.profilePic, bio: u.bio, isVerified: verifiedData.verified?.includes(u.id) || false }))
      .slice(0, 20);
    res.json({ users });
  }
);

app.post('/api/user/:userId/follow', requireLogin,
  rateLimit({ windowMs: 60000, max: 20, keyFn: (req) => 'follow:' + req.session.userId }),
  async (req, res) => {
    const targetId = sanitizeText(req.params.userId, 50);
    if (targetId === req.session.userId) return res.status(400).json({ error: 'Tidak bisa follow diri sendiri' });
    if (!await getUserById(targetId)) return res.status(404).json({ error: 'User not found' });
    const result = await toggleFollow(req.session.userId, targetId);
    res.json(result);
  }
);

app.get('/api/explore', requireLogin, async (req, res) => {
  const [database, verifiedData] = await Promise.all([readJSON('data/database.json'), readJSON('data/verified.users.json')]);
  const page       = Math.max(1, parseInt(req.query.page) || 1);
  const limit      = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
  const startIndex = (page - 1) * limit;
  const posts = (database.posts || [])
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(startIndex, startIndex + limit)
    .map(p => ({ ...p, likesCount: p.likes?.length || 0, commentsCount: p.comments?.length || 0, isLiked: p.likes?.includes(req.session.userId) || false, isVerified: verifiedData.verified?.includes(p.userId) || false }));
  res.json({ posts, hasMore: startIndex + limit < (database.posts || []).length });
});

// LEADERBOARD
app.get('/api/leaderboard', requireLogin, async (req, res) => {
  const [userData, levelsData, verifiedData, loginData] = await Promise.all([
    readJSON('data/user.json'),
    readJSON('data/levels.json'),
    readJSON('data/verified.users.json'),
    readJSON('data/login.json')
  ]);
  const leaderboardData = [];
  for (const [userId, user] of Object.entries(userData)) {
    const levelInfo = levelsData.userLevels[userId] || { xp:0, level:1, totalPosts:0, totalLikes:0 };
    leaderboardData.push({
      userId, username: user.username, profilePic: user.profilePic || '',
      level: levelInfo.level, xp: levelInfo.xp, totalPosts: levelInfo.totalPosts || 0,
      totalLikes: levelInfo.totalLikes || 0, followers: user.followers || 0,
      isVerified: verifiedData.verified?.includes(userId) || false,
      isAdmin:    loginData.adminUsers?.includes(userId) || false
    });
  }
  const sortedByLevel = [...leaderboardData].sort((a, b) => b.level !== a.level ? b.level - a.level : b.xp - a.xp);
  const topUsers       = sortedByLevel.slice(0, 50);
  const topDevelopers  = leaderboardData.filter(u => u.isAdmin).sort((a, b) => b.level !== a.level ? b.level - a.level : b.xp - a.xp);
  const currentUserRank = sortedByLevel.findIndex(u => u.userId === req.session.userId) + 1;
  res.json({ success:true, topUsers, topDevelopers, currentUserRank, totalUsers: leaderboardData.length });
});

// CHAT
app.get('/api/chat/conversations', requireLogin, async (req, res) => {
  const [chatData, userData] = await Promise.all([getChatData(), readJSON('data/user.json')]);
  const verifiedData = await readJSON('data/verified.users.json');
  const loginData    = await readJSON('data/login.json');
  const userId       = req.session.userId;
  const conversations = [];
  for (const [convId, conv] of Object.entries(chatData.conversations)) {
    if (!conv.participants.includes(userId)) continue;
    const otherUserId = conv.participants.find(id => id !== userId);
    const otherUser   = userData[otherUserId];
    if (!otherUser) continue;
    const messages    = chatData.messages[convId] || [];
    const lastMessage = messages[messages.length - 1] || null;
    const unreadCount = (conv.unreadCount || {})[userId] || 0;
    conversations.push({
      id: convId,
      otherUser: { id: otherUserId, username: otherUser.username, profilePic: otherUser.profilePic || '',
        isVerified: verifiedData.verified?.includes(otherUserId) || false,
        isAdmin:    loginData.adminUsers?.includes(otherUserId)  || false },
      lastMessage: lastMessage ? { text: lastMessage.text, mediaType: lastMessage.mediaType || null,
        senderId: lastMessage.senderId, createdAt: lastMessage.createdAt, isRead: lastMessage.isRead || false } : null,
      unreadCount, updatedAt: conv.updatedAt || conv.createdAt
    });
  }
  conversations.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
  res.json({ success:true, conversations });
});

app.get('/api/chat/with/:userId', requireLogin, async (req, res) => {
  const targetId  = sanitizeText(req.params.userId, 50);
  const myId      = req.session.userId;
  if (targetId === myId) return res.status(400).json({ error: 'Tidak bisa chat dengan diri sendiri' });
  const [targetUser, chatData] = await Promise.all([getUserById(targetId), getChatData()]);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  const convId = getConversationId(myId, targetId);
  if (!chatData.conversations[convId]) {
    chatData.conversations[convId] = { id: convId, participants: [myId, targetId], createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), unreadCount: { [myId]:0, [targetId]:0 } };
    chatData.messages[convId] = [];
    await saveChatData(chatData);
  }
  const [vT, aT] = await Promise.all([isVerified(targetId), isAdmin(targetId)]);
  res.json({ success:true, conversationId: convId, otherUser: { id: targetId, username: targetUser.username, profilePic: targetUser.profilePic || '', bio: targetUser.bio || '', isVerified: vT, isAdmin: aT } });
});

app.get('/api/chat/:conversationId/messages', requireLogin, async (req, res) => {
  const { conversationId } = req.params;
  const userId   = req.session.userId;
  const chatData = await getChatData();
  const conv     = chatData.conversations[conversationId];
  if (!conv || !conv.participants.includes(userId)) return res.status(403).json({ error: 'Akses ditolak' });
  if (conv.unreadCount) conv.unreadCount[userId] = 0;
  const messages = chatData.messages[conversationId] || [];
  messages.forEach(msg => { if (msg.senderId !== userId) msg.isRead = true; });
  await saveChatData(chatData);
  const userData   = await readJSON('data/user.json');
  const verifiedData = await readJSON('data/verified.users.json');
  const page       = Math.max(1, parseInt(req.query.page) || 1);
  const limit      = 30;
  const total      = messages.length;
  const startIndex = Math.max(0, total - page * limit);
  const endIndex   = total - (page - 1) * limit;
  const enriched   = messages.slice(startIndex, endIndex).map(msg => {
    const sender = userData[msg.senderId];
    return { ...msg, senderUsername: sender?.username || 'Unknown', senderProfilePic: sender?.profilePic || '', isVerified: verifiedData.verified?.includes(msg.senderId) || false };
  });
  res.json({ success:true, messages: enriched, hasMore: startIndex > 0, total });
});

app.post('/api/chat/:conversationId/send', requireLogin,
  rateLimit({ windowMs: 60000, max: 60, keyFn: (req) => 'chat:' + req.session.userId }),
  async (req, res) => {
    const { conversationId } = req.params;
    const text      = sanitizeText(req.body.text || '', 2000);
    const mediaUrl  = req.body.mediaUrl ? sanitizeText(req.body.mediaUrl, 300) : null;
    const mediaType = ['image','video','audio'].includes(req.body.mediaType) ? req.body.mediaType : null;
    const userId    = req.session.userId;
    if (!text && !mediaUrl) return res.status(400).json({ error: 'Pesan tidak boleh kosong' });
    const chatData = await getChatData();
    const conv     = chatData.conversations[conversationId];
    if (!conv || !conv.participants.includes(userId)) return res.status(403).json({ error: 'Akses ditolak' });
    const messageId = 'msg_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
    const newMsg    = { id: messageId, conversationId, senderId: userId, text, mediaUrl, mediaType, isRead:false, createdAt: new Date().toISOString() };
    if (!chatData.messages[conversationId]) chatData.messages[conversationId] = [];
    chatData.messages[conversationId].push(newMsg);
    const otherUserId = conv.participants.find(id => id !== userId);
    if (!conv.unreadCount) conv.unreadCount = {};
    conv.unreadCount[otherUserId] = (conv.unreadCount[otherUserId] || 0) + 1;
    conv.updatedAt = new Date().toISOString();
    const [,sender] = await Promise.all([saveChatData(chatData), getUserById(userId)]);
    const verifiedData = await readJSON('data/verified.users.json');
    res.json({ success:true, message: { ...newMsg, senderUsername: sender?.username || 'Unknown', senderProfilePic: sender?.profilePic || '', isVerified: verifiedData.verified?.includes(userId) || false } });
  }
);

app.post('/api/chat/upload-media', requireLogin, chatMediaUpload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Tidak ada file' });
  let mediaType = 'image';
  if (req.file.mimetype.startsWith('video/')) mediaType = 'video';
  else if (req.file.mimetype.startsWith('audio/')) mediaType = 'audio';
  res.json({ success:true, mediaUrl: '/uploads/chat/' + req.file.filename, mediaType });
});

app.delete('/api/chat/message/:messageId', requireLogin, async (req, res) => {
  const messageId = sanitizeText(req.params.messageId, 80);
  const userId    = req.session.userId;
  const chatData  = await getChatData();
  let found = false;
  for (const convId in chatData.messages) {
    const idx = chatData.messages[convId].findIndex(m => m.id === messageId);
    if (idx !== -1) {
      if (chatData.messages[convId][idx].senderId !== userId) return res.status(403).json({ error: 'Tidak bisa menghapus pesan orang lain' });
      chatData.messages[convId][idx].deleted  = true;
      chatData.messages[convId][idx].text     = '';
      chatData.messages[convId][idx].mediaUrl = null;
      found = true; break;
    }
  }
  if (!found) return res.status(404).json({ error: 'Pesan tidak ditemukan' });
  await saveChatData(chatData);
  res.json({ success:true });
});

app.get('/api/chat/unread', requireLogin, async (req, res) => {
  res.json({ success:true, count: await getUnreadCount(req.session.userId) });
});

// ADMIN ROUTES
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const [userData, verifiedData, levelsData, loginData] = await Promise.all([
    readJSON('data/user.json'), readJSON('data/verified.users.json'),
    readJSON('data/levels.json'), readJSON('data/login.json')
  ]);
  const users = await Promise.all(Object.values(userData).map(async u => ({
    id: u.id, username: u.username, profilePic: u.profilePic, bio: u.bio,
    posts: u.posts || 0, followers: u.followers || 0, following: u.following || 0,
    isVerified: verifiedData.verified?.includes(u.id) || false,
    isAdmin:    loginData.adminUsers?.includes(u.id) || false,
    level: levelsData.userLevels[u.id]?.level || 1,
    xp:    levelsData.userLevels[u.id]?.xp    || 0,
    badges: await getUserBadges(u.id), createdAt: u.createdAt,
    registeredIp: u.registeredIp || '-'
  })));
  res.json({ users });
});

app.get('/api/admin/posts', requireAdmin, async (req, res) => {
  const [database, userData] = await Promise.all([readJSON('data/database.json'), readJSON('data/user.json')]);
  const posts = (database.posts || [])
    .map(p => ({ ...p, username: userData[p.userId]?.username || 'Unknown', userProfilePic: userData[p.userId]?.profilePic || '', likesCount: p.likes?.length || 0, commentsCount: p.comments?.length || 0 }))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ posts });
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const [userData, database, loginData, verifiedData, levelsData, chatData] = await Promise.all([
    readJSON('data/user.json'), readJSON('data/database.json'),
    readJSON('data/login.json'), readJSON('data/verified.users.json'),
    readJSON('data/levels.json'), getChatData()
  ]);
  let totalXP = 0;
  for (const uid in levelsData.userLevels) totalXP += levelsData.userLevels[uid].xp || 0;
  const totalMessages = Object.values(chatData.messages || {}).reduce((sum, msgs) => sum + msgs.length, 0);
  res.json({
    stats: {
      totalUsers: Object.keys(userData).length, totalPosts: (database.posts || []).length,
      totalComments: database.comments?.length || 0, totalAdmins: loginData.adminUsers?.length || 0,
      totalVerified: verifiedData.verified?.length || 0,
      totalImages: (database.posts || []).filter(p => p.mediaType === 'image').length,
      totalVideos: (database.posts || []).filter(p => p.mediaType === 'video').length,
      totalXP, totalMessages, blockedIPs: rateLimitStore.size
    }
  });
});

app.post('/api/admin/verify/:userId', requireAdmin, async (req, res) => {
  const targetId     = sanitizeText(req.params.userId, 50);
  const verifiedData = await readJSON('data/verified.users.json');
  if (!verifiedData.verified) verifiedData.verified = [];
  if (!verifiedData.verified.includes(targetId)) {
    verifiedData.verified.push(targetId);
    await Promise.all([writeJSON('data/verified.users.json', verifiedData), addXP(targetId, 100)]);
  }
  res.json({ success:true, verified:true });
});

app.post('/api/admin/unverify/:userId', requireAdmin, async (req, res) => {
  const targetId     = sanitizeText(req.params.userId, 50);
  const verifiedData = await readJSON('data/verified.users.json');
  if (verifiedData.verified) { verifiedData.verified = verifiedData.verified.filter(id => id !== targetId); await writeJSON('data/verified.users.json', verifiedData); }
  res.json({ success:true, verified:false });
});

app.post('/api/admin/make-admin/:userId', requireAdmin, async (req, res) => {
  const targetId  = sanitizeText(req.params.userId, 50);
  const loginData = await readJSON('data/login.json');
  if (!loginData.adminUsers) loginData.adminUsers = [];
  if (!loginData.adminUsers.includes(targetId)) {
    loginData.adminUsers.push(targetId);
    await Promise.all([writeJSON('data/login.json', loginData), addXP(targetId, 200)]);
  }
  res.json({ success:true, isAdmin:true });
});

app.post('/api/admin/remove-admin/:userId', requireAdmin, async (req, res) => {
  const targetId  = sanitizeText(req.params.userId, 50);
  if (targetId === req.session.userId) return res.status(400).json({ error: 'Tidak bisa menghapus status admin diri sendiri' });
  const loginData = await readJSON('data/login.json');
  if (loginData.adminUsers) { loginData.adminUsers = loginData.adminUsers.filter(id => id !== targetId); await writeJSON('data/login.json', loginData); }
  res.json({ success:true, isAdmin:false });
});

app.delete('/api/admin/post/:postId', requireAdmin, async (req, res) => {
  const postId   = sanitizeText(req.params.postId, 60);
  const database = await readJSON('data/database.json');
  const idx      = database.posts.findIndex(p => p.id === postId);
  if (idx === -1) return res.status(404).json({ error: 'Post not found' });
  const post = database.posts[idx];
  database.posts.splice(idx, 1);
  if (database.comments) database.comments = database.comments.filter(c => c.postId !== postId);
  const userData = await readJSON('data/user.json');
  if (userData[post.userId]) userData[post.userId].posts = Math.max(0, (userData[post.userId].posts || 0) - 1);
  await Promise.all([writeJSON('data/database.json', database), writeJSON('data/user.json', userData)]);
  res.json({ success:true });
});

app.delete('/api/admin/user/:userId', requireAdmin, async (req, res) => {
  const targetId = sanitizeText(req.params.userId, 50);
  if (targetId === req.session.userId) return res.status(400).json({ error: 'Tidak bisa menghapus akun sendiri' });
  const user = await getUserById(targetId);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });
  try {
    await deleteUserData(targetId);
    res.json({ success:true, message: `Akun @${user.username} berhasil dihapus` });
  } catch (err) { console.error('Error deleting user:', err); res.status(500).json({ error: 'Gagal menghapus akun' }); }
});

// IP BLOCK
const blockedIPs = new Set();
app.post('/api/admin/block-ip', requireAdmin, (req, res) => {
  const { ip } = req.body;
  if (!ip || typeof ip !== 'string') return res.status(400).json({ error: 'IP tidak valid' });
  blockedIPs.add(ip.trim());
  res.json({ success:true, message: `IP ${ip} diblokir` });
});
app.post('/api/admin/unblock-ip', requireAdmin, (req, res) => {
  blockedIPs.delete(req.body?.ip?.trim());
  res.json({ success:true });
});
app.get('/api/admin/blocked-ips', requireAdmin, (req, res) => res.json({ ips: [...blockedIPs] }));

app.use((req, res, next) => {
  if (blockedIPs.has(req.ip)) return res.status(403).json({ error: 'Akses diblokir' });
  next();
});

app.get('/api/admin/badges', requireAdmin, async (req, res) => res.json({ badges: await getAllCustomBadges() }));

app.post('/api/admin/assign-badge', requireAdmin, async (req, res) => {
  const userId    = sanitizeText(req.body.userId || '', 50);
  const badgeName = sanitizeText(req.body.badgeName || '', 30);
  if (!userId || !badgeName) return res.status(400).json({ error: 'User ID dan nama badge diperlukan' });
  if (!await getUserById(userId)) return res.status(404).json({ error: 'User tidak ditemukan' });
  const result = await assignBadge(userId, badgeName, sanitizeText(req.body.badgeIcon || '🏷️', 10), sanitizeText(req.body.badgeColor || '#667eea', 20));
  res.json(result ? { success:true } : { error:'Gagal' });
});

app.post('/api/admin/remove-badge', requireAdmin, async (req, res) => {
  const userId    = sanitizeText(req.body.userId || '', 50);
  const badgeName = sanitizeText(req.body.badgeName || '', 30);
  if (!userId || !badgeName) return res.status(400).json({ error: 'Parameter kurang' });
  const result = await removeBadge(userId, badgeName);
  res.json(result ? { success:true } : { error:'Gagal' });
});

// NOTIFICATIONS
app.get('/api/notifications', requireLogin, async (req, res) => {
  const [database, userData, verifiedData] = await Promise.all([
    readJSON('data/database.json'), readJSON('data/user.json'), readJSON('data/verified.users.json')
  ]);
  const notifications = [];
  (database.posts || []).forEach(post => {
    if (post.userId !== req.session.userId) return;
    (post.likes || []).forEach(likeUserId => {
      if (likeUserId !== req.session.userId) {
        notifications.push({ id:`like_${post.id}_${likeUserId}`, type:'like', userId: likeUserId, username: userData[likeUserId]?.username || 'Unknown', profilePic: userData[likeUserId]?.profilePic || '', isVerified: verifiedData.verified?.includes(likeUserId) || false, postId: post.id, postMedia: post.mediaUrl, createdAt: post.createdAt, read:false });
      }
    });
    (database.comments || []).forEach(c => {
      if (c.postId === post.id && c.userId !== req.session.userId) {
        notifications.push({ id:`comment_${c.id}`, type:'comment', userId: c.userId, username: c.username, profilePic: c.profilePic || '', isVerified: verifiedData.verified?.includes(c.userId) || false, postId: post.id, postMedia: post.mediaUrl, comment: c.text, createdAt: c.createdAt, read:false });
      }
    });
  });
  notifications.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ notifications: notifications.slice(0, 50) });
});

// SETTINGS
app.post('/api/settings/change-password', requireLogin,
  rateLimit({ windowMs: 60 * 60 * 1000, max: 5, keyFn: (req) => 'chgpw:' + req.session.userId }),
  async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Semua field wajib diisi' });
    const passErr = validatePassword(newPassword);
    if (passErr) return res.status(400).json({ error: passErr });
    const loginData = await readJSON('data/login.json');
    const idx       = loginData.users.findIndex(u => u.id === req.session.userId);
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    const valid = await bcrypt.compare(currentPassword, loginData.users[idx].password);
    if (!valid) return res.status(401).json({ error: 'Password lama salah' });
    loginData.users[idx].password = await bcrypt.hash(newPassword, 12);
    await writeJSON('data/login.json', loginData);
    res.json({ success:true });
  }
);

app.delete('/api/settings/delete-account', requireLogin, async (req, res) => {
  const userId = req.session.userId;
  await deleteUserData(userId);
  req.session.destroy();
  res.clearCookie('mio.sid');
  res.clearCookie('rememberToken');
  res.json({ success:true });
});

// ERROR HANDLING
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Terjadi kesalahan server' });
});
app.use((req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan' }));

app.listen(PORT, () => {
  console.log(`✅ Mio Media (OPTIMIZED) berjalan di http://localhost:${PORT}`);
  console.log(`🚀 Async I/O + JSON Cache + Security: AKTIF`);
});

module.exports = app;
