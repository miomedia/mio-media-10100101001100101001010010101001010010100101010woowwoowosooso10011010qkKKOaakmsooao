const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3469;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

app.use(session({
  secret: 'mio-media-secret-key-' + crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ========== LEVEL CONFIGURATION (UP TO 999+) ==========
function generateLevelConfig() {
  const config = {};
  for (let level = 1; level <= 999; level++) {
    // Formula XP minimal untuk mencapai level L: 50 * (L-1) * L
    const minXP = Math.floor(50 * (level - 1) * level);
    let name = '';
    let icon = '';
    if (level <= 10) {
      const names = ['Newbie', 'Rookie', 'Explorer', 'Creator', 'Influencer', 'Elite', 'Legend', 'Mythic', 'Godlike', 'Immortal'];
      const icons = ['🌱', '⭐', '🚀', '🎨', '🌟', '💎', '🏆', '⚡', '👑', '🔥'];
      name = names[level-1];
      icon = icons[level-1];
    } else if (level <= 50) {
      name = 'Master';
      icon = '✨';
    } else if (level <= 100) {
      name = 'Grandmaster';
      icon = '💫';
    } else if (level <= 200) {
      name = 'Legendary';
      icon = '🏅';
    } else if (level <= 500) {
      name = 'Mythic';
      icon = '🌌';
    } else {
      name = 'Ascendant';
      icon = '👁️';
    }
    config[level] = { name, minXp: minXP, icon };
  }
  return config;
}

// Fungsi menghitung level berdasarkan XP (loop dari 999 ke bawah)
function calculateLevel(xp) {
  const levelsData = readJSON('data/levels.json');
  const levelConfig = levelsData.levelConfig;
  for (let i = 999; i >= 1; i--) {
    if (levelConfig[i] && xp >= levelConfig[i].minXp) {
      return i;
    }
  }
  return 1;
}

// ========== INITIALIZE DATA FILES ==========
function initializeDataFiles() {
  const dirs = [
    './data', './uploads', './uploads/images', './uploads/videos',
    './uploads/profiles', './uploads/comments', './uploads/music',
    './uploads/wallpapers', './uploads/chat'
  ];
  dirs.forEach(dir => { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); });

  const fullLevelConfig = generateLevelConfig();

  const files = {
    'data/login.json': { users: [], adminUsers: [] },
    'data/user.json': {},
    'data/database.json': { posts: [], comments: [], likes: [] },
    'data/setting.user.json': {},
    'data/verified.users.json': { verified: [] },
    'data/saved.login.json': { savedLogins: [], rememberTokens: {} },
    'data/follow.data.json': { followers: {}, following: {}, followRequests: {} },
    'data/levels.json': { userLevels: {}, levelConfig: fullLevelConfig },
    'data/badges.json': { customBadges: {}, badgeColors: { "gold": "#FFD700", "silver": "#C0C0C0", "bronze": "#CD7F32", "platinum": "#E5E4E2", "diamond": "#B9F2FF" } },
    'data/chats.json': { conversations: {}, messages: {} }
  };

  Object.entries(files).forEach(([filePath, defaultData]) => {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2));
    } else {
      try {
        const existingData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        // Upgrade levelConfig jika masih versi lama
        if (filePath === 'data/levels.json' && (!existingData.levelConfig || Object.keys(existingData.levelConfig).length < 100)) {
          existingData.levelConfig = fullLevelConfig;
        }
        Object.keys(defaultData).forEach(key => {
          if (existingData[key] === undefined) existingData[key] = defaultData[key];
        });
        fs.writeFileSync(filePath, JSON.stringify(existingData, null, 2));
      } catch (error) {
        fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2));
      }
    }
  });

  // Set admin pertama jika belum ada
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
  } catch (error) {}
}

initializeDataFiles();

// ========== HELPER FUNCTIONS ==========
function readJSON(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch (error) { return null; }
}

function writeJSON(filePath, data) {
  try { fs.writeFileSync(filePath, JSON.stringify(data, null, 2)); return true; } catch (error) { return false; }
}

function getUserById(userId) {
  const userData = readJSON('data/user.json');
  return userData[userId] || null;
}

function isAdmin(userId) {
  const loginData = readJSON('data/login.json');
  return loginData.adminUsers && loginData.adminUsers.includes(userId);
}

function isVerified(userId) {
  const verifiedData = readJSON('data/verified.users.json');
  return verifiedData.verified && verifiedData.verified.includes(userId);
}

function getUserLevel(userId) {
  const levelsData = readJSON('data/levels.json');
  if (!levelsData.userLevels[userId]) {
    levelsData.userLevels[userId] = { xp: 0, level: 1, totalPosts: 0, totalLikes: 0 };
    writeJSON('data/levels.json', levelsData);
  }
  return levelsData.userLevels[userId];
}

function addXP(userId, amount, source = 'action') {
  const levelsData = readJSON('data/levels.json');
  if (!levelsData.userLevels[userId]) {
    levelsData.userLevels[userId] = { xp: 0, level: 1, totalPosts: 0, totalLikes: 0 };
  }
  const userLevel = levelsData.userLevels[userId];
  userLevel.xp += amount;
  if (source === 'post') userLevel.totalPosts++;
  if (source === 'like') userLevel.totalLikes++;
  const newLevel = calculateLevel(userLevel.xp);
  const leveledUp = newLevel > userLevel.level;
  userLevel.level = newLevel;
  writeJSON('data/levels.json', levelsData);
  return { leveledUp, oldLevel: userLevel.level - (leveledUp ? 1 : 0), newLevel: userLevel.level };
}

function getLevelInfo(userId) {
  const levelsData = readJSON('data/levels.json');
  const levelConfig = levelsData.levelConfig;
  const userLevel = getUserLevel(userId);
  const currentLevelConfig = levelConfig[userLevel.level] || levelConfig[999];
  const nextLevelConfig = levelConfig[userLevel.level + 1] || null;
  return {
    level: userLevel.level,
    xp: userLevel.xp,
    levelName: currentLevelConfig.name,
    levelIcon: currentLevelConfig.icon,
    xpNeeded: nextLevelConfig ? nextLevelConfig.minXp - userLevel.xp : 0,
    xpForNext: nextLevelConfig ? nextLevelConfig.minXp : userLevel.xp,
    totalPosts: userLevel.totalPosts,
    totalLikes: userLevel.totalLikes,
    progress: nextLevelConfig ? (userLevel.xp - currentLevelConfig.minXp) / (nextLevelConfig.minXp - currentLevelConfig.minXp) * 100 : 100
  };
}

function getUserBadges(userId) {
  const badgesData = readJSON('data/badges.json');
  const userBadges = badgesData.customBadges[userId] || [];
  const verified = isVerified(userId);
  const isAdminUser = isAdmin(userId);
  const badges = [];
  if (verified) badges.push({ name: "Verified", icon: "✓", color: "#1da1f2", isCustom: false });
  if (isAdminUser) badges.push({ name: "Developer", icon: "👑", color: "#FF4444", isCustom: false });
  userBadges.forEach(badge => { badges.push({ ...badge, isCustom: true }); });
  return badges;
}

function assignBadge(userId, badgeName, badgeIcon, badgeColor) {
  const badgesData = readJSON('data/badges.json');
  if (!badgesData.customBadges[userId]) badgesData.customBadges[userId] = [];
  const existing = badgesData.customBadges[userId].find(b => b.name === badgeName);
  if (existing) { existing.icon = badgeIcon; existing.color = badgeColor; }
  else { badgesData.customBadges[userId].push({ name: badgeName, icon: badgeIcon, color: badgeColor }); }
  writeJSON('data/badges.json', badgesData);
  return true;
}

function removeBadge(userId, badgeName) {
  const badgesData = readJSON('data/badges.json');
  if (badgesData.customBadges[userId]) {
    badgesData.customBadges[userId] = badgesData.customBadges[userId].filter(b => b.name !== badgeName);
    writeJSON('data/badges.json', badgesData);
    return true;
  }
  return false;
}

function getAllCustomBadges() {
  const badgesData = readJSON('data/badges.json');
  const allBadges = [];
  for (const [userId, badges] of Object.entries(badgesData.customBadges)) {
    const user = getUserById(userId);
    if (user) {
      badges.forEach(badge => { allBadges.push({ ...badge, userId, username: user.username }); });
    }
  }
  return allBadges;
}

function generateRememberToken() {
  return crypto.randomBytes(32).toString('hex');
}

function saveRememberToken(userId, username) {
  const savedData = readJSON('data/saved.login.json');
  const token = generateRememberToken();
  const expires = Date.now() + (30 * 24 * 60 * 60 * 1000);
  if (!savedData.rememberTokens) savedData.rememberTokens = {};
  savedData.rememberTokens[token] = { userId, username, expires };
  writeJSON('data/saved.login.json', savedData);
  return token;
}

function validateRememberToken(token) {
  const savedData = readJSON('data/saved.login.json');
  if (!savedData.rememberTokens || !savedData.rememberTokens[token]) return null;
  const tokenData = savedData.rememberTokens[token];
  if (tokenData.expires < Date.now()) {
    delete savedData.rememberTokens[token];
    writeJSON('data/saved.login.json', savedData);
    return null;
  }
  tokenData.expires = Date.now() + (30 * 24 * 60 * 60 * 1000);
  savedData.rememberTokens[token] = tokenData;
  writeJSON('data/saved.login.json', savedData);
  return tokenData;
}

function removeRememberToken(token) {
  const savedData = readJSON('data/saved.login.json');
  if (savedData.rememberTokens && savedData.rememberTokens[token]) {
    delete savedData.rememberTokens[token];
    writeJSON('data/saved.login.json', savedData);
  }
}

function getFollowStatus(userId, targetUserId) {
  const followData = readJSON('data/follow.data.json');
  const isFollowing = followData.following[userId] && followData.following[userId].includes(targetUserId);
  const isFollowedBack = followData.followers[userId] && followData.followers[userId].includes(targetUserId);
  return {
    isFollowing: isFollowing || false,
    isFollowedBack: isFollowedBack || false,
    followersCount: followData.followers[targetUserId] ? followData.followers[targetUserId].length : 0,
    followingCount: followData.following[targetUserId] ? followData.following[targetUserId].length : 0
  };
}

function toggleFollow(userId, targetUserId) {
  const followData = readJSON('data/follow.data.json');
  if (!followData.following[userId]) followData.following[userId] = [];
  if (!followData.followers[targetUserId]) followData.followers[targetUserId] = [];
  const followingIndex = followData.following[userId].indexOf(targetUserId);
  let action = 'follow';
  if (followingIndex === -1) {
    followData.following[userId].push(targetUserId);
    followData.followers[targetUserId].push(userId);
    action = 'follow';
  } else {
    followData.following[userId].splice(followingIndex, 1);
    const followerIndex = followData.followers[targetUserId].indexOf(userId);
    followData.followers[targetUserId].splice(followerIndex, 1);
    action = 'unfollow';
  }
  const userData = readJSON('data/user.json');
  if (userData[userId]) userData[userId].following = followData.following[userId].length;
  if (userData[targetUserId]) userData[targetUserId].followers = followData.followers[targetUserId].length;
  writeJSON('data/user.json', userData);
  writeJSON('data/follow.data.json', followData);
  return { success: true, action, followersCount: followData.followers[targetUserId] ? followData.followers[targetUserId].length : 0, followingCount: followData.following[userId] ? followData.following[userId].length : 0 };
}

// ========== CHAT HELPER FUNCTIONS ==========
function getConversationId(userId1, userId2) {
  return [userId1, userId2].sort().join('_');
}

function getChatData() {
  return readJSON('data/chats.json') || { conversations: {}, messages: {} };
}

function saveChatData(data) {
  return writeJSON('data/chats.json', data);
}

function getUnreadCount(userId) {
  const chatData = getChatData();
  let total = 0;
  for (const convId in chatData.conversations) {
    const conv = chatData.conversations[convId];
    if (conv.participants.includes(userId)) {
      const unread = conv.unreadCount || {};
      total += unread[userId] || 0;
    }
  }
  return total;
}

// ========== HELPER: DELETE USER DATA (reusable) ==========
function deleteUserData(userId) {
  // Login
  const loginData = readJSON('data/login.json');
  loginData.users = loginData.users.filter(u => u.id !== userId);
  loginData.adminUsers = (loginData.adminUsers || []).filter(id => id !== userId);
  writeJSON('data/login.json', loginData);

  // User profile
  const userData = readJSON('data/user.json');
  delete userData[userId];
  writeJSON('data/user.json', userData);

  // Verified
  const verifiedData = readJSON('data/verified.users.json');
  verifiedData.verified = (verifiedData.verified || []).filter(id => id !== userId);
  writeJSON('data/verified.users.json', verifiedData);

  // Posts & comments
  const database = readJSON('data/database.json');
  database.posts = (database.posts || []).filter(p => p.userId !== userId);
  database.comments = (database.comments || []).filter(c => c.userId !== userId);
  writeJSON('data/database.json', database);

  // Follow data
  const followData = readJSON('data/follow.data.json');
  delete followData.followers[userId];
  delete followData.following[userId];
  Object.keys(followData.followers || {}).forEach(key => {
    followData.followers[key] = followData.followers[key].filter(id => id !== userId);
  });
  Object.keys(followData.following || {}).forEach(key => {
    followData.following[key] = followData.following[key].filter(id => id !== userId);
  });
  writeJSON('data/follow.data.json', followData);

  // Remember tokens
  const savedData = readJSON('data/saved.login.json');
  if (savedData.rememberTokens) {
    Object.keys(savedData.rememberTokens).forEach(token => {
      if (savedData.rememberTokens[token].userId === userId) delete savedData.rememberTokens[token];
    });
    writeJSON('data/saved.login.json', savedData);
  }

  // Levels
  const levelsData = readJSON('data/levels.json');
  delete levelsData.userLevels[userId];
  writeJSON('data/levels.json', levelsData);

  // Badges
  const badgesData = readJSON('data/badges.json');
  delete badgesData.customBadges[userId];
  writeJSON('data/badges.json', badgesData);

  // Chat conversations & messages
  const chatData = getChatData();
  const convIdsToDelete = [];
  for (const convId in chatData.conversations) {
    if (chatData.conversations[convId].participants.includes(userId)) {
      convIdsToDelete.push(convId);
    }
  }
  convIdsToDelete.forEach(convId => {
    delete chatData.conversations[convId];
    delete chatData.messages[convId];
  });
  saveChatData(chatData);
}

// ========== MULTER STORAGE CONFIGURATIONS ==========
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    let folder = 'uploads/';
    if (file.mimetype.startsWith('image/')) folder += 'images/';
    else if (file.mimetype.startsWith('video/')) folder += 'videos/';
    else if (file.mimetype.startsWith('audio/')) folder += 'music/';
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
    cb(null, folder);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const prefix = file.fieldname.startsWith('media') ? 'media' : (file.fieldname === 'music' ? 'music' : 'file');
    cb(null, prefix + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024, files: 6 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname.startsWith('media')) {
      if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) cb(null, true);
      else cb(new Error('Media harus gambar atau video!'), false);
    } else if (file.fieldname === 'music') {
      if (file.mimetype.startsWith('audio/')) cb(null, true);
      else cb(new Error('File harus audio!'), false);
    } else cb(new Error('Field tidak dikenal'), false);
  }
});

const profileStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const folder = 'uploads/profiles/';
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
    cb(null, folder);
  },
  filename: (req, file, cb) => {
    const userId = req.session.userId || 'unknown';
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, `${userId}-${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});
const profileUpload = multer({
  storage: profileStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Hanya gambar yang diizinkan!'), false);
  }
});

const wallpaperStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const folder = 'uploads/wallpapers/';
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
    cb(null, folder);
  },
  filename: (req, file, cb) => {
    const userId = req.session.userId || 'unknown';
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, `wallpaper-${userId}-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});
const wallpaperUpload = multer({
  storage: wallpaperStorage,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) cb(null, true);
    else cb(new Error('Hanya gambar atau video yang diizinkan untuk wallpaper!'), false);
  }
});

const commentStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const folder = 'uploads/comments/';
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
    cb(null, folder);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'comment-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const commentUpload = multer({
  storage: commentStorage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) cb(null, true);
    else cb(new Error('Hanya gambar dan video yang diizinkan!'), false);
  }
});

const chatMediaStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const folder = 'uploads/chat/';
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
    cb(null, folder);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'chat-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const chatMediaUpload = multer({
  storage: chatMediaStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/') || file.mimetype.startsWith('audio/')) cb(null, true);
    else cb(new Error('Hanya gambar, video, dan audio yang diizinkan!'), false);
  }
});

// ========== MIDDLEWARE ==========
function requireLogin(req, res, next) {
  if (req.session.userId) return next();
  const token = req.cookies?.rememberToken;
  if (token) {
    const tokenData = validateRememberToken(token);
    if (tokenData) {
      req.session.userId = tokenData.userId;
      req.session.username = tokenData.username;
      return next();
    }
  }
  res.status(401).json({ error: 'Unauthorized' });
}

function requireAdmin(req, res, next) {
  if (req.session.userId && isAdmin(req.session.userId)) return next();
  res.status(403).json({ error: 'Forbidden: Developer only' });
}

// ========== ROUTES ==========
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Auth
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username dan password wajib diisi' });
  const loginData = readJSON('data/login.json');
  if (loginData.users.some(u => u.username === username)) return res.status(400).json({ error: 'Username sudah digunakan' });
  const hashedPassword = await bcrypt.hash(password, 10);
  const userId = 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  loginData.users.push({ id: userId, username, password: hashedPassword, email: email || '', createdAt: new Date().toISOString() });
  writeJSON('data/login.json', loginData);
  const userData = readJSON('data/user.json');
  userData[userId] = { id: userId, username, email: email || '', profilePic: '', wallpaper: '', bio: '', followers: 0, following: 0, posts: 0, createdAt: new Date().toISOString() };
  writeJSON('data/user.json', userData);
  const levelsData = readJSON('data/levels.json');
  levelsData.userLevels[userId] = { xp: 0, level: 1, totalPosts: 0, totalLikes: 0 };
  writeJSON('data/levels.json', levelsData);
  res.json({ success: true, userId });
});

app.post('/api/login', async (req, res) => {
  const { username, password, rememberMe } = req.body;
  const loginData = readJSON('data/login.json');
  const user = loginData.users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Username atau password salah' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Username atau password salah' });
  req.session.userId = user.id;
  req.session.username = user.username;
  let token = null;
  if (rememberMe) {
    token = saveRememberToken(user.id, user.username);
    res.cookie('rememberToken', token, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true });
  }
  res.json({ success: true, userId: user.id, username: user.username, token });
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies?.rememberToken;
  if (token) removeRememberToken(token);
  req.session.destroy();
  res.clearCookie('connect.sid');
  res.clearCookie('rememberToken');
  res.json({ success: true });
});

app.get('/api/me', requireLogin, (req, res) => {
  const user = getUserById(req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const levelInfo = getLevelInfo(req.session.userId);
  const badges = getUserBadges(req.session.userId);
  const unreadChats = getUnreadCount(req.session.userId);
  res.json({
    id: user.id, username: user.username, profilePic: user.profilePic,
    wallpaper: user.wallpaper, wallpaperSettings: user.wallpaperSettings,
    bio: user.bio, followers: user.followers, following: user.following,
    posts: user.posts, isVerified: isVerified(user.id), isAdmin: isAdmin(user.id),
    level: levelInfo.level, levelName: levelInfo.levelName, levelIcon: levelInfo.levelIcon,
    xp: levelInfo.xp, xpProgress: levelInfo.progress, badges, unreadChats
  });
});

// Profile
app.get('/api/profile/:userId', requireLogin, (req, res) => {
  const targetId = req.params.userId;
  const user = getUserById(targetId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const database = readJSON('data/database.json');
  const userPosts = (database.posts || []).filter(post => post.userId === targetId);
  const totalLikes = userPosts.reduce((sum, post) => sum + (post.likes ? post.likes.length : 0), 0);
  const followStatus = getFollowStatus(req.session.userId, targetId);
  const levelInfo = getLevelInfo(targetId);
  const badges = getUserBadges(targetId);
  res.json({
    id: user.id, username: user.username, profilePic: user.profilePic,
    wallpaper: user.wallpaper, wallpaperSettings: user.wallpaperSettings,
    bio: user.bio, followers: followStatus.followersCount, following: followStatus.followingCount,
    posts: user.posts, totalLikes, isVerified: isVerified(targetId), isAdmin: isAdmin(targetId),
    isFollowing: followStatus.isFollowing, isFollowedBack: followStatus.isFollowedBack,
    level: levelInfo.level, levelName: levelInfo.levelName, levelIcon: levelInfo.levelIcon,
    xp: levelInfo.xp, xpProgress: levelInfo.progress, badges
  });
});

app.post('/api/profile/update', requireLogin, (req, res) => {
  const { bio } = req.body;
  const userData = readJSON('data/user.json');
  if (!userData[req.session.userId]) return res.status(404).json({ error: 'User not found' });
  userData[req.session.userId].bio = bio || userData[req.session.userId].bio;
  writeJSON('data/user.json', userData);
  res.json({ success: true });
});

app.post('/api/profile/upload-pic', requireLogin, profileUpload.fields([{ name: 'profilePic', maxCount: 1 }, { name: 'wallpaper', maxCount: 1 }]), (req, res) => {
  const userData = readJSON('data/user.json');
  if (req.files['profilePic']) userData[req.session.userId].profilePic = '/uploads/profiles/' + req.files['profilePic'][0].filename;
  if (req.files['wallpaper']) {
    const wallpaperUrl = '/uploads/profiles/' + req.files['wallpaper'][0].filename;
    userData[req.session.userId].wallpaper = wallpaperUrl;
    if (!userData[req.session.userId].wallpaperSettings) userData[req.session.userId].wallpaperSettings = {};
    userData[req.session.userId].wallpaperSettings.type = 'image';
    userData[req.session.userId].wallpaperSettings.image = wallpaperUrl;
  }
  writeJSON('data/user.json', userData);
  res.json({ success: true, profilePic: userData[req.session.userId].profilePic, wallpaper: userData[req.session.userId].wallpaper });
});

app.post('/api/profile/upload-wallpaper', requireLogin, wallpaperUpload.single('wallpaper'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Tidak ada file yang diupload' });
  const fileUrl = '/uploads/wallpapers/' + req.file.filename;
  const fileType = req.file.mimetype.startsWith('image/') ? 'image' : 'video';
  const userData = readJSON('data/user.json');
  if (!userData[req.session.userId]) return res.status(404).json({ error: 'User not found' });
  userData[req.session.userId].wallpaper = fileUrl;
  if (!userData[req.session.userId].wallpaperSettings) userData[req.session.userId].wallpaperSettings = {};
  userData[req.session.userId].wallpaperSettings.type = 'media';
  userData[req.session.userId].wallpaperSettings.mediaUrl = fileUrl;
  userData[req.session.userId].wallpaperSettings.mediaType = fileType;
  writeJSON('data/user.json', userData);
  res.json({ success: true, wallpaperUrl: fileUrl, mediaType: fileType });
});

app.post('/api/profile/wallpaper', requireLogin, (req, res) => {
  const { wallpaperType, wallpaperValue, blur } = req.body;
  const userData = readJSON('data/user.json');
  if (!userData[req.session.userId]) return res.status(404).json({ error: 'User not found' });
  userData[req.session.userId].wallpaperSettings = { type: wallpaperType || 'image', value: wallpaperValue || '', blur: blur || false };
  writeJSON('data/user.json', userData);
  res.json({ success: true, settings: userData[req.session.userId].wallpaperSettings });
});

app.get('/api/profile/wallpaper', requireLogin, (req, res) => {
  const userData = readJSON('data/user.json');
  const user = userData[req.session.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const settings = user.wallpaperSettings || { type: 'image', value: user.wallpaper || '', blur: false };
  res.json({ success: true, settings });
});

// Post upload
app.post('/api/upload', requireLogin, (req, res) => {
  const uploadMiddleware = upload.fields([{ name: 'media0', maxCount: 1 }, { name: 'media1', maxCount: 1 }, { name: 'media2', maxCount: 1 }, { name: 'media3', maxCount: 1 }, { name: 'media4', maxCount: 1 }, { name: 'music', maxCount: 1 }]);
  uploadMiddleware(req, res, async function(err) {
    if (err) return res.status(400).json({ error: err.message });
    try {
      const { caption, fileCount } = req.body;
      const files = req.files;
      if (!files || Object.keys(files).length === 0) return res.status(400).json({ error: 'Tidak ada file yang diupload' });
      const mediaFiles = [];
      const count = parseInt(fileCount) || 0;
      for (let i = 0; i < count; i++) if (files[`media${i}`] && files[`media${i}`][0]) mediaFiles.push(files[`media${i}`][0]);
      if (mediaFiles.length === 0) return res.status(400).json({ error: 'Tidak ada media yang valid' });
      const musicFile = files.music ? files.music[0] : null;
      const mediaArray = mediaFiles.map(file => ({ mediaUrl: '/uploads/' + (file.mimetype.startsWith('image/') ? 'images/' : 'videos/') + file.filename, mediaType: file.mimetype.startsWith('image/') ? 'image' : 'video' }));
      const database = readJSON('data/database.json');
      const postId = 'post_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
      const newPost = {
        id: postId, userId: req.session.userId, username: req.session.username,
        mediaArray, mediaUrl: mediaArray[0].mediaUrl, mediaType: mediaArray[0].mediaType,
        caption: caption || '', likes: [], comments: [],
        musicUrl: musicFile ? '/uploads/music/' + musicFile.filename : null,
        musicName: musicFile ? musicFile.originalname : null, createdAt: new Date().toISOString()
      };
      if (!database.posts) database.posts = [];
      database.posts.push(newPost);
      writeJSON('data/database.json', database);
      const userData = readJSON('data/user.json');
      userData[req.session.userId].posts = (userData[req.session.userId].posts || 0) + 1;
      writeJSON('data/user.json', userData);
      const levelResult = addXP(req.session.userId, 50, 'post');
      res.json({ success: true, post: newPost, mediaCount: mediaArray.length, hasMusic: !!musicFile, leveledUp: levelResult.leveledUp, newLevel: levelResult.newLevel });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });
});

// Comments
app.post('/api/comment/upload-media', requireLogin, commentUpload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Tidak ada file yang diupload' });
  res.json({ success: true, mediaUrl: '/uploads/comments/' + req.file.filename, mediaType: req.file.mimetype.startsWith('image/') ? 'image' : 'video', filename: req.file.filename });
});

app.post('/api/post/:postId/comment', requireLogin, (req, res) => {
  const postId = req.params.postId;
  const { text, mediaUrl, mediaType } = req.body;
  if (!text && !mediaUrl) return res.status(400).json({ error: 'Komentar tidak boleh kosong' });
  const database = readJSON('data/database.json');
  const postIndex = database.posts.findIndex(p => p.id === postId);
  if (postIndex === -1) return res.status(404).json({ error: 'Post not found' });
  const commentId = 'comment_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  const newComment = {
    id: commentId, postId, userId: req.session.userId, username: req.session.username,
    text: text || '', mediaUrl: mediaUrl || null, mediaType: mediaType || null,
    profilePic: getUserById(req.session.userId)?.profilePic || '',
    isVerified: isVerified(req.session.userId), createdAt: new Date().toISOString()
  };
  if (!database.comments) database.comments = [];
  database.comments.push(newComment);
  if (!database.posts[postIndex].comments) database.posts[postIndex].comments = [];
  database.posts[postIndex].comments.push(commentId);
  writeJSON('data/database.json', database);
  addXP(req.session.userId, 10, 'comment');
  res.json({ success: true, comment: newComment });
});

app.get('/api/post/:postId/comments', requireLogin, (req, res) => {
  const postId = req.params.postId;
  const database = readJSON('data/database.json');
  const comments = (database.comments || []).filter(c => c.postId === postId).sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  res.json({ comments });
});

// Feed & Explore
app.get('/api/feed', requireLogin, (req, res) => {
  const database = readJSON('data/database.json');
  const followData = readJSON('data/follow.data.json');
  const following = followData.following[req.session.userId] || [];
  const allPosts = database.posts || [];
  const sortedPosts = allPosts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const posts = sortedPosts.map(post => ({
    ...post,
    likesCount: post.likes ? post.likes.length : 0,
    commentsCount: post.comments ? post.comments.length : 0,
    isLiked: post.likes ? post.likes.includes(req.session.userId) : false,
    isFromFollowing: following.includes(post.userId) || post.userId === req.session.userId,
    userProfilePic: getUserById(post.userId)?.profilePic || '',
    isVerified: isVerified(post.userId)
  }));
  res.json({ posts });
});

app.get('/api/user/:userId/posts', requireLogin, (req, res) => {
  const targetId = req.params.userId;
  const database = readJSON('data/database.json');
  const posts = (database.posts || []).filter(post => post.userId === targetId).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).map(post => ({ ...post, likesCount: post.likes ? post.likes.length : 0, commentsCount: post.comments ? post.comments.length : 0, isLiked: post.likes ? post.likes.includes(req.session.userId) : false, isVerified: isVerified(targetId) }));
  res.json({ posts });
});

app.post('/api/post/:postId/like', requireLogin, (req, res) => {
  const postId = req.params.postId;
  const database = readJSON('data/database.json');
  const postIndex = database.posts.findIndex(p => p.id === postId);
  if (postIndex === -1) return res.status(404).json({ error: 'Post not found' });
  const post = database.posts[postIndex];
  if (!post.likes) post.likes = [];
  const likeIndex = post.likes.indexOf(req.session.userId);
  let liked = false;
  if (likeIndex === -1) { post.likes.push(req.session.userId); liked = true; addXP(req.session.userId, 5, 'like_given'); addXP(post.userId, 10, 'like_received'); }
  else { post.likes.splice(likeIndex, 1); liked = false; }
  database.posts[postIndex] = post;
  writeJSON('data/database.json', database);
  res.json({ success: true, liked, likesCount: post.likes.length });
});

app.get('/api/search', requireLogin, (req, res) => {
  const query = req.query.q?.toLowerCase() || '';
  if (!query) return res.json({ users: [] });
  const userData = readJSON('data/user.json');
  const users = Object.values(userData).filter(user => user.username.toLowerCase().includes(query)).map(user => ({ id: user.id, username: user.username, profilePic: user.profilePic, bio: user.bio, isVerified: isVerified(user.id) })).slice(0, 20);
  res.json({ users });
});

app.post('/api/user/:userId/follow', requireLogin, (req, res) => {
  const targetId = req.params.userId;
  if (targetId === req.session.userId) return res.status(400).json({ error: 'Tidak bisa follow diri sendiri' });
  const result = toggleFollow(req.session.userId, targetId);
  res.json(result);
});

app.get('/api/explore', requireLogin, (req, res) => {
  const database = readJSON('data/database.json');
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const startIndex = (page - 1) * limit;
  const posts = (database.posts || []).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(startIndex, startIndex + limit).map(post => ({ ...post, likesCount: post.likes ? post.likes.length : 0, commentsCount: post.comments ? post.comments.length : 0, isLiked: post.likes ? post.likes.includes(req.session.userId) : false, isVerified: isVerified(post.userId) }));
  res.json({ posts, hasMore: startIndex + limit < (database.posts || []).length });
});

// Leaderboard
app.get('/api/leaderboard', requireLogin, (req, res) => {
  const userData = readJSON('data/user.json');
  const levelsData = readJSON('data/levels.json');
  const verifiedData = readJSON('data/verified.users.json');
  const loginData = readJSON('data/login.json');
  const leaderboardData = [];
  for (const [userId, user] of Object.entries(userData)) {
    const levelInfo = levelsData.userLevels[userId] || { xp: 0, level: 1, totalPosts: 0, totalLikes: 0 };
    const isVerifiedUser = verifiedData.verified?.includes(userId) || false;
    const isAdminUser = loginData.adminUsers?.includes(userId) || false;
    leaderboardData.push({
      userId, username: user.username, profilePic: user.profilePic || '',
      level: levelInfo.level, xp: levelInfo.xp, totalPosts: levelInfo.totalPosts || 0,
      totalLikes: levelInfo.totalLikes || 0, followers: user.followers || 0,
      isVerified: isVerifiedUser, isAdmin: isAdminUser
    });
  }
  const sortedByLevel = [...leaderboardData].sort((a, b) => { if (a.level !== b.level) return b.level - a.level; return b.xp - a.xp; });
  const topUsers = sortedByLevel.slice(0, 50);
  const topDevelopers = leaderboardData.filter(user => user.isAdmin).sort((a, b) => { if (a.level !== b.level) return b.level - a.level; return b.xp - a.xp; });
  const currentUserRank = sortedByLevel.findIndex(u => u.userId === req.session.userId) + 1;
  res.json({ success: true, topUsers, topDevelopers, currentUserRank, totalUsers: leaderboardData.length });
});

// Chat Routes
app.get('/api/chat/conversations', requireLogin, (req, res) => {
  const chatData = getChatData();
  const userId = req.session.userId;
  const userData = readJSON('data/user.json');
  const conversations = [];
  for (const [convId, conv] of Object.entries(chatData.conversations)) {
    if (!conv.participants.includes(userId)) continue;
    const otherUserId = conv.participants.find(id => id !== userId);
    const otherUser = userData[otherUserId];
    if (!otherUser) continue;
    const messages = chatData.messages[convId] || [];
    const lastMessage = messages[messages.length - 1] || null;
    const unreadCount = (conv.unreadCount || {})[userId] || 0;
    conversations.push({
      id: convId,
      otherUser: { id: otherUserId, username: otherUser.username, profilePic: otherUser.profilePic || '', isVerified: isVerified(otherUserId), isAdmin: isAdmin(otherUserId) },
      lastMessage: lastMessage ? { text: lastMessage.text, mediaType: lastMessage.mediaType || null, senderId: lastMessage.senderId, createdAt: lastMessage.createdAt, isRead: lastMessage.isRead || false } : null,
      unreadCount, updatedAt: conv.updatedAt || conv.createdAt
    });
  }
  conversations.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
  res.json({ success: true, conversations });
});

app.get('/api/chat/with/:userId', requireLogin, (req, res) => {
  const targetId = req.params.userId;
  const myId = req.session.userId;
  if (targetId === myId) return res.status(400).json({ error: 'Tidak bisa chat dengan diri sendiri' });
  const targetUser = getUserById(targetId);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  const convId = getConversationId(myId, targetId);
  const chatData = getChatData();
  if (!chatData.conversations[convId]) {
    chatData.conversations[convId] = { id: convId, participants: [myId, targetId], createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), unreadCount: { [myId]: 0, [targetId]: 0 } };
    chatData.messages[convId] = [];
    saveChatData(chatData);
  }
  res.json({ success: true, conversationId: convId, otherUser: { id: targetId, username: targetUser.username, profilePic: targetUser.profilePic || '', bio: targetUser.bio || '', isVerified: isVerified(targetId), isAdmin: isAdmin(targetId) } });
});

app.get('/api/chat/:conversationId/messages', requireLogin, (req, res) => {
  const { conversationId } = req.params;
  const userId = req.session.userId;
  const page = parseInt(req.query.page) || 1;
  const limit = 30;
  const chatData = getChatData();
  const conv = chatData.conversations[conversationId];
  if (!conv || !conv.participants.includes(userId)) return res.status(403).json({ error: 'Akses ditolak' });
  if (conv.unreadCount) conv.unreadCount[userId] = 0;
  const messages = chatData.messages[conversationId] || [];
  messages.forEach(msg => { if (msg.senderId !== userId) msg.isRead = true; });
  saveChatData(chatData);
  const userData = readJSON('data/user.json');
  const totalMessages = messages.length;
  const startIndex = Math.max(0, totalMessages - (page * limit));
  const endIndex = totalMessages - ((page - 1) * limit);
  const pageMessages = messages.slice(startIndex, endIndex);
  const enrichedMessages = pageMessages.map(msg => {
    const sender = userData[msg.senderId];
    return { ...msg, senderUsername: sender?.username || 'Unknown', senderProfilePic: sender?.profilePic || '', isVerified: isVerified(msg.senderId) };
  });
  res.json({ success: true, messages: enrichedMessages, hasMore: startIndex > 0, total: totalMessages });
});

app.post('/api/chat/:conversationId/send', requireLogin, (req, res) => {
  const { conversationId } = req.params;
  const { text, mediaUrl, mediaType } = req.body;
  const userId = req.session.userId;
  if (!text && !mediaUrl) return res.status(400).json({ error: 'Pesan tidak boleh kosong' });
  const chatData = getChatData();
  const conv = chatData.conversations[conversationId];
  if (!conv || !conv.participants.includes(userId)) return res.status(403).json({ error: 'Akses ditolak' });
  const messageId = 'msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  const newMessage = { id: messageId, conversationId, senderId: userId, text: text || '', mediaUrl: mediaUrl || null, mediaType: mediaType || null, isRead: false, createdAt: new Date().toISOString() };
  if (!chatData.messages[conversationId]) chatData.messages[conversationId] = [];
  chatData.messages[conversationId].push(newMessage);
  const otherUserId = conv.participants.find(id => id !== userId);
  if (!conv.unreadCount) conv.unreadCount = {};
  conv.unreadCount[otherUserId] = (conv.unreadCount[otherUserId] || 0) + 1;
  conv.updatedAt = new Date().toISOString();
  saveChatData(chatData);
  const sender = getUserById(userId);
  res.json({ success: true, message: { ...newMessage, senderUsername: sender?.username || 'Unknown', senderProfilePic: sender?.profilePic || '', isVerified: isVerified(userId) } });
});

app.post('/api/chat/upload-media', requireLogin, chatMediaUpload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Tidak ada file yang diupload' });
  let mediaType = 'image';
  if (req.file.mimetype.startsWith('video/')) mediaType = 'video';
  else if (req.file.mimetype.startsWith('audio/')) mediaType = 'audio';
  res.json({ success: true, mediaUrl: '/uploads/chat/' + req.file.filename, mediaType });
});

app.delete('/api/chat/message/:messageId', requireLogin, (req, res) => {
  const { messageId } = req.params;
  const userId = req.session.userId;
  const chatData = getChatData();
  let found = false;
  for (const convId in chatData.messages) {
    const msgIndex = chatData.messages[convId].findIndex(m => m.id === messageId);
    if (msgIndex !== -1) {
      if (chatData.messages[convId][msgIndex].senderId !== userId) return res.status(403).json({ error: 'Tidak bisa menghapus pesan orang lain' });
      chatData.messages[convId][msgIndex].deleted = true;
      chatData.messages[convId][msgIndex].text = '';
      chatData.messages[convId][msgIndex].mediaUrl = null;
      found = true;
      break;
    }
  }
  if (!found) return res.status(404).json({ error: 'Pesan tidak ditemukan' });
  saveChatData(chatData);
  res.json({ success: true });
});

app.get('/api/chat/unread', requireLogin, (req, res) => {
  const count = getUnreadCount(req.session.userId);
  res.json({ success: true, count });
});

// Admin Routes
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const userData = readJSON('data/user.json');
  const verifiedData = readJSON('data/verified.users.json');
  const levelsData = readJSON('data/levels.json');
  const loginData = readJSON('data/login.json');
  const users = Object.values(userData).map(user => ({
    id: user.id, username: user.username, profilePic: user.profilePic, bio: user.bio,
    posts: user.posts || 0, followers: user.followers || 0, following: user.following || 0,
    isVerified: verifiedData.verified?.includes(user.id) || false,
    isAdmin: loginData.adminUsers?.includes(user.id) || false,
    level: levelsData.userLevels[user.id]?.level || 1, xp: levelsData.userLevels[user.id]?.xp || 0,
    badges: getUserBadges(user.id), createdAt: user.createdAt
  }));
  res.json({ users });
});

app.get('/api/admin/posts', requireAdmin, (req, res) => {
  const database = readJSON('data/database.json');
  const userData = readJSON('data/user.json');
  const posts = (database.posts || []).map(post => ({ ...post, username: userData[post.userId]?.username || 'Unknown', userProfilePic: userData[post.userId]?.profilePic || '', likesCount: post.likes ? post.likes.length : 0, commentsCount: post.comments ? post.comments.length : 0, isVerified: isVerified(post.userId), mediaCount: post.mediaArray ? post.mediaArray.length : 1 })).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ posts });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const userData = readJSON('data/user.json');
  const database = readJSON('data/database.json');
  const loginData = readJSON('data/login.json');
  const verifiedData = readJSON('data/verified.users.json');
  const levelsData = readJSON('data/levels.json');
  const chatData = getChatData();
  let totalMedia = 0, totalMusic = 0, totalXP = 0;
  database.posts?.forEach(post => { totalMedia += post.mediaArray ? post.mediaArray.length : 1; if (post.musicUrl) totalMusic++; });
  for (const userId in levelsData.userLevels) totalXP += levelsData.userLevels[userId].xp || 0;
  const totalMessages = Object.values(chatData.messages || {}).reduce((sum, msgs) => sum + msgs.length, 0);
  const stats = {
    totalUsers: Object.keys(userData).length, totalPosts: (database.posts || []).length,
    totalComments: database.comments?.length || 0, totalAdmins: loginData.adminUsers?.length || 0,
    totalVerified: verifiedData.verified?.length || 0,
    totalImages: (database.posts || []).filter(p => p.mediaType === 'image').length,
    totalVideos: (database.posts || []).filter(p => p.mediaType === 'video').length,
    totalMedia, totalMusic, totalXP, totalMessages,
    avgLevel: Object.keys(levelsData.userLevels).length > 0 ? Object.values(levelsData.userLevels).reduce((sum, l) => sum + l.level, 0) / Object.keys(levelsData.userLevels).length : 0
  };
  res.json({ stats });
});

app.post('/api/admin/verify/:userId', requireAdmin, (req, res) => {
  const targetId = req.params.userId;
  const verifiedData = readJSON('data/verified.users.json');
  if (!verifiedData.verified) verifiedData.verified = [];
  if (!verifiedData.verified.includes(targetId)) { verifiedData.verified.push(targetId); writeJSON('data/verified.users.json', verifiedData); addXP(targetId, 100, 'verified'); }
  res.json({ success: true, verified: true });
});

app.post('/api/admin/unverify/:userId', requireAdmin, (req, res) => {
  const targetId = req.params.userId;
  const verifiedData = readJSON('data/verified.users.json');
  if (verifiedData.verified) { verifiedData.verified = verifiedData.verified.filter(id => id !== targetId); writeJSON('data/verified.users.json', verifiedData); }
  res.json({ success: true, verified: false });
});

app.post('/api/admin/make-admin/:userId', requireAdmin, (req, res) => {
  const targetId = req.params.userId;
  const loginData = readJSON('data/login.json');
  if (!loginData.adminUsers) loginData.adminUsers = [];
  if (!loginData.adminUsers.includes(targetId)) { loginData.adminUsers.push(targetId); writeJSON('data/login.json', loginData); addXP(targetId, 200, 'become_developer'); }
  res.json({ success: true, isAdmin: true });
});

app.post('/api/admin/remove-admin/:userId', requireAdmin, (req, res) => {
  const targetId = req.params.userId;
  const loginData = readJSON('data/login.json');
  if (loginData.adminUsers) { loginData.adminUsers = loginData.adminUsers.filter(id => id !== targetId); writeJSON('data/login.json', loginData); }
  res.json({ success: true, isAdmin: false });
});

app.delete('/api/admin/post/:postId', requireAdmin, (req, res) => {
  const postId = req.params.postId;
  const database = readJSON('data/database.json');
  const postIndex = database.posts.findIndex(p => p.id === postId);
  if (postIndex === -1) return res.status(404).json({ error: 'Post not found' });
  const post = database.posts[postIndex];
  database.posts.splice(postIndex, 1);
  if (database.comments) database.comments = database.comments.filter(c => c.postId !== postId);
  writeJSON('data/database.json', database);
  const userData = readJSON('data/user.json');
  if (userData[post.userId]) { userData[post.userId].posts = Math.max(0, (userData[post.userId].posts || 0) - 1); writeJSON('data/user.json', userData); }
  res.json({ success: true });
});

// ========== NEW: Admin Delete User ==========
app.delete('/api/admin/user/:userId', requireAdmin, (req, res) => {
  const targetId = req.params.userId;

  // Cegah developer menghapus akun sendiri
  if (targetId === req.session.userId) {
    return res.status(400).json({ error: 'Tidak bisa menghapus akun sendiri melalui panel developer' });
  }

  // Pastikan user ada
  const user = getUserById(targetId);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });

  try {
    deleteUserData(targetId);
    res.json({ success: true, message: `Akun @${user.username} berhasil dihapus` });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'Gagal menghapus akun: ' + err.message });
  }
});

app.get('/api/admin/badges', requireAdmin, (req, res) => {
  res.json({ badges: getAllCustomBadges() });
});

app.post('/api/admin/assign-badge', requireAdmin, (req, res) => {
  const { userId, badgeName, badgeIcon, badgeColor } = req.body;
  if (!userId || !badgeName) return res.status(400).json({ error: 'User ID dan nama badge diperlukan' });
  const result = assignBadge(userId, badgeName, badgeIcon || '🏷️', badgeColor || '#667eea');
  if (result) res.json({ success: true });
  else res.status(500).json({ error: 'Gagal assign badge' });
});

app.post('/api/admin/remove-badge', requireAdmin, (req, res) => {
  const { userId, badgeName } = req.body;
  if (!userId || !badgeName) return res.status(400).json({ error: 'User ID dan nama badge diperlukan' });
  const result = removeBadge(userId, badgeName);
  if (result) res.json({ success: true });
  else res.status(500).json({ error: 'Gagal remove badge' });
});

// Notifications (simple)
app.get('/api/notifications', requireLogin, (req, res) => {
  const database = readJSON('data/database.json');
  const userData = readJSON('data/user.json');
  const notifications = [];
  (database.posts || []).forEach(post => {
    if (post.userId === req.session.userId && post.likes && post.likes.length > 0) {
      post.likes.forEach(likeUserId => {
        if (likeUserId !== req.session.userId) notifications.push({ id: `like_${post.id}_${likeUserId}`, type: 'like', userId: likeUserId, username: userData[likeUserId]?.username || 'Unknown', profilePic: userData[likeUserId]?.profilePic || '', isVerified: isVerified(likeUserId), postId: post.id, postMedia: post.mediaUrl, createdAt: post.createdAt, read: false });
      });
    }
    if (post.userId === req.session.userId && post.comments && post.comments.length > 0) {
      database.comments?.forEach(comment => {
        if (comment.postId === post.id && comment.userId !== req.session.userId) notifications.push({ id: `comment_${comment.id}`, type: 'comment', userId: comment.userId, username: comment.username, profilePic: comment.profilePic || '', isVerified: isVerified(comment.userId), postId: post.id, postMedia: post.mediaUrl, comment: comment.text, createdAt: comment.createdAt, read: false });
      });
    }
  });
  notifications.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ notifications: notifications.slice(0, 50) });
});

// Settings
app.post('/api/settings/change-password', requireLogin, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current password and new password required' });
  const loginData = readJSON('data/login.json');
  const userIndex = loginData.users.findIndex(u => u.id === req.session.userId);
  if (userIndex === -1) return res.status(404).json({ error: 'User not found' });
  const valid = await bcrypt.compare(currentPassword, loginData.users[userIndex].password);
  if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  loginData.users[userIndex].password = hashedPassword;
  writeJSON('data/login.json', loginData);
  res.json({ success: true });
});

app.delete('/api/settings/delete-account', requireLogin, async (req, res) => {
  const userId = req.session.userId;
  deleteUserData(userId);
  req.session.destroy();
  res.clearCookie('connect.sid');
  res.clearCookie('rememberToken');
  res.json({ success: true });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server berjalan di http://localhost:${PORT}`);
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err.stack);
  res.status(500).json({ error: err.message || 'Terjadi kesalahan server' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint tidak ditemukan' });
});

module.exports = app;
