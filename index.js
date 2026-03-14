const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// -------------------- SUPABASE --------------------
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY; // service_role key for backend

// DEBUG - remove after fixing
console.log('ENV CHECK:');
console.log('SUPABASE_URL:', SUPABASE_URL ? `SET (${SUPABASE_URL.slice(0, 20)}...)` : 'NOT SET');
console.log('SUPABASE_SERVICE_KEY:', SUPABASE_SERVICE_KEY ? `SET (${SUPABASE_SERVICE_KEY.slice(0, 10)}...)` : 'NOT SET');
console.log('All env keys:', Object.keys(process.env).join(', '));

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('❌ SUPABASE_URL and SUPABASE_SERVICE_KEY environment variables are required!');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// -------------------- MIDDLEWARE --------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'memoryretrieve-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// -------------------- AUTH MIDDLEWARE --------------------
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

// -------------------- AUTH ROUTES --------------------

// Login page
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/');
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render('login', { error: 'Please enter username and password.' });
  }

  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username.trim().toLowerCase())
      .single();

    if (error || !user) {
      return res.render('login', { error: 'Invalid username or password.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.render('login', { error: 'Invalid username or password.' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect('/');
  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { error: 'Something went wrong. Please try again.' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Register page (first-time setup or admin use)
app.get('/register', (req, res) => {
  // Only allow if no users exist yet, or if logged in
  res.render('register', { error: null, success: null });
});

app.post('/register', async (req, res) => {
  const { username, password, confirmPassword, invite_code } = req.body;

  // Simple invite code protection so random people can't register
  const INVITE_CODE = process.env.INVITE_CODE || 'memoryretrieve2024';
  if (invite_code !== INVITE_CODE) {
    return res.render('register', { error: 'Invalid invite code.', success: null });
  }

  if (!username || !password) {
    return res.render('register', { error: 'Please fill in all fields.', success: null });
  }

  if (password !== confirmPassword) {
    return res.render('register', { error: 'Passwords do not match.', success: null });
  }

  if (password.length < 8) {
    return res.render('register', { error: 'Password must be at least 8 characters.', success: null });
  }

  try {
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('username', username.trim().toLowerCase())
      .single();

    if (existing) {
      return res.render('register', { error: 'Username already taken.', success: null });
    }

    const password_hash = await bcrypt.hash(password, 12);

    const { error } = await supabase.from('users').insert({
      username: username.trim().toLowerCase(),
      password_hash,
      created_at: new Date().toISOString()
    });

    if (error) throw error;

    res.render('register', { error: null, success: 'Account created! You can now log in.' });
  } catch (err) {
    console.error('Register error:', err);
    res.render('register', { error: 'Failed to create account. Please try again.', success: null });
  }
});

// -------------------- HELPER: Get signed video URL --------------------
async function getVideoUrl(videoId) {
  try {
    const { data, error } = await supabase.storage
      .from('videos')
      .createSignedUrl(`${videoId}.mp4`, 3600); // 1 hour expiry

    if (error || !data) return null;
    return data.signedUrl;
  } catch {
    return null;
  }
}

// -------------------- MAIN ROUTES (protected) --------------------

// Home - show detections grouped by video
app.get('/', requireAuth, async (req, res) => {
  try {
    const { data: detections, error } = await supabase
      .from('detections')
      .select('*')
      .order('timestamp', { ascending: false });

    if (error) throw error;

    const videoMap = {};
    detections.forEach(det => {
      if (!videoMap[det.video_id]) {
        videoMap[det.video_id] = { videoId: det.video_id, cameraId: det.camera_id, detections: [] };
      }
      videoMap[det.video_id].detections.push(det);
    });

    const videos = Object.values(videoMap);
    res.render('index', {
      videos,
      message: req.query.message || null,
      error: req.query.error || null,
      username: req.session.username
    });
  } catch (err) {
    console.error('Error loading home page:', err);
    res.render('index', {
      videos: [],
      message: null,
      error: 'Failed to load data',
      username: req.session.username
    });
  }
});

// Video viewer
app.get('/video/:videoId', requireAuth, async (req, res) => {
  try {
    const { videoId } = req.params;

    const { data: detections, error } = await supabase
      .from('detections')
      .select('*')
      .eq('video_id', videoId)
      .order('timestamp_sec', { ascending: true });

    if (error) throw error;

    const videoUrl = await getVideoUrl(videoId);
    const cameraId = detections.length > 0 ? detections[0].camera_id : 'Unknown';

    res.render('edit', {
      videoId,
      cameraId,
      detections,
      videoUrl,
      username: req.session.username
    });
  } catch (err) {
    console.error('Error loading video page:', err);
    res.redirect('/?error=Failed to load video');
  }
});

// Search
app.get('/search', requireAuth, async (req, res) => {
  try {
    const { item } = req.query;
    if (!item) return res.redirect('/');

    const { data: detections, error } = await supabase
      .from('detections')
      .select('*')
      .ilike('item', `%${item}%`)
      .order('timestamp', { ascending: false });

    if (error) throw error;

    res.render('add', {
      detections,
      searchTerm: item,
      username: req.session.username
    });
  } catch (err) {
    console.error('Search error:', err);
    res.render('add', {
      detections: [],
      searchTerm: req.query.item,
      error: 'Search failed',
      username: req.session.username
    });
  }
});

// -------------------- API ROUTES --------------------

// API - last seen
app.get('/api/last-seen/:item', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('detections')
      .select('*')
      .ilike('item', `%${req.params.item}%`)
      .order('timestamp', { ascending: false })
      .limit(1);

    if (error) throw error;
    if (!data || data.length === 0) return res.json({ found: false, message: 'Item never detected' });
    res.json({ found: true, detection: data[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to search' });
  }
});

// API - log detection (from Raspberry Pi — uses API key auth instead of session)
app.post('/api/detection', async (req, res) => {
  // Simple API key check for Raspberry Pi
  const apiKey = req.headers['x-api-key'];
  const EXPECTED_KEY = process.env.RASPI_API_KEY || 'raspi-secret-key';
  if (apiKey !== EXPECTED_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const { cameraId, videoId, item, confidence, timestamp, timestampSec } = req.body;
    if (!cameraId || !videoId || !item || !confidence || !timestamp || timestampSec === undefined) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const { error } = await supabase.from('detections').insert({
      camera_id: cameraId,
      video_id: videoId,
      item,
      confidence: parseFloat(confidence),
      timestamp: new Date(timestamp).toISOString(),
      timestamp_sec: parseInt(timestampSec),
      created_at: new Date().toISOString()
    });

    if (error) throw error;
    res.json({ success: true, message: 'Detection logged' });
  } catch (err) {
    console.error('Error logging detection:', err);
    res.status(500).json({ error: 'Failed to log detection' });
  }
});

// API - list items
app.get('/api/items', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('detections')
      .select('item');

    if (error) throw error;

    const items = [...new Set(data.map(d => d.item))].sort();
    res.json({ items });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get items' });
  }
});

// Delete detection
app.post('/delete/:id', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase
      .from('detections')
      .delete()
      .eq('id', req.params.id);

    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.json({ success: false, error: 'Failed to delete' });
  }
});

// -------------------- START SERVER --------------------
app.listen(PORT, () => {
  console.log(`✅ Smart Camera Dashboard running on http://localhost:${PORT}`);
});
