require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const PORT = process.env.PORT || 3000;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ CRITICAL SECURITY ERROR: Missing SUPABASE_URL or SUPABASE_KEY in .env!');
  console.error('Please configure your .env file before starting the server process.');
  process.exit(1);
}

const app = express();

// Middleware: Firewall packet inspection parsing incoming JSON payloads
app.use(express.json());

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ==============================================================================
// STAGE 0: GUARD TOWER HEALTH CHECK
// ==============================================================================

app.get('/', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Kenyan SME Document Security API - Stage 0 Guard Tower Online',
    timestamp: new Date().toISOString()
  });
});

// ==============================================================================
// STAGE 1: OPEN AUTH (SIGN UP & LOG IN)
// ==============================================================================

app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const { data, error } = await supabase.auth.signUp({
      email,
      password
    });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(201).json({
      message: 'User registered successfully',
      user: data.user
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server authentication error' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error || !data.session) {
      return res.status(401).json({ error: 'Invalid login credentials' });
    }

    return res.status(200).json({
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      user: data.user
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server authentication error' });
  }
});

// ==============================================================================
// STAGE 2 & STAGE 3: PUBLIC & PROTECTED GATES WITH TOKEN VERIFICATION
// ==============================================================================

app.get('/public/info', (req, res) => {
  return res.status(200).json({
    message: 'Welcome stranger! This info is public.'
  });
});

app.get('/protected/profile', async (req, res) => {
  const authHeader = req.headers.authorization;

  // Step 1: Perimeter Inspection — Ensure "Authorization: Bearer <token>" is present
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access token required' });
  }

  const token = authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    // Step 2 & 3: Systems Analogy — Scanner at the entrance calling central HQ
    // (Supabase Auth) to verify if the digital visitor badge is authentic or forged.
    const { data, error } = await supabase.auth.getUser(token);

    // Step 3: If token is expired, tampered with, or invalid -> turn away forgeries
    if (error || !data.user) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Step 4: Token is authentic -> return 200 with user safe metadata
    return res.status(200).json({
      user: {
        id: data.user.id,
        email: data.user.email,
        created_at: data.user.created_at
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server authentication error' });
  }
});

app.listen(PORT, () => {
  console.log('=======================================================');
  console.log(`🚀 Server running on port ${PORT} and connected to Supabase`);
  console.log(`🔒 Identity Provider Target: ${SUPABASE_URL}`);
  console.log('=======================================================');
});