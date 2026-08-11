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
app.use(express.json());

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// Basic ping route to verify the guard tower server is alive and reachable.
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Kenyan SME Document Security API - Stage 0 Guard Tower Online',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /auth/signup
 * Registers a new user account with Supabase Auth.
 * Systems Analogy: Provisioning a new user profile record in Active Directory / LDAP.
 */
app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body;

  // Perimeter Inspection: Validate input payload presence (HTTP 400 Bad Request)
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

    // HTTP 201 Created: Account successfully created in Identity Provider
    return res.status(201).json({
      message: 'User registered successfully',
      user: data.user
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server authentication error' });
  }
});

/**
 * POST /auth/login
 * Authenticates user credentials against Supabase and returns a JWT access token.
 * Systems Analogy: AAA/RADIUS Server verifying password hash and issuing a Kerberos pass/JWT.
 */
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  // Perimeter Inspection: Reject empty credentials (HTTP 400 Bad Request)
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error || !data.session) {
      // HTTP 401 Unauthorized: Invalid pass/credentials
      return res.status(401).json({ error: 'Invalid login credentials' });
    }

    // HTTP 200 OK: Send access token and refresh token back to client
    return res.status(200).json({
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      user: data.user
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