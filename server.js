// System Analogy: Loading network interface modules and cryptographic libraries into memory.
require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');

// Inspection Rule: Verify that our security keys exist before opening network ports.
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const PORT = process.env.PORT || 3000;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ CRITICAL SECURITY ERROR: Missing SUPABASE_URL or SUPABASE_KEY in .env!');
  console.error('Please configure your .env file before starting the server process.');
  process.exit(1);
}

// Creating our application router instance (the digital security gatehouse).
const app = express();

// Middleware to parse incoming JSON network payloads (like firewall packet inspection).
app.use(express.json());

// System Analogy: Establishing an encrypted API bridge to our cloud RADIUS/Identity Provider server.
// We use the safe public 'anon' key here—never the service_role key.
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// Basic ping route to verify the guard tower server is alive and reachable.
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

// ==============================================================================
// STAGE 2: THE PUBLIC & PROTECTED GATES
// ==============================================================================

/**
 * GET /public/info
 * Publicly accessible endpoint requiring no authentication tokens.
 * Systems Analogy: Building reception lobby open to the public.
 */
app.get('/public/info', (req, res) => {
  return res.status(200).json({
    message: 'Welcome stranger! This info is public.'
  });
});

/**
 * GET /protected/profile
 * Protected endpoint requiring an Authorization header (Bearer token).
 * Systems Analogy: Turnstile gate checking if a visitor ID badge is presented.
 */
app.get('/protected/profile', (req, res) => {
  const authHeader = req.headers.authorization;

  // Inspection Rule: Verify presence of "Authorization: Bearer <token>"
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access token required' });
  }

  // Extract the token string from behind "Bearer "
  const token = authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  // Stage 2 Checkpoint: Token string is present (verification added in Stage 3)
  return res.status(200).json({
    message: 'Welcome authorized user! Token received.',
    token: token
  });
});

// Binding the application to listen for HTTP requests on TCP Port 3000.
app.listen(PORT, () => {
  console.log('=======================================================');
  console.log(`🚀 Server running on port ${PORT} and connected to Supabase`);
  console.log(`🔒 Identity Provider Target: ${SUPABASE_URL}`);
  console.log('=======================================================');
});