require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const swaggerUi = require('swagger-ui-express');
const openapiDocument = require('./openapi.json');

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

// Stage 5: Serve Swagger UI Documentation at /docs
app.use('/docs', swaggerUi.serve, swaggerUi.setup(openapiDocument));

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
// STAGE 4: REUSABLE AUTH MIDDLEWARE GUARD
// ==============================================================================

/**
 * REUSABLE MIDDLEWARE GUARD (requireAuth)
 * 
 * Network Analogy: Instead of placing a security guard inside every single office room 
 * in a building, you place a single, highly trained security guard at the main security 
 * checkpoint before the elevator bank.
 * 
 * If a request passes this guard, it gets tagged with `req.user` and allowed into the room (`next()`).
 * If the pass is missing, forged, or expired, the guard turns them away (`HTTP 401`).
 */
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  // Step 1: Perimeter Check — Ensure "Authorization: Bearer <token>" is present
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access token required' });
  }

  const token = authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    // Step 2: Verify badge authenticity directly with central Identity Provider (Supabase)
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Step 3: Attach verified identity to request object for downstream routes
    req.user = data.user;

    // Step 4: Open gate and allow request to proceed to route handler
    next();
  } catch (err) {
    return res.status(500).json({ error: 'Internal server authentication error' });
  }
}

// ==============================================================================
// STAGE 2, 3 & 4: PUBLIC & PROTECTED ROUTES
// ==============================================================================

app.get('/public/info', (req, res) => {
  return res.status(200).json({
    message: 'Welcome stranger! This info is public.'
  });
});

app.get('/protected/profile', requireAuth, (req, res) => {
  // Notice how clean this route body is! The guard already validated req.user.
  return res.status(200).json({
    user: {
      id: req.user.id,
      email: req.user.email,
      created_at: req.user.created_at
    }
  });
});

app.get('/protected/dashboard', requireAuth, (req, res) => {
  return res.status(200).json({
    message: `Welcome to the secure SME operational dashboard, ${req.user.email}!`,
    status: 'Active Session'
  });
});

app.post('/auth/logout', requireAuth, async (req, res) => {
  try {
    // Revoke session in Supabase Auth
    const { error } = await supabase.auth.signOut();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    // Return 204 No Content as required by REST API standard for logout
    return res.status(204).send();
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