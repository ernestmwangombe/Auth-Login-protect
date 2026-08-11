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

// Binding the application to listen for HTTP requests on TCP Port 3000.
app.listen(PORT, () => {
  console.log('=======================================================');
  console.log(`🚀 Server running on port ${PORT} and connected to Supabase`);
  console.log(`🔒 Identity Provider Target: ${SUPABASE_URL}`);
  console.log('=======================================================');
});