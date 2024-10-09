// server.js
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const qs = require('qs');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// Environment variables
const clientId = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;
const tenantId = process.env.TENANT_ID;
const redirectUri = process.env.REDIRECT_URI;

let codeVerifierStore = {}; // Use an in-memory store to temporarily hold code_verifiers

// Helper function to base64 URL encode a string
const base64URLEncode = (str) => {
  return str.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

// Generate a PKCE code verifier and code challenge
const generatePKCECodes = () => {
  const codeVerifier = base64URLEncode(crypto.randomBytes(32)); // Generate a random code verifier
  const codeChallenge = base64URLEncode(crypto.createHash('sha256').update(codeVerifier).digest()); // Generate code challenge
  return { codeVerifier, codeChallenge };
};

// Step 1: Redirect user to Microsoft login page with PKCE
app.get('/auth/login', (req, res) => {
  const { codeVerifier, codeChallenge } = generatePKCECodes(); // Generate the code challenge

  // Store the codeVerifier temporarily using a session identifier (for demonstration purposes, using a timestamp as a simple key)
  const sessionId = Date.now().toString();
  codeVerifierStore[sessionId] = codeVerifier;

  const authorizationUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?client_id=${clientId}&response_type=code&redirect_uri=${redirectUri}&response_mode=query&scope=openid%20profile%20offline_access%20Calendars.ReadWrite&code_challenge_method=S256&code_challenge=${codeChallenge}&state=${sessionId}`;
  
  res.redirect(authorizationUrl); // Redirect the user to the Microsoft login with PKCE
});

// Step 2: Handle the redirect and exchange the authorization code for tokens using PKCE
app.get('/auth/callback', async (req, res) => {
  const code = req.query.code; // Authorization code received from Microsoft
  const sessionId = req.query.state; // Retrieve the session identifier to get the correct code_verifier

  if (!code || !sessionId || !codeVerifierStore[sessionId]) {
    return res.status(400).send('Authorization code or session identifier not found');
  }

  const codeVerifier = codeVerifierStore[sessionId]; // Retrieve the code_verifier from the temporary store

  const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;

  // Create the data payload for the token request
  const data = qs.stringify({
    client_id: clientId,
    client_secret: clientSecret,
    scope: 'openid profile offline_access Calendars.ReadWrite',
    code: code,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
    code_verifier: codeVerifier, // Include the code verifier for PKCE
  });

  try {
    // Exchange the authorization code for an access token
    const tokenResponse = await axios.post(tokenUrl, data, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    const accessToken = tokenResponse.data.access_token;
    const refreshToken = tokenResponse.data.refresh_token;

    // Cleanup the stored code_verifier after successful exchange
    delete codeVerifierStore[sessionId];

    // Send the access and refresh tokens back to the frontend (Vue.js)
    res.json({ accessToken, refreshToken });
  } catch (error) {
    console.error('Error exchanging code for tokens:', error.response ? error.response.data : error.message);
    res.status(500).send('Authentication failed');
  }
});

// Start the backend server
app.listen(port, () => {
  console.log(`Backend running at http://localhost:${port}`);
});
