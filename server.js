// server.js
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const qs = require('qs');
const crypto = require('crypto');

const app = express(); 
const port = process.env.PORT || 3000;

const cors = require('cors');
app.use(cors()); 

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
  const code = req.query.code;
  const sessionId = req.query.state;

  if (!code || !sessionId || !codeVerifierStore[sessionId]) {
    return res.status(400).send('Authorization code or session identifier not found');
  }

  const codeVerifier = codeVerifierStore[sessionId];

  const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;

  const data = qs.stringify({
    client_id: clientId,
    client_secret: clientSecret,
    scope: 'openid profile offline_access Calendars.ReadWrite',
    code: code,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
    code_verifier: codeVerifier,
  });

  try {
    const tokenResponse = await axios.post(tokenUrl, data, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    const accessToken = tokenResponse.data.access_token;
    const refreshToken = tokenResponse.data.refresh_token;

    // Clean up the code_verifier after successful token exchange
    delete codeVerifierStore[sessionId];

    // Redirect to the frontend with access token and refresh token in query parameters
    res.redirect(`http://localhost:8080?accessToken=${encodeURIComponent(accessToken)}&refreshToken=${encodeURIComponent(refreshToken)}`);
  } catch (error) {
    console.error('Error exchanging code for tokens:', error.response ? error.response.data : error.message);
    res.status(500).send('Authentication failed');
  }
});


// Endpoint to create appointment
app.post('/appointments', async (req, res) => {
  const { accessToken, title, startTime, endTime, description } = req.body;

  if (!accessToken) {
    return res.status(401).send('Access token is missing');
  }

  // Event object to send to Microsoft Graph API
  const event = {
    subject: title,
    body: {
      contentType: 'HTML',
      content: description || '',
    },
    start: {
      dateTime: new Date(startTime).toISOString(),
      timeZone: 'UTC',
    },
    end: {
      dateTime: new Date(endTime).toISOString(),
      timeZone: 'UTC',
    },
  };

  try {
    // Make the request to Microsoft Graph API to create the event
    const graphResponse = await axios.post(
      'https://graph.microsoft.com/v1.0/me/events',
      event,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      }
    );

    if (graphResponse.status === 201) {
      res.status(201).send('Appointment created successfully');
    } else {
      res.status(graphResponse.status).send(graphResponse.data);
    }
  } catch (error) {
    console.error('Error creating appointment:', error.response ? error.response.data : error.message);
    res.status(500).send('Failed to create appointment');
  }
});


// Start the backend server
app.listen(port, () => {
  console.log(`Backend running at http://localhost:${port}`);
});
