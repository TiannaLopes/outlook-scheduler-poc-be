// server.js
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const qs = require('qs');

const app = express();
const port = process.env.PORT || 3000;

// Environment variables
const clientId = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;
const tenantId = process.env.TENANT_ID;
const redirectUri = process.env.REDIRECT_URI;

// Step 1: Redirect user to Microsoft login page
app.get('/auth/login', (req, res) => {
  const authorizationUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?client_id=${clientId}&response_type=code&redirect_uri=${redirectUri}&response_mode=query&scope=openid%20profile%20offline_access%20Calendars.ReadWrite`;
  res.redirect(authorizationUrl);
});

// Step 2: Handle the redirect and exchange the authorization code for tokens
app.get('/auth/callback', async (req, res) => {
  const code = req.query.code; // Authorization code received from Microsoft

  if (!code) {
    return res.status(400).send('Authorization code not found');
  }

  const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;

  const data = qs.stringify({
    client_id: clientId,
    scope: 'openid profile offline_access Calendars.ReadWrite',
    code: code,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
    client_secret: clientSecret,
  });

  try {
    // Step 3: Exchange the authorization code for an access token
    const tokenResponse = await axios.post(tokenUrl, data, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    const accessToken = tokenResponse.data.access_token;
    const refreshToken = tokenResponse.data.refresh_token;

    // Send access and refresh tokens back to the frontend (Vue.js)
    res.json({ accessToken, refreshToken });
  } catch (error) {
    console.error('Error exchanging code for tokens:', error.response ? error.response.data : error.message);
    res.status(500).send('Authentication failed');
  }
});

// Step 4: Start the backend server
app.listen(port, () => {
  console.log(`Backend running at http://localhost:${port}`);
});
