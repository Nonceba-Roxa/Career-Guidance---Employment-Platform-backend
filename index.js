const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
require('dotenv').config();

let appInitialized = false;

// Initialize Firebase Admin safely for serverless
const initializeFirebase = () => {
  if (appInitialized) return;
  try {
    const serviceAccount = {
      type: process.env.FIREBASE_TYPE,
      project_id: process.env.FIREBASE_PROJECT_ID,
      private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
      private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
      client_email: process.env.FIREBASE_CLIENT_EMAIL,
      client_id: process.env.FIREBASE_CLIENT_ID,
      auth_uri: process.env.FIREBASE_AUTH_URI,
      token_uri: process.env.FIREBASE_TOKEN_URI,
      auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
      client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
      universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN
    };

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`,
      storageBucket: process.env.FIREBASE_STORAGE_BUCKET
    });

    console.log('✅ Firebase initialized for Vercel environment');
    appInitialized = true;
  } catch (error) {
    console.error('❌ Firebase initialization failed:', error.message);
  }
};

initializeFirebase();

const db = admin.firestore();
const auth = admin.auth();

const app = express();

// ===== Middleware =====
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(compression());
app.use(morgan('tiny'));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// ===== Routes =====
app.get('/', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Career Guidance Platform API (Vercel Ready)',
    version: '1.0.0',
    time: new Date().toISOString()
  });
});

app.get('/api/health', async (req, res) => {
  try {
    await db.collection('health').doc('check').set({
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'OK'
    });
    res.json({ status: 'OK', firestore: 'Connected' });
  } catch (err) {
    res.status(500).json({ status: 'Error', message: err.message });
  }
});

// Example secured route
app.get('/api/test-auth', async (req, res) => {
  res.json({ success: true, message: 'Auth works in Vercel!' });
});

// ===== Error Handling =====
app.use('*', (req, res) => res.status(404).json({ error: 'Not Found' }));

// Export app for Vercel (serverless)
module.exports = app;
