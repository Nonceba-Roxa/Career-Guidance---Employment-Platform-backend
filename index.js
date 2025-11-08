/**
 * 🌐 Career Guidance Platform Backend (Node.js + Express + Firebase)
 * Compatible with: Local development & Vercel serverless deployment
 */

const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
let appInitialized = false;

// ==================== FIREBASE INITIALIZATION ====================
const initializeFirebase = () => {
  if (appInitialized) return;
  try {
    let serviceAccount;

    if (process.env.NODE_ENV === 'production') {
      // --- Use env vars on Vercel ---
      serviceAccount = {
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

      console.log('✅ Firebase initialized (Vercel environment)');
    } else {
      // --- Local mode with serviceAccountKey.json ---
      serviceAccount = require('./serviceAccountKey.json');
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
      });
      console.log('✅ Firebase initialized (Local development)');
    }

    appInitialized = true;
  } catch (error) {
    console.error('❌ Firebase initialization failed:', error.message);
  }
};

initializeFirebase();

const db = admin.firestore();
const auth = admin.auth();

// ==================== SECURITY MIDDLEWARE ====================
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(compression());
app.use(morgan('tiny'));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// ==================== BASE ROUTES ====================
app.get('/', (req, res) => {
  res.json({
    success: true,
    name: 'Career Guidance Platform API',
    version: '1.0.0',
    status: 'OK',
    environment: process.env.NODE_ENV || 'development',
    endpoints: {
      public: ['/api/health', '/api/test-auth'],
      admin: ['/api/admin/*'],
      user: ['/api/user/*', '/api/student/*', '/api/institute/*']
    },
    timestamp: new Date().toISOString()
  });
});

app.get('/api/health', async (req, res) => {
  try {
    await db.collection('health').doc('check').set({
      status: 'OK',
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({
      success: true,
      message: 'Server and Firestore operational',
      uptime: process.uptime(),
      node: process.version,
      region: process.env.VERCEL_REGION || 'local',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: 'Database connection failed',
      details: err.message
    });
  }
});

app.get('/api/test-auth', async (req, res) => {
  res.json({
    success: true,
    message: 'Node.js + Express API running successfully on Vercel'
  });
});

// ==================== ERROR HANDLING ====================
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method
  });
});

// ==================== EXPORT APP (Vercel compatible) ====================
module.exports = app;

// ==================== LOCAL SERVER MODE ====================
if (require.main === module) {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`🚀 Career Guidance Platform API running at http://localhost:${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log('✅ API ready to handle requests');
  });
}
