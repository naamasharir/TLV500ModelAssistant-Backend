require('dotenv').config({
  path: process.env.NODE_ENV === 'production' ? '.env.production' : '.env'
});

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const multer = require('multer');
const cors = require('cors');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { GoogleGenAI } = require('@google/genai');
const fs = require('fs');
const path = require('path');
const { google } = require('googleapis');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');

// Import models
const User = require('./models/User');
const ChatHistory = require('./models/ChatHistory');
const ActionHistory = require('./models/ActionHistory');
const ChangePlan = require('./models/ChangePlan');

const logger = require('./logger');

const app = express();
const PORT = process.env.PORT || 3001;

// 🔥 Initialize Winston logging system
logger.info('🔥 Winston logging system initialized - All detailed logs saved to logs/ directory');
// MongoDB Connection
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/fin-copilot';
logger.info('🔗 Attempting to connect to MongoDB...');
console.log('🔗 Database URI:', mongoUri.replace(/:[^:@]*@/, ':***@')); // Hide password in logs

mongoose.connect(mongoUri, {
  serverSelectionTimeoutMS: 10000 // Timeout after 10s instead of 30s
})
.then(() => {
  logger.info('🍃 Connected to MongoDB successfully');
  console.log('📊 Database name:', mongoose.connection.db.databaseName);
  
  // Test the connection by listing collections
  mongoose.connection.db.listCollections().toArray()
    .then(collections => {
      console.log('📁 Available collections:', collections.map(c => c.name));
    })
    .catch(err => console.log('⚠️  Could not list collections:', err.message));
})
.catch((error) => {
  console.error('❌ MongoDB connection error:', error.message);
  console.log('💡 Check your Azure Cosmos DB connection string and credentials');
  
  // Don't exit in development so you can still test other features
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
});

// Monitor connection events
mongoose.connection.on('connected', () => {
  console.log('📡 Mongoose connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('📡 Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('📡 Mongoose disconnected from MongoDB');
});

// Initialize Gemini AI
const key = "AIzaSyC83AY7WDibXU0cgttKO4vQoPh1WrtcS0E";
console.log("🔑 Initializing Gemini with API Key:", key ? `${key.substring(0, 4)}...${key.substring(key.length - 4)}` : 'No key found!');
const genAI = new GoogleGenerativeAI(key);
const genAINew = new GoogleGenAI({apiKey: key}); // New SDK for caching

// ActionHistory model is now used instead of in-memory pendingChanges

// 🔧 Helper function for clean value conversion (fixes apostrophe issue)
function cleanValueConversion(value) {
    if (value === null || value === undefined || value === '') {
        return '';
    }
    
    // For numbers, convert directly without toString() to avoid locale formatting
    if (typeof value === 'number') {
        return String(value);
    }
    
    // For strings, clean all possible apostrophe and quote characters
    if (typeof value === 'string') {
        // Remove various apostrophe and quote characters that can appear in different locales
        return value.replace(/['\u0027\u2018\u2019\u201A\u201B\u201C\u201D\u201E\u201F\u2032\u2033\u2034\u2035\u2036\u2037]/g, '');
    }
    
    // For other types, convert safely and clean
    const stringValue = String(value);
    return stringValue.replace(/['\u0027\u2018\u2019\u201A\u201B\u201C\u201D\u201E\u201F\u2032\u2033\u2034\u2035\u2036\u2037]/g, '');
}

// 🔧 Helper function to determine correct value type for Google Sheets
function getCorrectValueType(value) {
    if (value === null || value === undefined || value === '') {
        return {};
    }
    
    // Check if it's already a number
    if (typeof value === 'number') {
        return { numberValue: value };
    }
    
    // Check if it's a formula
    if (typeof value === 'string' && value.startsWith('=')) {
        return { formulaValue: value };
    }
    
    // Check if it's a string that represents a number
    if (typeof value === 'string') {
        const cleanValue = cleanValueConversion(value);
        const numericValue = parseFloat(cleanValue);
        
        // If it's a valid number and the string contains only digits, decimal point, and minus sign
        if (!isNaN(numericValue) && /^-?[\d.]+$/.test(cleanValue)) {
            return { numberValue: numericValue };
        }
        
        // Otherwise, it's a string
        return { stringValue: cleanValue };
    }
    
    // For other types, convert to clean string
    return { stringValue: cleanValueConversion(value) };
}

// 📸 Helper Functions for Change Management
function cellToRange(cellAddress, sheetId) {
    const match = cellAddress.match(/([A-Z]+)(\d+)/);
    const column = match[1];
    const row = parseInt(match[2]);
    
    return {
        sheetId: sheetId,
        startRowIndex: row - 1,
        endRowIndex: row,
        startColumnIndex: column.charCodeAt(0) - 'A'.charCodeAt(0),
        endColumnIndex: column.charCodeAt(0) - 'A'.charCodeAt(0) + 1
    };
}

async function takeSnapshot(cellAddresses, sheets, spreadsheetId, selectedSheetName, sheetId) {
    console.log(`📸 Taking snapshot of ${cellAddresses.length} cells before changes`);
    
    const CHUNK_SIZE = 50; // מגביל ל-50 תאים לכל בקשה
    const snapshot = {};
    
    // חילוק התאים ל-chunks
    for (let i = 0; i < cellAddresses.length; i += CHUNK_SIZE) {
        const chunk = cellAddresses.slice(i, i + CHUNK_SIZE);
        const ranges = chunk.map(cell => `${selectedSheetName}!${cell}`);
        
        // קרא values עבור ה-chunk הזה
        const valuesResponse = await sheets.spreadsheets.values.batchGet({
            spreadsheetId: spreadsheetId,
            ranges: ranges
        });
        
        // קרא formatting עבור ה-chunk הזה
        const sheetData = await sheets.spreadsheets.get({
            spreadsheetId: spreadsheetId,
            ranges: ranges,
            includeGridData: true
        });
        
        // עבד את ה-chunk
        chunk.forEach((cellAddress, index) => {
            // Get the value
            const valueRange = valuesResponse.data.valueRanges[index];
            const value = valueRange.values?.[0]?.[0] || "";
            
            // Get the formatting
            const cellData = extractCellFormatting(sheetData, cellAddress, selectedSheetName);
            
            snapshot[cellAddress] = {
                value: value,
                backgroundColor: cellData.backgroundColor || { red: 1, green: 1, blue: 1 },
                textFormat: cellData.textFormat || {},
                numberFormat: cellData.numberFormat || {}
            };
        });
    }
    
    console.log(`📸 Snapshot captured:`, Object.keys(snapshot));
    return snapshot;
}

function extractCellFormatting(sheetData, cellAddress, sheetName) {
    try {
        const match = cellAddress.match(/([A-Z]+)(\d+)/);
        const column = match[1];
        const row = parseInt(match[2]) - 1; // Convert to 0-based
        const colIndex = column.charCodeAt(0) - 'A'.charCodeAt(0);
        
        const sheet = sheetData.data.sheets.find(s => s.properties.title === sheetName);
        if (!sheet || !sheet.data || !sheet.data[0] || !sheet.data[0].rowData) {
            return {};
        }
        
        const rowData = sheet.data[0].rowData[row];
        if (!rowData || !rowData.values || !rowData.values[colIndex]) {
            return {};
        }
        
        const cellData = rowData.values[colIndex];
        return {
            backgroundColor: cellData.userEnteredFormat?.backgroundColor,
            textFormat: cellData.userEnteredFormat?.textFormat,
            numberFormat: cellData.userEnteredFormat?.numberFormat
        };
    } catch (error) {
        console.error('Error extracting cell formatting:', error);
        return {};
    }
}

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Configure multer for file uploads
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Configure CORS
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:3000',
      'https://yellow-river-01e099d03.1.azurestaticapps.net',
      process.env.FRONTEND_URL
    ].filter(Boolean);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Origin',
    'Cache-Control',
    'X-File-Name',
    'X-CSRF-Token'
  ],
  exposedHeaders: ['Set-Cookie'],
  optionsSuccessStatus: 200,
  preflightContinue: false
};

app.use(cors(corsOptions));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: mongoUri,
        touchAfter: 24 * 3600 // lazy session update
    }),
    cookie: {
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        secure: process.env.NODE_ENV === 'production',
        httpOnly: false, // Allow JavaScript access for debugging
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        domain: process.env.NODE_ENV === 'production' ? undefined : undefined // Let browser handle domain
    },
    name: 'fin-copilot-session' // Custom session name
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
    console.log('🔐 Serializing user:', user._id);
    done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
    try {
        console.log('🔍 Deserializing user ID:', id);
        
        if (!id) {
            console.log('❌ No user ID provided to deserializeUser');
            return done(null, false);
        }
        
        const user = await User.findById(id);
        
        if (!user) {
            console.log('❌ User not found in database for ID:', id);
            return done(null, false);
        }
        
        console.log('✅ User deserialized successfully:', user.email);
        done(null, user);
    } catch (error) {
        console.error('❌ Error in deserializeUser:', error);
        done(error, null);
    }
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.NODE_ENV === 'production'
        ? `https://tlv500-backendserver-dqfed5d9dcfkd3ce.westeurope-01.azurewebsites.net/auth/google/callback`
        : "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        console.log('🔐 Google OAuth callback - Profile:', {
            id: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value
        });

        // Check if user already exists
        let user = await User.findOne({ googleId: profile.id });
        
        if (user) {
            // Update existing user
            user.accessToken = accessToken;
            user.refreshToken = refreshToken;
            user.lastLogin = new Date();
            user.name = profile.displayName; // Update name in case it changed
            user.email = profile.emails[0].value; // Update email
            if (profile.photos && profile.photos.length > 0) {
                user.profilePicture = profile.photos[0].value;
            }
            await user.save();
            console.log('👤 Updated existing user:', user.email);
        } else {
            // Create new user
            user = new User({
                googleId: profile.id,
                email: profile.emails[0].value,
                name: profile.displayName,
                profilePicture: profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null,
                accessToken: accessToken,
                refreshToken: refreshToken
            });
            await user.save();
            console.log('🆕 Created new user:', user.email);
        }
        
        return done(null, user);
    } catch (error) {
        console.error('❌ Error in Google OAuth strategy:', error);
        return done(error, null);
    }
}));

// Azure App Service Authentication middleware
app.use((req, res, next) => {
    // Check for Azure App Service auth headers
    const azureUser = req.headers['x-ms-client-principal'];
    const azureToken = req.headers['x-ms-token-google-access-token'];
    
    if (azureUser && azureToken && !req.isAuthenticated()) {
        try {
            const userInfo = JSON.parse(Buffer.from(azureUser, 'base64').toString());
            console.log('🔵 Azure App Service user detected:', userInfo.userDetails);
            
            // You could create a session here or handle Azure auth
            // For now, we'll log it and continue with custom auth
            req.azureAuth = {
                user: userInfo,
                token: azureToken
            };
        } catch (error) {
            console.error('Error parsing Azure auth:', error);
        }
    }
    
    next();
});

// Add debugging middleware for authentication
app.use((req, res, next) => {
    if (req.path.startsWith('/api/')) {
        console.log(`🔍 API Request: ${req.method} ${req.path}`);
        console.log(`🔐 Authenticated: ${req.isAuthenticated()}`);
        console.log(`🍪 Session ID: ${req.sessionID}`);
        console.log(`👤 User: ${req.user ? req.user.email : 'None'}`);
        console.log(`🔵 Azure Auth: ${req.azureAuth ? 'Present' : 'None'}`);
        
        if (req.headers.cookie) {
            console.log(`🍪 Cookies: ${req.headers.cookie.substring(0, 100)}...`);
        }
    }
    next();
});

app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        const frontendUrl = process.env.NODE_ENV === 'production'
            ? process.env.FRONTEND_URL
            : 'http://localhost:3000';
        res.redirect(frontendUrl);
    } else {
        const html = `<!DOCTYPE html>
<html dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>התחברות - Fin-Copilot</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', 'Segoe UI', sans-serif;
            background: #000000;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            direction: rtl;
            overflow: hidden;
        }
        .background-animation {
            position: absolute;
            top: 0; left: 0; width: 100%; height: 100%;
            background: radial-gradient(circle at 20% 80%, #8B5CF6 0%, transparent 50%),
                        radial-gradient(circle at 80% 20%, #6366F1 0%, transparent 50%),
                        radial-gradient(circle at 40% 40%, #7C3AED 0%, transparent 50%);
            animation: pulse 4s ease-in-out infinite alternate;
        }
        @keyframes pulse { 0% { opacity: 0.3; } 100% { opacity: 0.6; } }
        .container {
            position: relative;
            background: rgba(10, 10, 10, 0.95);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(139, 92, 246, 0.2);
            padding: 3rem;
            border-radius: 24px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(139, 92, 246, 0.1);
            text-align: center;
            max-width: 420px;
            width: 90%;
            z-index: 1;
        }
        .logo {
            font-size: 2.8rem;
            font-weight: 700;
            background: linear-gradient(135deg, #8B5CF6 0%, #6366F1 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
            letter-spacing: -0.02em;
        }
        .subtitle {
            color: #A78BFA;
            margin-bottom: 3rem;
            font-size: 1.1rem;
            font-weight: 400;
            opacity: 0.9;
        }
        .google-btn {
            position: relative;
            background: linear-gradient(135deg, #8B5CF6 0%, #6366F1 100%);
            color: white;
            border: none;
            padding: 1.2rem 2rem;
            border-radius: 16px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            width: 100%;
            text-decoration: none;
            font-family: 'Inter', sans-serif;
            box-shadow: 0 4px 15px rgba(139, 92, 246, 0.3);
            overflow: hidden;
        }
        .google-btn::before {
            content: '';
            position: absolute;
            top: 0; left: -100%; width: 100%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }
        .google-btn:hover::before { left: 100%; }
        .google-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(139, 92, 246, 0.4);
        }
        .google-btn:active { transform: translateY(0); }
        .google-icon {
            width: 24px; height: 24px;
            background: white;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            color: #4285f4;
            font-size: 14px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .features {
            margin-top: 2.5rem;
            text-align: right;
        }
        .feature {
            margin: 0.75rem 0;
            color: #818CF8;
            font-size: 0.95rem;
            font-weight: 400;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            opacity: 0.9;
        }
        .feature::before {
            content: "✓";
            color: #8B5CF6;
            font-weight: 600;
            margin-left: 0.75rem;
            font-size: 1.1rem;
        }
        .loading {
            display: none;
            margin-top: 1.5rem;
            color: #A78BFA;
        }
        .spinner {
            border: 2px solid rgba(139, 92, 246, 0.2);
            border-top: 2px solid #8B5CF6;
            border-radius: 50%;
            width: 24px; height: 24px;
            animation: spin 1s linear infinite;
            margin: 0 auto 0.5rem;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .powered-by {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid rgba(139, 92, 246, 0.1);
            color: #6B7280;
            font-size: 0.85rem;
            font-weight: 400;
        }
        @media (max-width: 480px) {
            .container { padding: 2rem; margin: 1rem; }
            .logo { font-size: 2.2rem; }
            .subtitle { font-size: 1rem; }
        }
    </style>
</head>
<body>
    <div class="background-animation"></div>
    <div class="container">
        <div class="logo">Fin-Copilot</div>
        <div class="subtitle">עוזר AI פיננסי מתקדם</div>
        
        <a href="/auth/google" class="google-btn" onclick="showLoading()">
            <div class="google-icon">G</div>
            התחבר עם Google
        </a>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p>מתחבר לחשבון Google...</p>
        </div>
        
        <div class="features">
            <div class="feature">גישה מאובטחת לגליונות שלך</div>
            <div class="feature">עריכה בזמן אמת עם AI</div>
            <div class="feature">ניתוח נתונים מתקדם</div>
            <div class="feature">ממשק משתמש מודרני</div>
        </div>
        
        <div class="powered-by">
            מופעל על ידי Google OAuth 2.0
        </div>
    </div>
    
    <script>
        function showLoading() {
            document.querySelector('.google-btn').style.display = 'none';
            document.getElementById('loading').style.display = 'block';
        }
        
        document.addEventListener('mousemove', (e) => {
            const container = document.querySelector('.container');
            const x = (e.clientX / window.innerWidth) * 100;
            const y = (e.clientY / window.innerHeight) * 100;
            container.style.transform = 'translate(' + (x * 0.02) + 'px, ' + (y * 0.02) + 'px)';
        });
    </script>
</body>
</html>`;
        res.send(html);
    }
});

app.get('/auth/google', passport.authenticate('google', {
    scope: ['profile', 'email', 'https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive']
}));

app.get('/auth/google/callback',
    passport.authenticate('google', {
        failureRedirect: `${process.env.FRONTEND_URL}?error=auth_failed`
    }),
    (req, res) => {
        console.log('🔐 Google OAuth callback successful');
        console.log('👤 User authenticated:', req.user.email);
        
        // Passport automatically saves the user to req.session.passport.user
        // Let's also manually ensure session is properly saved
        req.session.save((err) => {
            if (err) {
                console.error('❌ Session save error:', err);
                res.redirect(`${process.env.FRONTEND_URL}?error=session_error`);
            } else {
                console.log('✅ Session saved successfully');
                console.log('🍪 Session ID:', req.sessionID);
                console.log('👤 Session passport user:', req.session.passport?.user || 'none');
                
                // Redirect to frontend with success indicator
                res.redirect(`${process.env.FRONTEND_URL}?auth=success`);
            }
        });
    }
);

// Logout endpoint
app.get('/auth/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ error: 'Failed to logout' });
        }
        req.session.destroy((err) => {
            if (err) {
                console.error('Session destroy error:', err);
                return res.status(500).json({ error: 'Failed to destroy session' });
            }
            res.clearCookie('connect.sid'); // Clear the session cookie
            res.json({ message: 'Logged out successfully' });
        });
    });
});

app.get('/api/user', (req, res) => {
    console.log('🔍 /api/user endpoint called');
    console.log('🔐 req.isAuthenticated():', req.isAuthenticated());
    console.log('🍪 Session ID:', req.sessionID);
    console.log('👤 User object:', req.user ? 'Present' : 'None');
    console.log('🔵 Azure auth:', req.azureAuth ? 'Present' : 'None');
    console.log('📋 Session passport data:', req.session?.passport || 'None');
    console.log('🔑 Session passport user:', req.session?.passport?.user || 'None');
    
    if (req.isAuthenticated()) {
        res.json({
            user: {
                id: req.user._id,
                googleId: req.user.googleId,
                name: req.user.name,
                email: req.user.email,
                profilePicture: req.user.profilePicture,
                preferences: req.user.preferences,
                lastLogin: req.user.lastLogin
            },
            accessToken: req.user.accessToken,
            sessionId: req.sessionID,
            authMethod: 'passport'
        });
    } else if (req.azureAuth) {
        // Fallback to Azure auth if available
        console.log('🔵 Using Azure authentication fallback');
        res.json({
            user: {
                name: req.azureAuth.user.userDetails,
                email: req.azureAuth.user.userDetails,
                profilePicture: null
            },
            accessToken: req.azureAuth.token,
            authMethod: 'azure',
            note: 'Using Azure App Service authentication'
        });
    } else {
        console.log('❌ User not authenticated - returning null user instead of 401');
        // Return null user instead of 401 error to prevent frontend crashes
        res.json({
            user: null,
            authenticated: false,
            sessionId: req.sessionID,
            debug: {
                cookieHeader: req.headers.cookie ? 'Present' : 'Missing',
                sessionExists: !!req.session,
                sessionUser: req.session ? !!req.session.passport : false,
                passportData: req.session?.passport || null,
                passportUser: req.session?.passport?.user || null
            }
        });
    }
});

/**
 * Act I: The Backend Heist
 * This endpoint extracts numerical data and tables from a PDF and returns it as clean JSON.
 */
app.post('/api/extract-pdf-data', upload.single('pdf'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }

    // Check file size (max 20MB for Gemini API)
    const maxSize = 20 * 1024 * 1024; // 20MB
    if (req.file.size > maxSize) {
        return res.status(400).json({ 
            error: `File too large. Maximum size is ${maxSize / (1024 * 1024)}MB, but received ${(req.file.size / (1024 * 1024)).toFixed(2)}MB.` 
        });
    }

    console.log(`[${new Date().toISOString()}] Starting data extraction for: ${req.file.originalname}`);

    // 🔥 קבל קונטקסט הגליון מה-FormData
    const sheetInstructions = req.body.sheetInstructions;
    const sheetAnalysis = req.body.sheetAnalysis; 
    const sheetName = req.body.sheetName;
    const sheetData = req.body.sheetData ? JSON.parse(req.body.sheetData) : null;
    
    console.log('🔥 Sheet context received:', {
        hasInstructions: !!sheetInstructions,
        hasAnalysis: !!sheetAnalysis,
        sheetName: sheetName,
        hasSheetData: !!sheetData,
        sheetDataSize: sheetData ? sheetData.length : 0
    });

    // 🔥 NEW: Parse sheetInstructions to get only the relevant data extraction guidelines
    let extractionGuidelines = '';
    if (sheetInstructions) {
        const match = sheetInstructions.match(/## Data Extraction Guidelines([\s\S]*)/);
        if (match && match[1]) {
            extractionGuidelines = `This is the most important context. Follow these rules precisely:\n${match[1].trim()}`;
        } else {
            // Fallback if the specific header isn't found, use the whole thing as context might still be useful
            extractionGuidelines = sheetInstructions;
        }
    }

    // 🔥 NEW LOGIC: Check if we have sheet context for structured extraction
    const hasSheetContext = !!sheetData && !!sheetName && !!sheetInstructions;
    console.log(`[${new Date().toISOString()}] PDF processing mode: ${hasSheetContext ? 'STRUCTURED_EXTRACTION' : 'SIMPLE_OCR_WITH_CACHE'}`);

    try {
        if (hasSheetContext) {
            // === STRUCTURED EXTRACTION MODE (with sheet context) ===
            console.log(`[${new Date().toISOString()}] Using structured extraction with sheet context`);
            
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

        const pdfPart = {
            inlineData: {
                data: req.file.buffer.toString("base64"),
                mimeType: "application/pdf"
            }
        };

        console.log(`[${new Date().toISOString()}] PDF size: ${req.file.size} bytes`);

        // שלבים: 1) חילוץ נתונים, 2) ניתוח התאמה פנימי
        const extractionPrompt = `
You are an expert financial data analyst. Your task is to extract all relevant financial data from the provided PDF and then provide an internal integration analysis for a specific Google Sheet.

**CONTEXT ON THE TARGET GOOGLE SHEET:**
You are NOT seeing the full sheet data. Instead, you have been provided with a summary and specific instructions generated by a prior analysis of the sheet.

**1. High-Level Sheet Summary:**
${sheetAnalysis || "No summary provided."}

**2. Specific Data Extraction Guidelines for this Sheet:**
${extractionGuidelines || "No specific guidelines provided. Use your best judgment to extract all relevant financial data."}

---

**YOUR DUAL TASK:**
Based ONLY on the context above and the content of the PDF, perform the following two tasks:

1.  **DATA EXTRACTION:** Extract the financial data from the PDF as requested by the guidelines.
2.  **INTEGRATION ANALYSIS (INTERNAL):** Provide a detailed step-by-step analysis of how the data you just extracted should be integrated into the sheet described in the summary.

**EXTRACTION REQUIREMENTS:**
- **Format all tabular data using Markdown tables.** This is critical for maintaining data integrity.
- **Begin your output with a clear note, for example: "Note: All tabular data below is formatted using Markdown tables for structural clarity."** This will inform subsequent AI agents how to parse the data.
- Include table headers and organize data logically.
- Preserve context and relationships between data points.
- Include units, time periods, and any important notes.
- Focus on numerical data while keeping essential context.
- Prioritize data that matches the financial model structure described in the guidelines.

**INTEGRATION ANALYSIS REQUIREMENTS (INTERNAL - NOT FOR CLIENT):**
After extracting the data, provide a detailed step-by-step analysis addressing:
1.  **Data Mapping:** Which PDF data corresponds to which areas of the sheet, as described in the summary?
2.  **Replacement vs. Addition:** Which data replaces existing values vs. adds new information?
3.  **Table Expansion:** Do the guidelines suggest that tables need to be expanded? Where and how?
4.  **Space Management:** Will new data require moving existing elements?
5.  **Potential Conflicts:** Any areas where new data might conflict with the described sheet structure?

**OUTPUT FORMAT:**
Return a JSON object with exactly two fields. For example:
{
  "extractedData": "Note: All tabular data below is formatted using Markdown tables for structural clarity.\\n\\n### **Project Summary**\\n\\n| Project Name | Revenue (M NIS) | Status |\\n| :--- | :--- | :--- |\\n| Project Alpha | 25.5 | In Progress |\\n| Project Beta | 15.0 | Completed |\\n\\nOther non-tabular data can be listed here.",
  "integrationAnalysis": "Detailed internal analysis of how this data integrates with the existing sheet structure, including step-by-step integration plan."
}
        `;

        // Retry mechanism for network failures
        let result;
        let attempts = 0;
        const maxAttempts = 3;
        
        while (attempts < maxAttempts) {
            try {
                attempts++;
                console.log(`[${new Date().toISOString()}] Attempt ${attempts}/${maxAttempts} to process PDF`);
                
                    
                    // Log detailed prompt to file
                    logger.logDetailed('pdf_extraction', 'prompt', extractionPrompt, {
                        model: 'gemini-2.5-flash',
                        purpose: 'Extract structured financial data from PDF',
                        pdf_file: req.file.originalname,
                        pdf_size: req.file.size
                    });                    result = await model.generateContent({
                    contents: [{
                        role: "user",
                        parts: [pdfPart, { text: extractionPrompt }]
                    }]
                });
                break; // Success, exit retry loop
                
            } catch (retryError) {
                console.error(`[${new Date().toISOString()}] Attempt ${attempts} failed:`, retryError.message);
                
                if (attempts === maxAttempts) {
                    throw retryError; // Final attempt failed
                }
                
                // Wait before retry (exponential backoff)
                const waitTime = Math.pow(2, attempts) * 1000; // 2s, 4s, 8s
                console.log(`[${new Date().toISOString()}] Waiting ${waitTime}ms before retry...`);
                await new Promise(resolve => setTimeout(resolve, waitTime));
            }
        }

        const response = await result.response;
        const text = await response.text();
        
        console.log(`[${new Date().toISOString()}] Raw response from Gemini received.`);
        
            // Log detailed response to file
            logger.logDetailed('pdf_extraction', 'response', text, {
                model: 'gemini-2.5-flash',
                pdf_file: req.file.originalname
            });            
        let extractedData, integrationAnalysis;
        
            // Try to parse as JSON
            try {
                // Clean JSON response more carefully
                const cleanedText = text
                    .replace(/```json/g, '')
                    .replace(/```/g, '')
                    .replace(/\n(?!["}])/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim();

                const parsedResponse = JSON.parse(cleanedText);
                extractedData = parsedResponse.extractedData || text.trim();
                integrationAnalysis = parsedResponse.integrationAnalysis || null;
                
                console.log(`[${new Date().toISOString()}] Successfully parsed JSON response with integration analysis`);
                
                // 🔥 Add structured log for the parsed response
                logger.logDetailed('pdf_extraction', 'parsed_response', { extractedData, integrationAnalysis }, {
                    description: "תוצאה מפוענחת מחילוץ PDF: הטקסט שחולץ וניתוח האינטגרציה הפנימי.",
                    model: 'gemini-2.5-flash',
                    pdf_file: req.file.originalname
                });
            } catch (parseError) {
                console.log(`[${new Date().toISOString()}] Failed to parse JSON, using text as-is:`, parseError.message);
            extractedData = text.trim();
            integrationAnalysis = null;
        }
        
            console.log(`[${new Date().toISOString()}] Structured extraction successful for: ${req.file.originalname}`);
            
            // Save PDF file for later viewing
            const fileId = Date.now() + '_' + Math.random().toString(36).substring(2, 15);
            const filePath = path.join(__dirname, 'uploads', `${fileId}.pdf`);
            
            // Ensure uploads directory exists
            if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
                fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
            }
            
            fs.writeFileSync(filePath, req.file.buffer);
            console.log(`[${new Date().toISOString()}] PDF saved with fileId: ${fileId}`);
            
            // Return structured extraction results
        res.json({
            extractedText: extractedData,
            integrationAnalysis: integrationAnalysis,
            fileName: req.file.originalname,
            extractionDate: new Date().toISOString(),
                fileId: fileId,
                processingMode: 'structured',
                isFullText: false
            });
            
        } else {
            // === SIMPLE OCR MODE (no sheet context) - Use Gemini Caching ===
            console.log(`[${new Date().toISOString()}] Using simple OCR mode with Gemini caching`);
            
            // Create a temporary file for upload
            const fileId = Date.now() + '_' + Math.random().toString(36).substring(2, 15);
            const tempFilePath = path.join(__dirname, 'temp', `${fileId}.pdf`);
            
            // Ensure temp directory exists
            if (!fs.existsSync(path.join(__dirname, 'temp'))) {
                fs.mkdirSync(path.join(__dirname, 'temp'), { recursive: true });
            }
            
            fs.writeFileSync(tempFilePath, req.file.buffer);
            
            try {
                // Upload PDF to Gemini's file service using NEW SDK
                console.log(`[${new Date().toISOString()}] Uploading PDF to Gemini file service...`);
                
                const uploadedDoc = await genAINew.files.upload({
                    file: tempFilePath,
                    config: { mimeType: "application/pdf" }
                });
                
                console.log(`[${new Date().toISOString()}] PDF uploaded to Gemini: ${uploadedDoc.name}`);
                
                // Create cache with the uploaded PDF using NEW SDK
                const modelName = "gemini-2.5-flash";
                const cache = await genAINew.caches.create({
                    model: modelName,
                    config: {
                        contents: [
                            {
                                role: "user",
                                parts: [{ fileData: { mimeType: "application/pdf", fileUri: uploadedDoc.uri } }]
                            }
                        ],
                        systemInstruction: "You are a helpful assistant that can analyze and discuss the content of the provided PDF document. Answer questions about the document content clearly and accurately. The document is available for reference and analysis.",
                        ttl: "300s" // 5 minutes as requested
                    }
                });
                
                console.log(`[${new Date().toISOString()}] Cache created: ${cache.name}`);
                
                // Clean up temp file
                fs.unlinkSync(tempFilePath);
                
                // Save PDF for later viewing (optional)
                const savedFilePath = path.join(__dirname, 'uploads', `${fileId}.pdf`);
                if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
                    fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
                }
                fs.writeFileSync(savedFilePath, req.file.buffer);
                
                // Return cache information
                res.json({
                    extractedText: `PDF uploaded for conversation. You can now ask questions about: ${req.file.originalname}`,
                    integrationAnalysis: null,
                    fileName: req.file.originalname,
                    extractionDate: new Date().toISOString(),
                    fileId: fileId,
                    cacheId: cache.name,
                    processingMode: 'simple_ocr',
                    isFullText: true
                });
                
            } catch (uploadError) {
                console.error(`[${new Date().toISOString()}] Error uploading to Gemini:`, uploadError);
                
                // Clean up temp file if it exists
                if (fs.existsSync(tempFilePath)) {
                    fs.unlinkSync(tempFilePath);
                }
                
                // Return error without fallback
                res.status(500).json({ 
                    error: `Failed to upload PDF to Gemini cache service: ${uploadError.message}` 
                });
            }
        }
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Error during data extraction:`, error);
        res.status(500).json({ error: `An error occurred during PDF processing: ${error.message}` });
    }
});

// Helper function to generate unique session ID
function generateSessionId() {
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

// A new helper function to format the history for the prompt
function formatConversationHistory(history) {
    if (!history || history.length === 0) return "No previous conversation history.";
    // We take the last 10 messages to keep the prompt from getting too long
    return history.slice(-10).map(msg => `${msg.role === 'user' ? 'User' : 'Assistant'}: ${msg.parts[0].text}`).join('\n');
}

// ===== CHAT HISTORY ENDPOINTS =====

// Debug endpoint to check database content
app.get('/api/debug/database', async (req, res) => {
    try {
        console.log('🔍 Debug endpoint called - checking database...');
        
        const users = await User.find({}).select('email name createdAt');
        console.log('👥 Found users:', users.length);
        
        const chats = await ChatHistory.find({}).select('userId sessionId title totalMessages createdAt messages');
        console.log('💬 Found chats:', chats.length);
        
        // Log detailed chat info
        chats.forEach(chat => {
            console.log(`📝 Chat ${chat.sessionId}: ${chat.totalMessages} messages, title: ${chat.title}`);
        });
        
        res.json({
            totalUsers: users.length,
            users: users,
            totalChats: chats.length,
            chats: chats.map(chat => ({
                ...chat.toObject(),
                messageDetails: chat.messages.map(msg => ({
                    role: msg.role,
                    contentPreview: msg.content.substring(0, 50) + '...',
                    timestamp: msg.timestamp
                }))
            }))
        });
    } catch (error) {
        console.error('❌ Database debug error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Test endpoint to create a simple chat
app.post('/api/debug/test-save', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    try {
        console.log('🧪 Test save endpoint called');
        
        const testSessionId = 'test_' + Date.now();
        console.log('📝 Creating test session:', testSessionId);
        
        const testChat = await ChatHistory.createNewSession(req.user._id, testSessionId, 'Test Chat');
        console.log('✅ Test session created:', testChat._id);
        
        await testChat.addMessage('user', 'This is a test message', {});
        console.log('✅ Test message added');
        
        await testChat.addMessage('assistant', 'This is a test response', {});
        console.log('✅ Test response added');
        
        // Verify it was saved
        const saved = await ChatHistory.findById(testChat._id);
        console.log('🔍 Verification - saved chat has', saved.messages.length, 'messages');
        
        res.json({
            success: true,
            sessionId: testSessionId,
            messageCount: saved.messages.length,
            chat: saved
        });
        
    } catch (error) {
        console.error('❌ Test save error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get all chat sessions for a user
app.get('/api/chat/sessions', async (req, res) => {
    console.log('🔍 /api/chat/sessions endpoint called');
    console.log('🔐 Authentication status:', req.isAuthenticated());
    
    if (!req.isAuthenticated()) {
        console.log('❌ User not authenticated - returning empty sessions array');
        return res.json([]); // Return empty array instead of 401 error
    }
    
    try {
        console.log('✅ User authenticated - fetching sessions for user:', req.user.email);
        const sessions = await ChatHistory.findUserSessions(req.user._id);
        console.log('📊 Found sessions:', sessions.length);
        res.json(sessions);
    } catch (error) {
        console.error('❌ Error fetching chat sessions:', error);
        res.status(500).json({ error: 'Failed to fetch chat sessions' });
    }
});

// Get messages for a specific session
app.get('/api/chat/session/:sessionId', async (req, res) => {
    console.log('🔍 /api/chat/session/:sessionId endpoint called');
    console.log('🔐 Authentication status:', req.isAuthenticated());
    
    if (!req.isAuthenticated()) {
        console.log('❌ User not authenticated - returning empty session');
        return res.status(404).json({ error: 'Session not found' }); // Return 404 instead of 401
    }
    
    try {
        const { sessionId } = req.params;
        const chatHistory = await ChatHistory.findOne({
            userId: req.user._id,
            sessionId: sessionId
        });
        
        if (!chatHistory) {
            return res.status(404).json({ error: 'Chat session not found' });
        }
        
        res.json(chatHistory);
    } catch (error) {
        console.error('Error fetching chat session:', error);
        res.status(500).json({ error: 'Failed to fetch chat session' });
    }
});

// Create a new chat session
app.post('/api/chat/session/new', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    try {
        const { title } = req.body;
        const sessionId = generateSessionId();
        
        const newSession = await ChatHistory.createNewSession(
            req.user._id,
            sessionId,
            title || 'New Conversation'
        );
        
        res.json({
            sessionId: newSession.sessionId,
            title: newSession.title,
            createdAt: newSession.createdAt
        });
    } catch (error) {
        console.error('Error creating new chat session:', error);
        res.status(500).json({ error: 'Failed to create new chat session' });
    }
});

// Save a message to a chat session
app.post('/api/chat/message', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    try {
        const { sessionId, role, content, metadata = {} } = req.body;
        
        if (!sessionId || !role || !content) {
            return res.status(400).json({ error: 'sessionId, role, and content are required' });
        }
        
        let chatHistory = await ChatHistory.findOne({
            userId: req.user._id,
            sessionId: sessionId
        });
        
        if (!chatHistory) {
            // Create new session if it doesn't exist
            chatHistory = await ChatHistory.createNewSession(req.user._id, sessionId);
        }
        
        await chatHistory.addMessage(role, content, metadata);
        
        res.json({
            success: true,
            messageCount: chatHistory.messageCount,
            title: chatHistory.title
        });
    } catch (error) {
        console.error('Error saving message:', error);
        res.status(500).json({ error: 'Failed to save message' });
    }
});

// Delete a chat session (permanently)
app.delete('/api/chat/session/:sessionId', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    try {
        const { sessionId } = req.params;
        
        console.log(`Deleting chat session: ${sessionId} for user: ${req.user.email}`);
        
        const result = await ChatHistory.findOneAndDelete({
            userId: req.user._id,
            sessionId: sessionId
        });
        
        if (!result) {
            console.log(`Chat session not found: ${sessionId}`);
            return res.status(404).json({ error: 'Chat session not found' });
        }
        
        console.log(`✅ Chat session deleted successfully: ${sessionId}`);
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error deleting chat session:', error);
        res.status(500).json({ error: 'Failed to delete chat session' });
    }
});

// Update chat session title
app.put('/api/chat/session/:sessionId/title', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    try {
        const { sessionId } = req.params;
        const { title } = req.body;
        
        if (!title) {
            return res.status(400).json({ error: 'Title is required' });
        }
        
        const chatHistory = await ChatHistory.findOneAndUpdate(
            { userId: req.user._id, sessionId: sessionId },
            { title: title },
            { new: true }
        );
        
        if (!chatHistory) {
            return res.status(404).json({ error: 'Chat session not found' });
        }
        
        res.json({ success: true, title: chatHistory.title });
    } catch (error) {
        console.error('Error updating chat session title:', error);
        res.status(500).json({ error: 'Failed to update chat session title' });
    }
});

// 🔄 Undo Action
app.post('/api/action/undo', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const { sessionId } = req.body;
        
        // מצא את הפעולה האחרונה שבוצעה
        const lastAction = await ActionHistory.findLastExecuted(sessionId);
        
        if (!lastAction) {
            return res.status(404).json({ 
                error: 'אין פעולות לביטול',
                canUndo: false 
            });
        }

        console.log(`↩️ Undoing action for session ${sessionId}`);

        // שחזר את המצב המקורי
        const oauth2Client = new google.auth.OAuth2();
        oauth2Client.setCredentials({ access_token: req.user.accessToken });
        const sheets = google.sheets({ version: 'v4', auth: oauth2Client });

        const revertRequests = [];
        let message = '';
        
        // Build revert requests based on action type
        switch (lastAction.actionType || 'AI_ACTION') {
            case 'AI_ACTION':
                // Standard AI action undo - restore original values and formatting
                lastAction.changedCells.forEach(cellAddress => {
                    const original = lastAction.snapshotBefore[cellAddress];
                    
                    // שחזר ערך מקורי
                    let valuePayload;
                    if (original.value === "") {
                        valuePayload = null;
                    } else if (typeof original.value === 'number') {
                        valuePayload = { numberValue: original.value };
                    } else if (typeof original.value === 'string' && original.value.startsWith('=')) {
                        valuePayload = { formulaValue: original.value };
                    } else {
                        valuePayload = { stringValue: cleanValueConversion(original.value) };
                    }
                    
                    revertRequests.push({
                        updateCells: {
                            range: cellToRange(cellAddress, lastAction.sheetId),
                            rows: [{ values: [{ userEnteredValue: valuePayload }] }],
                            fields: "userEnteredValue"
                        }
                    });
                    
                    // שחזר עיצוב מקורי
                    revertRequests.push({
                        repeatCell: {
                            range: cellToRange(cellAddress, lastAction.sheetId),
                            cell: { userEnteredFormat: { backgroundColor: original.backgroundColor } },
                            fields: "userEnteredFormat.backgroundColor"
                        }
                    });
                });
                message = `הפעולה בוטלה בהצלחה - ${lastAction.changedCells.length} תאים הוחזרו למצבם המקורי`;
                break;

            case 'APPROVE_ALL':
                // Undo approval - restore green highlighting and reactivate original AI action
                lastAction.changedCells.forEach(cellAddress => {
                    const original = lastAction.snapshotBefore[cellAddress];
                    
                    // החזר הדגשה ירוקה (מה-snapshot לפני האישור)
                    revertRequests.push({
                        repeatCell: {
                            range: cellToRange(cellAddress, lastAction.sheetId),
                            cell: { userEnteredFormat: { backgroundColor: original.backgroundColor || { red: 0.85, green: 0.95, blue: 0.85 } } },
                            fields: "userEnteredFormat.backgroundColor"
                        }
                    });
                });

                // חשוב: החזר את פעולת ה-AI המקורית לסטטוס EXECUTED כדי שניתן יהיה לעשות עליה Undo
                const originalAIAction = await ActionHistory.findOne({
                    sessionId: sessionId,
                    actionType: 'AI_ACTION',
                    status: 'EXECUTED',
                    changedCells: { $in: lastAction.changedCells }
                }).sort({ createdAt: -1 });
                
                if (originalAIAction) {
                    console.log(`🔄 Restoring AI action ${originalAIAction._id} to EXECUTED status`);
                    // פעולת ה-AI המקורית חוזרת להיות ניתנת ל-Undo
                }

                message = `האישור בוטל - ${lastAction.changedCells.length} תאים הוחזרו להדגשה ירוקה`;
                break;

            case 'REJECT_ALL':
                // Undo rejection - restore the values and green state from before rejection
                lastAction.changedCells.forEach(cellAddress => {
                    const original = lastAction.snapshotBefore[cellAddress];
                    
                    // שחזר ערך שהיה לפני הדחייה
                    let valuePayload;
                    if (original.value === "") {
                        valuePayload = null;
                    } else if (typeof original.value === 'number') {
                        valuePayload = { numberValue: original.value };
                    } else if (typeof original.value === 'string' && original.value.startsWith('=')) {
                        valuePayload = { formulaValue: original.value };
                    } else {
                        valuePayload = { stringValue: cleanValueConversion(original.value) };
                    }
                    
                    revertRequests.push({
                        updateCells: {
                            range: cellToRange(cellAddress, lastAction.sheetId),
                            rows: [{ values: [{ userEnteredValue: valuePayload }] }],
                            fields: "userEnteredValue"
                        }
                    });
                    
                    // שחזר עיצוב שהיה לפני הדחייה (בדרך כלל ירוק)
                    revertRequests.push({
                        repeatCell: {
                            range: cellToRange(cellAddress, lastAction.sheetId),
                            cell: { userEnteredFormat: { backgroundColor: original.backgroundColor || { red: 0.85, green: 0.95, blue: 0.85 } } },
                            fields: "userEnteredFormat.backgroundColor"
                        }
                    });
                });

                // חשוב: החזר את פעולת ה-AI המקורית לסטטוס EXECUTED כדי שניתן יהיה לעשות עליה Undo
                const originalAIActionReject = await ActionHistory.findOne({
                    sessionId: sessionId,
                    actionType: 'AI_ACTION',
                    status: 'EXECUTED',
                    changedCells: { $in: lastAction.changedCells }
                }).sort({ createdAt: -1 });
                
                if (originalAIActionReject) {
                    console.log(`🔄 Restoring AI action ${originalAIActionReject._id} to EXECUTED status after reject undo`);
                    // פעולת ה-AI המקורית חוזרת להיות ניתנת ל-Undo
                }

                message = `הדחייה בוטלה - ${lastAction.changedCells.length} תאים הוחזרו למצבם לפני הדחייה`;
                break;

            default:
                lastAction.changedCells.forEach(cellAddress => {
                    const original = lastAction.snapshotBefore[cellAddress];
                    
                    let valuePayload;
                    if (original.value === "") {
                        valuePayload = null;
                    } else if (typeof original.value === 'number') {
                        valuePayload = { numberValue: original.value };
                    } else if (typeof original.value === 'string' && original.value.startsWith('=')) {
                        valuePayload = { formulaValue: original.value };
                    } else {
                        valuePayload = { stringValue: cleanValueConversion(original.value) };
                    }
                    
                    revertRequests.push({
                        updateCells: {
                            range: cellToRange(cellAddress, lastAction.sheetId),
                            rows: [{ values: [{ userEnteredValue: valuePayload }] }],
                            fields: "userEnteredValue"
                        }
                    });
                    
                    revertRequests.push({
                        repeatCell: {
                            range: cellToRange(cellAddress, lastAction.sheetId),
                            cell: { userEnteredFormat: { backgroundColor: original.backgroundColor } },
                            fields: "userEnteredFormat.backgroundColor"
                        }
                    });
                });
                message = `הפעולה בוטלה בהצלחה - ${lastAction.changedCells.length} תאים הוחזרו`;
        }

        await sheets.spreadsheets.batchUpdate({
            spreadsheetId: lastAction.spreadsheetId,
            resource: { requests: revertRequests }
        });

        // עדכן סטטוס לUNDONE
        lastAction.status = 'UNDONE';
        await lastAction.save();

        console.log(`↩️ Action undone successfully for session ${sessionId}`);

        const status = await ActionHistory.getStatus(sessionId);
        res.json({ 
            success: true, 
            message: message,
            actionType: lastAction.actionType,
            ...status
        });

    } catch (error) {
        console.error('Error in undo action:', error);
        res.status(500).json({ error: 'שגיאה בביטול הפעולה' });
    }
});

// ⤴️ Redo Action  
app.post('/api/action/redo', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const { sessionId } = req.body;
        
        // מצא את הפעולה האחרונה שבוטלה
        const lastUndone = await ActionHistory.findLastUndone(sessionId);
        
        if (!lastUndone) {
            return res.status(404).json({ 
                error: 'אין פעולות לשחזור',
                canRedo: false 
            });
        }

        console.log(`⤴️ Redoing action for session ${sessionId}`);

        // בצע שוב את השינוי המקורי
        const oauth2Client = new google.auth.OAuth2();
        oauth2Client.setCredentials({ access_token: req.user.accessToken });
        const sheets = google.sheets({ version: 'v4', auth: oauth2Client });

        const redoRequests = [];
        
        lastUndone.changeRequest.forEach(action => {
            const range = cellToRange(action.cell, lastUndone.sheetId);

            switch (action.type) {
                case 'UPDATE':
                    // Determine the correct value type for redo
                    let userEnteredValue;
                    if (typeof action.value === 'number') {
                        userEnteredValue = { numberValue: action.value };
                    } else if (typeof action.value === 'string' && action.value.startsWith('=')) {
                        userEnteredValue = { formulaValue: action.value };
                    } else {
                        userEnteredValue = { stringValue: cleanValueConversion(action.value) };
                    }
                    
                    redoRequests.push({
                        updateCells: {
                            rows: [{ values: [{ userEnteredValue: userEnteredValue }] }],
                            range: range,
                            fields: "userEnteredValue"
                        }
                    });
                    break;

                case 'CLEAR':
                    redoRequests.push({
                        updateCells: {
                            range: range,
                            fields: "*"
                        }
                    });
                    break;
            }
        });

        await sheets.spreadsheets.batchUpdate({
            spreadsheetId: lastUndone.spreadsheetId,
            resource: { requests: redoRequests }
        });

        // עדכן סטטוס בחזרה לEXECUTED
        lastUndone.status = 'EXECUTED';
        await lastUndone.save();

        console.log(`⤴️ Action redone successfully for session ${sessionId}`);

        const status = await ActionHistory.getStatus(sessionId);
        res.json({ 
            success: true, 
            message: `הפעולה שוחזרה בהצלחה - ${lastUndone.changedCells.length} תאים שונו`,
            ...status
        });

    } catch (error) {
        console.error('Error in redo action:', error);
        res.status(500).json({ error: 'שגיאה בשחזור הפעולה' });
    }
});

// 📊 Get Undo/Redo Status
app.get('/api/action/status/:sessionId', async (req, res) => {
    console.log('🔍 /api/action/status/:sessionId endpoint called');
    console.log('🔐 Authentication status:', req.isAuthenticated());
    
    if (!req.isAuthenticated()) {
        console.log('❌ User not authenticated - returning default status');
        return res.json({
            canUndo: false,
            canRedo: false,
            changesCount: 0,
            message: 'Not authenticated'
        });
    }

    try {
        const { sessionId } = req.params;
        const status = await ActionHistory.getStatus(sessionId);
        
        // חישוב changesCount מדויק יותר - רק עבור AI_ACTION שיש בו תאים ירוקים
        let changesCount = 0;
        if (status.canUndo) {
            // מצא את הפעולה האחרונה מסוג AI_ACTION (שיש בה תאים ירוקים)
            const lastAIAction = await ActionHistory.findOne({
                sessionId,
                actionType: 'AI_ACTION',
                status: 'EXECUTED'
            }).sort({ createdAt: -1 });
            
            console.log('🔍 Last AI action found:', lastAIAction ? 'YES' : 'NO');
            if (lastAIAction) {
                console.log('🔍 AI action type:', lastAIAction.actionType);
                console.log('📊 Changed cells in AI action:', lastAIAction.changedCells);
                changesCount = lastAIAction.changedCells ? lastAIAction.changedCells.length : 0;
            } else {
                // אין AI_ACTION - אולי יש רק APPROVE_ALL או REJECT_ALL
                const recentAction = await ActionHistory.findOne({
                    sessionId,
                    status: 'EXECUTED'
                }).sort({ createdAt: -1 });
                
                console.log('🔍 Other recent action:', recentAction ? recentAction.actionType : 'NONE');
                changesCount = 0; // אין תאים ירוקים אם אין AI_ACTION
            }
        }
        
        console.log('📈 Final changesCount:', changesCount, 'canUndo:', status.canUndo);
        
        res.json({
            ...status,
            changesCount
        });
    } catch (error) {
        console.error('Error getting action status:', error);
        res.status(500).json({ error: 'Failed to get action status' });
    }
});

// 🟢 Helper function to find green cells
async function findGreenCells(spreadsheetId, selectedSheetName, sheetId, sheets) {
    try {
        // Get detailed sheet data with formatting
        const response = await sheets.spreadsheets.get({
            spreadsheetId: spreadsheetId,
            ranges: [`${selectedSheetName}`],
            includeGridData: true
        });

        const greenCells = [];
        const GREEN_COLOR = { red: 0.85, green: 0.95, blue: 0.85 };
        
        if (response.data.sheets && response.data.sheets[0] && response.data.sheets[0].data) {
            const sheetData = response.data.sheets[0].data[0];
            if (sheetData.rowData) {
                sheetData.rowData.forEach((row, rowIndex) => {
                    if (row.values) {
                        row.values.forEach((cell, colIndex) => {
                            if (cell.effectiveFormat && cell.effectiveFormat.backgroundColor) {
                                const bg = cell.effectiveFormat.backgroundColor;
                                // Check if cell has green background (AI highlight)
                                if (bg.red === GREEN_COLOR.red && bg.green === GREEN_COLOR.green && bg.blue === GREEN_COLOR.blue) {
                                    const cellAddress = String.fromCharCode(65 + colIndex) + (rowIndex + 1);
                                    greenCells.push(cellAddress);
                                }
                            }
                        });
                    }
                });
            }
        }
        
        return greenCells;
    } catch (error) {
        console.error('Error finding green cells:', error);
        return [];
    }
}

// ✅ Approve All Changes
app.post('/api/action/approve-all', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const { spreadsheetId, selectedSheetName, sheetId, sessionId } = req.body;
        
        if (!spreadsheetId || !selectedSheetName || !sessionId) {
            return res.status(400).json({ error: 'Missing required parameters' });
        }

        const oauth2Client = new google.auth.OAuth2();
        oauth2Client.setCredentials({ access_token: req.user.accessToken });
        const sheets = google.sheets({ version: 'v4', auth: oauth2Client });
        
        // Find all green cells
        const greenCells = await findGreenCells(spreadsheetId, selectedSheetName, sheetId, sheets);
        
        if (greenCells.length === 0) {
            return res.json({ message: 'לא נמצאו שינויים לאישור', greenCells: [] });
        }

        // Take snapshot before change (with green colors)
        const snapshotBefore = await takeSnapshot(greenCells, sheets, spreadsheetId, selectedSheetName, sheetId);

        // Remove green background from all cells (approve changes)
        const approveRequests = greenCells.map(cellAddress => {
            const range = cellToRange(cellAddress, sheetId);
            return {
                repeatCell: {
                    range: range,
                    cell: {
                        userEnteredFormat: {
                            backgroundColor: null // Remove green, revert to original
                        }
                    },
                    fields: "userEnteredFormat.backgroundColor"
                }
            };
        });

        // Execute the approval
        await sheets.spreadsheets.batchUpdate({
            spreadsheetId: spreadsheetId,
            resource: { requests: approveRequests }
        });

        // Save action to history
        const actionHistory = new ActionHistory({
            userId: req.user._id,
            sessionId: sessionId,
            actionType: 'APPROVE_ALL',
            snapshotBefore: snapshotBefore,
            changeRequest: approveRequests,
            status: 'EXECUTED',
            spreadsheetId: spreadsheetId,
            sheetId: sheetId,
            selectedSheetName: selectedSheetName,
            changedCells: greenCells
        });

        await actionHistory.save();

        console.log(`✅ Approved ${greenCells.length} changes for session ${sessionId}`);
        res.json({ 
            message: `✅ אושרו ${greenCells.length} שינויים`, 
            greenCells: greenCells,
            actionId: actionHistory._id
        });

    } catch (error) {
        console.error('Error in approve all:', error);
        res.status(500).json({ error: 'שגיאה באישור השינויים' });
    }
});

// ❌ Reject All Changes  
app.post('/api/action/reject-all', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const { spreadsheetId, selectedSheetName, sheetId, sessionId } = req.body;
        
        if (!spreadsheetId || !selectedSheetName || !sessionId) {
            return res.status(400).json({ error: 'Missing required parameters' });
        }

        const oauth2Client = new google.auth.OAuth2();
        oauth2Client.setCredentials({ access_token: req.user.accessToken });
        const sheets = google.sheets({ version: 'v4', auth: oauth2Client });
        
        // Find all green cells
        const greenCells = await findGreenCells(spreadsheetId, selectedSheetName, sheetId, sheets);
        
        if (greenCells.length === 0) {
            return res.json({ message: 'לא נמצאו שינויים לדחייה', greenCells: [] });
        }

        // Take snapshot before rejection (current state with green)
        const snapshotBefore = await takeSnapshot(greenCells, sheets, spreadsheetId, selectedSheetName, sheetId);

        // Find the original state before AI changes
        // We need to look through the history to find the original values
        const aiActions = await ActionHistory.find({
            sessionId: sessionId,
            actionType: 'AI_ACTION',
            status: 'EXECUTED'
        }).sort({ createdAt: 1 }); // Oldest first

        // Build reject requests by restoring original values and colors
        const rejectRequests = [];
        
        for (const cellAddress of greenCells) {
            const range = cellToRange(cellAddress, sheetId);
            
            // Find original value from first AI action that affected this cell
            let originalValue = '';
            let originalFormatting = null;
            
            for (const action of aiActions) {
                if (action.changedCells.includes(cellAddress) && action.snapshotBefore[cellAddress]) {
                    originalValue = action.snapshotBefore[cellAddress].value || '';
                    originalFormatting = action.snapshotBefore[cellAddress].formatting || null;
                    break;
                }
            }

            // Restore original value
            if (originalValue !== undefined) {
                rejectRequests.push({
                    updateCells: {
                        range: range,
                        rows: [{
                            values: [{
                                userEnteredValue: originalValue === '' ? {} : getCorrectValueType(originalValue)
                            }]
                        }],
                        fields: "userEnteredValue"
                    }
                });
            }

            // Restore original formatting
            rejectRequests.push({
                repeatCell: {
                    range: range,
                    cell: {
                        userEnteredFormat: originalFormatting || { backgroundColor: null }
                    },
                    fields: "*"
                }
            });
        }

        // Execute the rejection
        if (rejectRequests.length > 0) {
            await sheets.spreadsheets.batchUpdate({
                spreadsheetId: spreadsheetId,
                resource: { requests: rejectRequests }
            });
        }

        // Save action to history
        const actionHistory = new ActionHistory({
            userId: req.user._id,
            sessionId: sessionId,
            actionType: 'REJECT_ALL',
            snapshotBefore: snapshotBefore,
            changeRequest: rejectRequests,
            status: 'EXECUTED',
            spreadsheetId: spreadsheetId,
            sheetId: sheetId,
            selectedSheetName: selectedSheetName,
            changedCells: greenCells
        });

        await actionHistory.save();

        console.log(`❌ Rejected ${greenCells.length} changes for session ${sessionId}`);
        res.json({ 
            message: `❌ נדחו ${greenCells.length} שינויים`, 
            greenCells: greenCells,
            actionId: actionHistory._id
        });

    } catch (error) {
        console.error('Error in reject all:', error);
        res.status(500).json({ error: 'שגיאה בדחיית השינויים' });
    }
});

/**
 * Act III: The Streaming Conversation (with Agent Mode)
 * This endpoint now has two distinct code paths based on the `isAgentMode` flag
 * to ensure a secure separation between read-only chat and read-write agent actions.
 */
app.post('/api/chat-stream', async (req, res) => {
    // 1. DESTRUCTURE REQUEST: Now includes spreadsheetId and accessToken from the frontend.
    const { question, sheetData, extractedPdfData, extractedExcelData, isAgentMode, isSignificantChange, conversationHistory, spreadsheetId, accessToken, sheetsMetadata, selectedSheetName, sessionId, sheetInstructions } = req.body;

    if (!question) {
        return res.status(400).json({ error: 'Question is required.' });
    }

    console.log('🔥 Chat request received. Sheet instructions:', !!sheetInstructions);
    console.log('🎚️ Significant change mode:', isSignificantChange);
    if (sheetInstructions) {
        console.log('📋 Sheet instructions preview:', sheetInstructions.substring(0, 150) + '...');
    }
    const hasSheetContext = !!sheetData && !!selectedSheetName && !!sheetInstructions;

    // 🔄 בדיקה לפקודות Undo/Redo
    const questionLower = question.toLowerCase().trim();
    const undoKeywords = ['בטל', 'undo', 'בטל פעולה', 'בטל את הפעולה', 'חזור אחורה'];
    const redoKeywords = ['שחזר', 'redo', 'שחזר פעולה', 'עשה שוב', 'חזור קדימה'];
    
    if (undoKeywords.some(keyword => questionLower.includes(keyword))) {
        // בדוק אם יש פעולה לביטול
        const lastAction = await ActionHistory.findLastExecuted(currentSessionId);
        if (!lastAction) {
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.write('❌ אין פעולות לביטול');
            res.end();
            return;
        }
        
        // בצע Undo
        try {
            const oauth2Client = new google.auth.OAuth2();
            oauth2Client.setCredentials({ access_token: accessToken });
            const sheets = google.sheets({ version: 'v4', auth: oauth2Client });

            const revertRequests = [];
            lastAction.changedCells.forEach(cellAddress => {
                const original = lastAction.snapshotBefore[cellAddress];
                let valuePayload;
                if (original.value === "") {
                    valuePayload = null;
                } else if (typeof original.value === 'number') {
                    valuePayload = { numberValue: original.value };
                } else if (typeof original.value === 'string' && original.value.startsWith('=')) {
                    valuePayload = { formulaValue: original.value };
                } else {
                    valuePayload = { stringValue: cleanValueConversion(original.value) };
                }
                
                revertRequests.push({
                    updateCells: {
                        range: cellToRange(cellAddress, lastAction.sheetId),
                        rows: [{ values: [{ userEnteredValue: valuePayload }] }],
                        fields: "userEnteredValue"
                    }
                });
                
                revertRequests.push({
                    repeatCell: {
                        range: cellToRange(cellAddress, lastAction.sheetId),
                        cell: { userEnteredFormat: { backgroundColor: original.backgroundColor } },
                        fields: "userEnteredFormat.backgroundColor"
                    }
                });
            });

            await sheets.spreadsheets.batchUpdate({
                spreadsheetId: lastAction.spreadsheetId,
                resource: { requests: revertRequests }
            });

            lastAction.status = 'UNDONE';
            await lastAction.save();

            console.log(`↩️ Chat Undo executed for session ${currentSessionId}`);
            
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.write(`↩️ הפעולה בוטלה בהצלחה! חזרתי ${lastAction.changedCells.length} תאים למצב הקודם.`);
            res.end();
            return;
        } catch (error) {
            console.error('Error in chat undo:', error);
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.write('❌ שגיאה בביטול הפעולה');
            res.end();
            return;
        }
    }
    
    if (redoKeywords.some(keyword => questionLower.includes(keyword))) {
        // בדוק אם יש פעולה לשחזור
        const lastUndone = await ActionHistory.findLastUndone(currentSessionId);
        if (!lastUndone) {
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.write('❌ אין פעולות לשחזור');
            res.end();
            return;
        }
        
        // בצע Redo
        try {
            const oauth2Client = new google.auth.OAuth2();
            oauth2Client.setCredentials({ access_token: accessToken });
            const sheets = google.sheets({ version: 'v4', auth: oauth2Client });

            const redoRequests = [];
            lastUndone.changeRequest.forEach(action => {
                const range = cellToRange(action.cell, lastUndone.sheetId);

                switch (action.type) {
                    case 'UPDATE':
                        // Determine the correct value type for redo
                        let userEnteredValue;
                        if (typeof action.value === 'number') {
                            userEnteredValue = { numberValue: action.value };
                        } else if (typeof action.value === 'string' && action.value.startsWith('=')) {
                            userEnteredValue = { formulaValue: action.value };
                        } else {
                            userEnteredValue = { stringValue: cleanValueConversion(action.value) };
                        }
                        
                        redoRequests.push({
                            updateCells: {
                                rows: [{ values: [{ userEnteredValue: userEnteredValue }] }],
                                range: range,
                                fields: "userEnteredValue"
                            }
                        });
                        break;

                    case 'CLEAR':
                        redoRequests.push({
                            updateCells: {
                                range: range,
                                fields: "*"
                            }
                        });
                        break;
                }
            });

            await sheets.spreadsheets.batchUpdate({
                spreadsheetId: lastUndone.spreadsheetId,
                resource: { requests: redoRequests }
            });

            lastUndone.status = 'EXECUTED';
            await lastUndone.save();

            console.log(`⤴️ Chat Redo executed for session ${currentSessionId}`);
            
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.write(`⤴️ הפעולה שוחזרה בהצלחה! חזרתי ${lastUndone.changedCells.length} תאים לשינוי החדש.`);
            res.end();
            return;
        } catch (error) {
            console.error('Error in chat redo:', error);
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.write('❌ שגיאה בשחזור הפעולה');
            res.end();
            return;
        }
    }

    // 🛡️ בדיקה חדשה לAgent Mode
    if (isAgentMode && sheetData && (!selectedSheetName || !sheetsMetadata)) {
        return res.status(400).send('לא ניתן לערוך גליון ללא בחירת גליון ספציפי. אנא בחר גליון תחילה.');
    }

    // Generate session ID if not provided
    const currentSessionId = sessionId || generateSessionId();
    let chatHistory = null;

    // Save to database if user is authenticated
    if (req.isAuthenticated()) {
        try {
            console.log(`🔍 Looking for existing session: ${currentSessionId} for user ID: ${req.user._id}`);
            
            chatHistory = await ChatHistory.findOne({
                userId: req.user._id,
                sessionId: currentSessionId
            });
            
            console.log(`🔍 Found existing session:`, chatHistory ? 'YES' : 'NO');
            
            if (!chatHistory) {
                console.log(`📝 Creating new chat session: ${currentSessionId} for user: ${req.user.email}`);
                try {
                    chatHistory = await ChatHistory.createNewSession(req.user._id, currentSessionId);
                    console.log(`✅ Chat session created with ID: ${chatHistory._id}`);
                    console.log(`📊 Session details:`, {
                        sessionId: chatHistory.sessionId,
                        userId: chatHistory.userId,
                        title: chatHistory.title,
                        messageCount: chatHistory.messages.length
                    });
                } catch (createError) {
                    console.error(`❌ Failed to create chat session: ${createError.message}`);
                    console.error('Create error details:', createError);
                    throw createError;
                }
            }

            // Save user message
            console.log(`💾 Attempting to save user message to session: ${currentSessionId}`);
            console.log(`📝 Message content: "${question.substring(0, 50)}..."`);
            
            try {
                const beforeSave = {
                    sessionId: chatHistory.sessionId,
                    messageCount: chatHistory.messages.length,
                    lastActivity: chatHistory.lastActivity
                };
                console.log(`📊 Before save:`, beforeSave);
                
                const result = await chatHistory.addMessage('user', question, {
                    isAgentMode: !!isAgentMode,
                    spreadsheetId: spreadsheetId || null,
                    selectedSheetName: selectedSheetName || null,
                    hasAttachments: !!(extractedPdfData || extractedExcelData),
                    attachmentTypes: [
                        ...(extractedPdfData ? ['pdf'] : []),
                        ...(extractedExcelData ? ['excel'] : [])
                    ]
                });
                
                console.log(`📊 After save:`, {
                    messageCount: chatHistory.messages.length,
                    lastActivity: chatHistory.lastActivity,
                    saved: !!result
                });
                
                console.log(`✅ User message saved successfully to MongoDB`);
                
                // Verify the save by checking database
                const verification = await ChatHistory.findOne({
                    userId: req.user._id,
                    sessionId: currentSessionId
                });
                console.log(`🔍 Verification - Messages in DB: ${verification ? verification.messages.length : 'NOT FOUND'}`);
                
            } catch (saveError) {
                console.error(`❌ Failed to save user message: ${saveError.message}`);
                console.error('Save error details:', saveError);
                throw saveError;
            }
        } catch (error) {
            console.error('❌ Error in chat history operation:', error);
            // Continue processing even if saving fails
        }
    } else {
        console.log('❌ User not authenticated, skipping message save');
    }

    if (isAgentMode && sheetData) {
    /*********************************/
        /* AGENT MODE LOGIC         */
        /*********************************/
        console.log(`[${new Date().toISOString()}] Entering Agent Mode.`);

        // --- NEW: Build dynamic context based on available data ---
        let contextParts = [];
        if (sheetData) {
            console.log('🔥 Agent Mode - Sheet data structure (first 3 rows):', JSON.stringify(sheetData.slice(0, 3), null, 2));
            contextParts.push(`
## The Analyst's Model (From Google Sheets)
This is the destination sheet you will be editing. It contains the user's financial model.
Note: Cells with 'formula' type contain both the calculated value and the original formula for better context.
\`\`\`json
${JSON.stringify(sheetData, null, 2)}
\`\`\`
`);
        }
        if (extractedPdfData) {
            // Check if we have a cached PDF (simple OCR mode) 
            if (hasSheetContext && extractedPdfData?.processingMode === 'simple_ocr') {
                console.warn('[Agent] Sheet context present but PDF still simple_ocr → skipping cache; ensure reanalysis ran.');
            } else if (!hasSheetContext && extractedPdfData.cacheId && extractedPdfData.processingMode === 'simple_ocr') {
                console.log(`[${new Date().toISOString()}] Using cached PDF for Agent mode: ${extractedPdfData.cacheId}`);
                
                // For cached PDFs in Agent mode, we need to generate content with cache
                // But first, let's add the sheet context to help with structured understanding
                contextParts.push(`
## Current Google Sheet Structure
You are working with this financial model sheet:

\`\`\`json
${JSON.stringify(sheetData, null, 2)}
\`\`\`

## Sheet Analysis Context
${sheetInstructions || 'No specific instructions available'}

## Your Task
The user has uploaded a PDF document (available in the conversation context) and wants to update the Google Sheet above. 
Analyze the PDF content and suggest specific changes to the sheet structure, focusing on:
1. Which cells need to be updated with values from the PDF
2. Whether new rows/columns are needed
3. How to maintain the existing formulas and structure

You must provide specific cell references (like A1, B2, etc.) for any changes.
`);
            } else {
                // Traditional structured extraction mode
            const pdfText = extractedPdfData.extractedText || extractedPdfData;
            const integrationAnalysis = extractedPdfData.integrationAnalysis;
            
            contextParts.push(`
## The Company Report (From PDF)
This is the source document. You should extract values FROM this report TO FILL or UPDATE the Analyst's Model in the Google Sheet.

${pdfText}
`);

            // Add integration analysis if available
            if (integrationAnalysis) {
                contextParts.push(`
## Internal Integration Analysis (CRITICAL CONTEXT)
This detailed analysis explains how the PDF data should integrate with the existing sheet. Use this as your guide for making changes:

${integrationAnalysis}
`);
                }
            }
        }
        // You can add a similar block for extractedExcelData if needed

        const fullContext = contextParts.join('\n\n');
        // --- END NEW ---

        // 2. NEW SMART AGENT LOGIC: First check if user is responding to pending clarification questions
        
        // Check if this message contains answers to a pending change plan
        const pendingPlans = await ChangePlan.find({ 
            userId: req.user._id, 
            sessionId: currentSessionId, 
            status: 'PENDING_CLARIFICATION' 
        }).sort({ createdAt: -1 }).limit(1);
        
        if (pendingPlans.length > 0) {
            const pendingPlan = pendingPlans[0];
            const userAnswers = question; // The user's message is the answer

            console.log(`✅ Found pending plan ${pendingPlan.planId}. Assuming user message is the answer and executing.`);

            // 1. Create the execution prompt, now including conversation history for full context
            const executionPrompt = `
You are "Fin-Copilot," an expert Google Sheets agent executing a pre-planned change based on user clarifications.

**CONTEXT:**
You have already analyzed a complex request and created an execution plan. You asked the user clarification questions to finalize the plan. Now, you have received their answers.

**Original User Request:** "${pendingPlan.userRequest}"

**Your Internal Analysis & Execution Plan:**
${pendingPlan.analysisResult.executionPlan}

**Your Clarification Questions You Asked The User:**
${pendingPlan.analysisResult.clarificationQuestions.map((q, i) => `Q${i + 1}: ${q}`).join('\n')}

**Conversation History (for context):**
${formatConversationHistory(conversationHistory)}

**USER'S ANSWERS (process this as a single block of text):**
"${userAnswers}"

**Your Task:**
Based on the user's answers, generate the final list of actions to execute your plan. Produce a JSON object with "actions" and a brief "explanation".

**Available Actions:**
- UPDATE: {"type": "UPDATE", "cell": "A1", "value": "new value"}
- CLEAR: {"type": "CLEAR", "cell": "A1"}

**Full Sheet & Data Context:**
${fullContext}

**IMPORTANT:**
- Adhere strictly to your original execution plan, using the user's answers to resolve ambiguities.
- Respond in the same language as the original user request.
- Return ONLY the JSON object.
`;

            // 🔥 Log the execution prompt
            logger.logDetailed('agent_mode_execution', 'prompt', executionPrompt, {
                description: "פרומפט ביצוע: נשלח למודל כדי לקבל פעולות סופיות לאחר קבלת תשובות מהמשתמש.",
                planId: pendingPlan.planId,
                model: 'gemini-2.5-flash'
            });

            // 2. Call the model to get the final actions
            const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
            const executionResult = await model.generateContent(executionPrompt);
            const executionResponse = await executionResult.response;
            const executionText = executionResponse.text();

            let finalPlan;
            try {
                const cleanedText = executionText.replace(/```json/g, '').replace(/```/g, '').trim();
                finalPlan = JSON.parse(cleanedText);
            } catch (parseError) {
                console.error('Failed to parse final execution plan from agent:', parseError);
                return res.status(500).send("The AI assistant returned a response in an unexpected format during execution.");
            }

            // 🔥 Log the parsed final plan
            logger.logDetailed('agent_mode_execution', 'response_parsed', finalPlan, {
                description: "תכנית פעולה סופית: רשימת הפעולות לביצוע בגיליון, כפי שהתקבלה מהמודל.",
                planId: pendingPlan.planId,
                model: 'gemini-2.5-flash'
            });

            const { actions, explanation } = finalPlan;

            // 3. Execute the actions using the existing logic
            if (actions && Array.isArray(actions) && actions.length > 0) {
                if (!accessToken || !spreadsheetId) {
                    return res.status(400).send("Cannot execute commands: Missing Access Token or Spreadsheet ID.");
                }

                const activeSheet = sheetsMetadata.find(s => s.name === selectedSheetName);
                if (!activeSheet) {
                    throw new Error(`The AI requested an action for a non-existent sheet: '${selectedSheetName}'`);
                }
                const activeSheetId = activeSheet.id;
                
                const oauth2Client = new google.auth.OAuth2();
                oauth2Client.setCredentials({ access_token: accessToken });
                const sheets = google.sheets({ version: 'v4', auth: oauth2Client });
                
                const cellAddresses = actions.map(action => action.cell);
                const snapshot = await takeSnapshot(cellAddresses, sheets, spreadsheetId, selectedSheetName, activeSheetId);
                
                // --- This is the reused execution block ---
                let requests = [];
                console.log(`[PLANNED EXECUTION] Building ${actions.length} actions`);
                
                actions.forEach(action => {
                    const range = {
                        sheetId: activeSheetId,
                        startRowIndex: parseInt(action.cell.match(/\d+/) - 1),
                        endRowIndex: parseInt(action.cell.match(/\d+/) - 1) + 1,
                        startColumnIndex: action.cell.match(/[A-Z]+/)[0].charCodeAt(0) - 'A'.charCodeAt(0),
                        endColumnIndex: action.cell.match(/[A-Z]+/)[0].charCodeAt(0) - 'A'.charCodeAt(0) + 1
                    };

                    switch (action.type) {
                        case 'UPDATE':
                            const userEnteredValue = getCorrectValueType(action.value);
                            
                            requests.push({
                                updateCells: {
                                    rows: [{ values: [{ userEnteredValue: userEnteredValue }] }],
                                    range: range,
                                    fields: "userEnteredValue"
                                }
                            });
                            requests.push({
                                repeatCell: {
                                    range: range,
                                    cell: { userEnteredFormat: { backgroundColor: { "red": 0.85, "green": 0.95, "blue": 0.85 } } },
                                    fields: "userEnteredFormat.backgroundColor"
                                }
                            });
                            break;

                        case 'CLEAR':
                            requests.push({
                                updateCells: {
                                    range: range,
                                    fields: "*"
                                }
                            });
                            break;
                    }
                });

                if (requests.length > 0) {
                    await sheets.spreadsheets.batchUpdate({
                        spreadsheetId: spreadsheetId,
                        resource: { requests: requests }
                    });
                }
                // --- End of reused block ---

                // 4. Update the plan and save to ActionHistory for undo/redo
                await ActionHistory.clearRedoHistory(currentSessionId);
                const actionRecord = new ActionHistory({
                    userId: req.user._id,
                    sessionId: currentSessionId,
                    actionType: 'AI_ACTION',
                    snapshotBefore: snapshot,
                    changeRequest: actions,
                    status: 'EXECUTED',
                    spreadsheetId: spreadsheetId,
                    sheetId: activeSheetId,
                    selectedSheetName: selectedSheetName,
                    changedCells: cellAddresses
                });
                await actionRecord.save();

                pendingPlan.status = 'EXECUTED';
                pendingPlan.finalActions = finalPlan;
                pendingPlan.clarificationAnswers = [userAnswers]; // Save the answer
                await pendingPlan.save();
                
                console.log(`✅ Plan ${pendingPlan.planId} executed successfully.`);
            }

            // 5. Send response to user and finish
                res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.write(explanation || "The changes have been successfully applied.");
                res.end();
            return; // Stop here to prevent falling through to the default logic
        }
        
        // Step 1: Use user-controlled significance (from frontend switch)
        console.log(`🔍 User-controlled significance: ${isSignificantChange ? 'SIGNIFICANT' : 'SIMPLE'}`);
        
        // No need for Gemini to analyze - user decides via frontend switch
        const significanceAnalysis = {
            isSignificant: isSignificantChange || false,
            reasoning: isSignificantChange ? "User marked as significant change via switch" : "User marked as simple change via switch"
        };
        
        console.log(`🔍 Significance Decision:`, significanceAnalysis);
        
        // Check if we need to use cached content for PDF
        const useCache = !hasSheetContext && extractedPdfData?.cacheId && extractedPdfData?.processingMode === 'simple_ocr';
        const modelName = "gemini-2.5-flash";
        const model = genAI.getGenerativeModel({ model: modelName });
        try {
            if (!significanceAnalysis.isSignificant) {
                // Simple change - use streamlined logic
                const simpleAgentPrompt = `
You are "Fin-Copilot," an expert Google Sheets agent handling a simple, straightforward change.

**Your Task:**
Generate a JSON object with:
1. "actions": Array of action objects for immediate execution
2. "explanation": Brief summary of what you're doing

**Available Actions:**
- UPDATE: {"type": "UPDATE", "cell": "A1", "value": "new value"}
- CLEAR: {"type": "CLEAR", "cell": "A1"}

**Context:**
${fullContext}

${sheetInstructions ? `**Sheet Guidelines:**
${sheetInstructions}
---
` : ''}

**User Request:** "${question}"

**IMPORTANT:** Respond in the same language as the user's request.

Return JSON with actions to execute immediately.`;

                let simpleResult;
                if (useCache) {
                    simpleResult = await genAI.models.generateContent({
                        model: modelName,
                        contents: simpleAgentPrompt,
                        config: { cachedContent: extractedPdfData.cacheId }
                    });
                } else {
                    simpleResult = await model.generateContent(simpleAgentPrompt);
                }
                
                const simpleResponse = await simpleResult.response;
                const simpleText = simpleResponse.text();
            
            let responseObject;
            try {
                    const cleanedText = simpleText
                    .replace(/```json/g, '')
                    .replace(/```/g, '')
                        .replace(/\n(?!["}])/g, ' ')
                        .replace(/\s*(["\-=+*/(){}[\],:.])\s*/g, '$1')
                        .replace(/\s{2,}/g, ' ')
                    .trim();
                responseObject = JSON.parse(cleanedText);
            } catch (parseError) {
                    console.error('Failed to parse simple agent response');
                return res.status(500).send("The AI assistant returned a response in an unexpected format.");
            }

                // Execute simple actions immediately
            const { actions, explanation } = responseObject;

            if (actions && Array.isArray(actions) && actions.length > 0) {
                if (!accessToken || !spreadsheetId) {
                    return res.status(400).send("Cannot execute commands: Missing Access Token or Spreadsheet ID.");
                }

                const activeSheet = sheetsMetadata.find(s => s.name === selectedSheetName);
                if (!activeSheet) {
                    throw new Error(`The AI requested an action for a non-existent sheet: '${selectedSheetName}'`);
                }
                const activeSheetId = activeSheet.id;

                const oauth2Client = new google.auth.OAuth2();
                oauth2Client.setCredentials({ access_token: accessToken });
                const sheets = google.sheets({ version: 'v4', auth: oauth2Client });

                    // Take snapshot and execute
                const cellAddresses = actions.map(action => action.cell);
                    console.log(`📸 Taking snapshot for simple execution: ${cellAddresses.join(', ')}`);
                
                const snapshot = await takeSnapshot(cellAddresses, sheets, spreadsheetId, selectedSheetName, activeSheetId);

                    // Build and execute requests
                let requests = [];
                    console.log(`[SIMPLE] Building ${actions.length} actions`);
                
                actions.forEach(action => {
                    const range = {
                        sheetId: activeSheetId,
                        startRowIndex: parseInt(action.cell.match(/\d+/) - 1),
                        endRowIndex: parseInt(action.cell.match(/\d+/) - 1) + 1,
                        startColumnIndex: action.cell.match(/[A-Z]+/)[0].charCodeAt(0) - 'A'.charCodeAt(0),
                        endColumnIndex: action.cell.match(/[A-Z]+/)[0].charCodeAt(0) - 'A'.charCodeAt(0) + 1
                    };

                    switch (action.type) {
                        case 'UPDATE':
                            const userEnteredValue = getCorrectValueType(action.value);
                            
                            requests.push({
                                updateCells: {
                                    rows: [{ values: [{ userEnteredValue: userEnteredValue }] }],
                                    range: range,
                                    fields: "userEnteredValue"
                                }
                            });
                            requests.push({
                                repeatCell: {
                                    range: range,
                                    cell: { userEnteredFormat: { backgroundColor: { "red": 0.85, "green": 0.95, "blue": 0.85 } } },
                                    fields: "userEnteredFormat.backgroundColor"
                                }
                            });
                            break;

                        case 'CLEAR':
                            requests.push({
                                updateCells: {
                                    range: range,
                                    fields: "*"
                                }
                            });
                            break;
                    }
                });

                    // Execute all requests
                    if (requests.length > 0) {
                await sheets.spreadsheets.batchUpdate({
                    spreadsheetId: spreadsheetId,
                            resource: { requests: requests }
                });
                    }

                    // Save to action history
                await ActionHistory.clearRedoHistory(currentSessionId);
                const actionRecord = new ActionHistory({
                    userId: req.user._id,
                    sessionId: currentSessionId,
                    actionType: 'AI_ACTION',
                    snapshotBefore: snapshot,
                    changeRequest: actions,
                    status: 'EXECUTED',
                    spreadsheetId: spreadsheetId,
                    sheetId: activeSheetId,
                    selectedSheetName: selectedSheetName,
                    changedCells: cellAddresses
                });
                await actionRecord.save();

                    console.log(`✅ Simple execution completed: ${actions.length} actions`);
                }
                
                res.setHeader('Content-Type', 'text/plain; charset=utf-8');
                res.write(explanation || "השינויים הפשוטים בוצעו בהצלחה");
                res.end();
                return;
            }

            // Significant change - create detailed plan
            const planningPrompt = `
You are "Fin-Copilot," an expert financial analyst creating a detailed implementation plan for a complex change to a Google Sheets financial model.

**Your Mission:** Create a comprehensive analysis and ask exactly 5 short clarification questions to ensure perfect execution.

**Context:**
${fullContext}

${sheetInstructions ? `**Sheet Guidelines:**
${sheetInstructions}
---
` : ''}

**User Request:** "${question}"
**Conversation History:**
${formatConversationHistory(conversationHistory)}

**Required Analysis:**
1. **Complexity Assessment:** What makes this change complex?
2. **Data Movement:** What data needs to be moved, copied, or restructured?
3. **Formula Impact:** Which formulas might be affected or broken?
4. **Structural Changes:** What structural changes to the sheet are needed?
5. **Potential Issues:** What could go wrong during implementation?
6. **Ambiguities:** What aspects of the request are unclear or could be interpreted multiple ways?

**Language Detection:** Identify the primary language of the sheet and user request. If PDF is in a different language than the sheet, ask about this.

**Your Task:**
Analyze the specific financial model structure and PDF data to create a detailed INTERNAL execution plan. Break down the sheet editing process into logical steps based on the actual data relationships, formulas, and financial logic. Generate exactly 5 short, specific clarification questions (maximum 10 words each).

**Focus Areas:**
1. **Data Relationships:** How do the PDF values relate to existing sheet structure?
2. **Temporal Logic:** Which years/periods need updating? What about historical vs. projected data?
3. **Formula Dependencies:** Which calculations will be affected by changes?
4. **Structural Impact:** Will tables need to be moved/expanded to avoid overwriting?
5. **Data Validation:** How to ensure consistency between old and new data?

**Example Planning Logic:**
- "Step 1: Move revenue table from B5:F10 to B15:F20 because new quarterly data will overwrite it"
- "Step 2: Update 2024 Q1-Q3 data in cells C5:E5 with PDF values"  
- "Step 3: Extend year columns if PDF contains 2025 data (depends on clarification)"
- "Conditional: If user wants to preserve historical data, copy old values to archive section"
- "Validation: Ensure SUM formulas in row 11 still reference correct ranges after move"

**IMPORTANT:** Respond in the same language as the user's request. All analysis and questions should be in that language.

**Return Format:**
Write a natural text analysis with clear sections. Do NOT use JSON format.

**Structure your response as:**

**COMPLEXITY ANALYSIS:**
[Explain in 2-3 sentences why this change is complex given the specific sheet structure and PDF data]

**EXECUTION PLAN:**
[Write a detailed plan in natural language, organized in numbered steps. Each step should explain what needs to be done, why, and which cells/ranges are affected. Include conditional logic based on clarification answers.]

**POTENTIAL ISSUES:**
[List specific issues that could arise during implementation]

**CLARIFICATION QUESTIONS:**
1. [Short specific question - max 10 words]
2. [Question about specific years/periods - max 10 words]
3. [Question about specific formulas/calculations - max 10 words]
4. [Question about specific layout decisions - max 10 words]
5. [Question about specific validation needs - max 10 words]

**LANGUAGE NOTE:**
[Only if there's mismatch between sheet and PDF languages]`;

            // 🔥 Log the planning prompt
            logger.logDetailed('agent_mode_planning', 'prompt', planningPrompt, {
                description: "פרומפט תכנון: נשלח למודל כדי לנתח שינוי מורכב, ליצור תכנית ולשאול שאלות הבהרה.",
                sessionId: currentSessionId,
                model: 'gemini-2.5-flash'
            });

            let planningResult;
            if (useCache) {
                planningResult = await genAI.models.generateContent({
                    model: modelName,
                    contents: planningPrompt,
                    config: { cachedContent: extractedPdfData.cacheId }
                });
            } else {
                planningResult = await model.generateContent(planningPrompt);
            }
            
            const planningResponse = await planningResult.response;
            const planningText = planningResponse.text();
            console.log('Planning response:', planningText);
            
            // Extract clarification questions from the text response
            // Try multiple patterns for different languages and formats
            let questionsMatch = planningText.match(/\*\*CLARIFICATION QUESTIONS:\*\*([\s\S]*?)(?:\*\*|$)/);
            if (!questionsMatch) {
                questionsMatch = planningText.match(/###\s*\*\*שאלות הבהרה\*\*([\s\S]*?)(?:###|$)/);
            }
            if (!questionsMatch) {
                questionsMatch = planningText.match(/שאלות הבהרה([\s\S]*?)(?:###|$)/);
            }
            
            const clarificationQuestions = [];
            
            if (questionsMatch) {
                const questionsText = questionsMatch[1];
                console.log('Questions text found:', questionsText);
                
                // Try different numbering patterns
                let questionMatches = questionsText.match(/^\d+\.\s*(.+)$/gm);
                if (!questionMatches) {
                    // Try Hebrew numbering or bullet points
                    questionMatches = questionsText.match(/^[•\-\*]\s*(.+)$/gm);
                }
                
                if (questionMatches) {
                    questionMatches.forEach(match => {
                        const question = match.replace(/^\d+\.\s*/, '').replace(/^[•\-\*]\s*/, '').trim();
                        if (question && !question.startsWith('[') && question.length > 5) { // Skip placeholder text and very short lines
                            clarificationQuestions.push(question);
                        }
                    });
                }
            }
            
            // If still no questions found, try a more aggressive search
            if (clarificationQuestions.length === 0) {
                console.log('No questions found with structured approach, trying line-by-line search');
                const lines = planningText.split('\n');
                let foundQuestionsSection = false;
                
                for (let line of lines) {
                    line = line.trim();
                    if (line.includes('שאלות הבהרה') || line.includes('CLARIFICATION QUESTIONS')) {
                        foundQuestionsSection = true;
                        continue;
                    }
                    
                    if (foundQuestionsSection && line.match(/^\d+\.\s*.+\?/)) {
                        const question = line.replace(/^\d+\.\s*/, '').trim();
                        if (question.length > 10) {
                            clarificationQuestions.push(question);
                        }
                        if (clarificationQuestions.length >= 5) break;
                    }
                }
            }
            
            console.log('Extracted questions:', clarificationQuestions);

            if (clarificationQuestions.length !== 5) {
                console.error('Expected 5 clarification questions, got:', clarificationQuestions.length);
                return res.status(500).send(`שגיאה: צפויות 5 שאלות הבהרה, התקבלו ${clarificationQuestions.length}`);
            }

            // Create analysis result object for storage
            const analysisResult = {
                fullAnalysis: planningText,
                clarificationQuestions: clarificationQuestions,
                complexity: planningText.match(/\*\*COMPLEXITY ANALYSIS:\*\*([\s\S]*?)(?:\*\*|$)/)?.[1]?.trim() || '',
                executionPlan: planningText.match(/\*\*EXECUTION PLAN:\*\*([\s\S]*?)(?:\*\*|$)/)?.[1]?.trim() || '',
                potentialIssues: planningText.match(/\*\*POTENTIAL ISSUES:\*\*([\s\S]*?)(?:\*\*|$)/)?.[1]?.trim() || '',
                languageNote: planningText.match(/\*\*LANGUAGE NOTE:\*\*([\s\S]*?)(?:\*\*|$)/)?.[1]?.trim() || ''
            };
            
            // 🔥 Log the parsed analysis result
            logger.logDetailed('agent_mode_planning', 'response_parsed', analysisResult, {
                description: "תוצאת תכנון מפוענחת: התכנית הפנימית ושאלות ההבהרה שהמודל יצר.",
                sessionId: currentSessionId,
                model: 'gemini-2.5-flash'
            });
            
            // Save the plan to database
            const changePlan = await ChangePlan.createNewPlan(
                req.user._id, 
                currentSessionId, 
                question, 
                analysisResult
            );
            
            console.log(`📋 Created change plan: ${changePlan.planId}`);
            
            // Return ONLY the clarification questions to user (keep analysis internal)
            const clarificationResponse = `
🔍 **השינוי המבוקש מורכב ודורש הבהרות**

זיהיתי שהשינוי שביקשת מורכב ועלול להשפיע על מספר אזורים בגליון. כדי לבצע אותו בצורה מדויקת ובטוחה, אני צריך כמה הבהרות קצרות ממך.

${analysisResult.languageNote ? `
**🌐 הערה חשובה:**
${analysisResult.languageNote}

` : ''}**🤔 שאלות הבהרה (חובה לענות על כולן):**

${analysisResult.clarificationQuestions.map((q, i) => `**${i + 1}.** ${q}`).join('\n\n')}

---

**⚠️ לביצוע השינויים, אנא ענה על כל 5 השאלות למעלה.**

**מזהה תוכנית:** \`${changePlan.planId}\`
`;

            console.log('=== SENDING TO USER ===');
            console.log(clarificationResponse);
            console.log('=== END USER RESPONSE ===');

            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.write(clarificationResponse);
            res.end();

        } catch (error) {
            console.error(`[${new Date().toISOString()}] Error in Agent Mode:`, error.response ? error.response.data : error.message);
            res.status(500).send("An error occurred while processing your request in Agent Mode.");
        }

    } else {
        /*********************************/
        /*       CHAT MODE LOGIC         */
        /*********************************/
        // This read-only path remains unchanged and safe.
        console.log(`[${new Date().toISOString()}] Entering Chat Mode (Read-Only).`);
        try {
            // Check if we need cache compatibility
            const useCache = extractedPdfData && extractedPdfData.cacheId && extractedPdfData.processingMode === 'simple_ocr';
            
            // Use consistent model
            const modelName = "gemini-2.5-flash";
            const model = genAI.getGenerativeModel({ model: modelName });
            let contextParts = [];
            let instructionParts = [];
            
            if (sheetData) {
                console.log('🔥 Regular chat - Sheet data structure (first 2 rows):', JSON.stringify(sheetData.slice(0, 2), null, 2));
                contextParts.push(`Google Sheet Data:\n${JSON.stringify(sheetData, null, 2)}`);
                instructionParts.push('Google Sheet data');
            }
            if (extractedPdfData) {
                // Check if we have a cached PDF (simple OCR mode) 
                if (extractedPdfData.cacheId && extractedPdfData.processingMode === 'simple_ocr') {
                    console.log(`[${new Date().toISOString()}] Using cached PDF for Chat mode: ${extractedPdfData.cacheId}`);
                    // For cached PDFs, we don't add text to context - the cache handles it
                    instructionParts.push('PDF document (cached)');
                } else {
                    // Traditional mode - add extracted text to context
                const pdfText = extractedPdfData.extractedText || extractedPdfData;
                const integrationAnalysis = extractedPdfData.integrationAnalysis;
                
                contextParts.push(`PDF Data:\n${pdfText}`);
                instructionParts.push('PDF data');
                
                // Add integration analysis if available
                if (integrationAnalysis) {
                    contextParts.push(`PDF Integration Analysis:\n${integrationAnalysis}`);
                    instructionParts.push('PDF integration analysis');
                    }
                }
            }
            if (extractedExcelData) {
                contextParts.push(`Excel Data:\n${JSON.stringify(extractedExcelData, null, 2)}`);
                instructionParts.push('Excel data');
            }
            let contextInfo = contextParts.join('\n\n');
            let instructions;
            if (instructionParts.length > 0) {
                const sources = new Intl.ListFormat('en', { style: 'long', type: 'conjunction' }).format(instructionParts);
                instructions = `You have ${sources}. Analyze all available sources to answer the question.`;
            } else {
                contextInfo = 'No data sources available.';
                instructions = 'Answer the question based on your general knowledge, but mention that no specific data was provided.';
            }
            
            // Check if we need to use cached content
            const useCacheForStreaming = !hasSheetContext && extractedPdfData?.cacheId && extractedPdfData?.processingMode === 'simple_ocr';
            
            if (useCacheForStreaming) {
                console.log(`[${new Date().toISOString()}] Using cached content for streaming: ${extractedPdfData.cacheId}`);
                
                const streamingPrompt = `
You are a financial assistant. ${instructions}
The user's question is: "${question}"
Available data:
${contextInfo}
${sheetInstructions ? `

IMPORTANT - Sheet Analysis Context:
A preliminary analysis has been conducted on the current sheet. Here are key insights and guidelines for working with this data:

${sheetInstructions}

` : ''}Please provide a clear, helpful answer in the same language as the question. Do not use JSON format - just respond naturally.

Note: You also have access to a PDF document that was uploaded by the user. Use the PDF content to help answer their question.
`;
                
                // Using cached content with the correct API
                const response = await genAI.models.generateContent({
                    model: modelName,
                    contents: streamingPrompt,
                    config: { cachedContent: extractedPdfData.cacheId }
                });
                
                // Since we can't stream with cache easily, return the full response
                res.setHeader('Content-Type', 'text/plain; charset=utf-8');
                const fullResponse = response.text();
                res.write(fullResponse);
                res.end();
                
                return; // Exit early for cached content
                
            } else {
            const streamingPrompt = `
You are a financial assistant. ${instructions}
The user's question is: "${question}"
Available data:
${contextInfo}
${sheetInstructions ? `

IMPORTANT - Sheet Analysis Context:
A preliminary analysis has been conducted on the current sheet. Here are key insights and guidelines for working with this data:

${sheetInstructions}

` : ''}Please provide a clear, helpful answer in the same language as the question. Do not use JSON format - just respond naturally.
`;
            const result = await model.generateContentStream({
                contents: [{ role: "user", parts: [{ text: streamingPrompt }] }]
            });
                
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.setHeader('Transfer-Encoding', 'chunked');
            
            let fullResponse = '';
            for await (const chunk of result.stream) {
                const chunkText = chunk.text();
                fullResponse += chunkText;
                res.write(chunkText);
            }
            
            // 🔥 DEBUG: Full Gemini response for Chat Stream
            console.log('\n💬 === GEMINI CHAT STREAM RESPONSE (FULL) ===');
            console.log(fullResponse);
            console.log('💬 === END CHAT STREAM ===\n');
            
            // Save assistant response only if user is authenticated
            try {
                if (chatHistory && fullResponse && req.isAuthenticated()) {
                    console.log(`Saving assistant response to session: ${currentSessionId}`);
                    await chatHistory.addMessage('assistant', fullResponse, {
                        isAgentMode: false,
                        hasAttachments: !!(extractedPdfData || extractedExcelData),
                        attachmentTypes: [
                            ...(extractedPdfData ? ['pdf'] : []),
                            ...(extractedExcelData ? ['excel'] : [])
                        ]
                    });
                    console.log(`✅ Assistant response saved successfully`);
                }
            } catch (error) {
                console.error('❌ Error saving assistant response:', error);
            }
            
            res.end();
            }
        } catch (error) {
            console.error(`[${new Date().toISOString()}] Error during chat streaming:`, error);
            res.end();
        }
    }
});


// Clean up old PDF files every hour
setInterval(() => {
    const now = new Date();
    fs.readdir(uploadsDir, (err, files) => {
        if (err) {
            console.error('Error reading uploads directory:', err);
            return;
        }
        
        files.forEach(file => {
            const filepath = path.join(uploadsDir, file);
            fs.stat(filepath, (err, stats) => {
                if (err) return;
                
                // Delete files older than 48 hours
                const fileAge = now - stats.mtime;
                const maxAge = 48 * 60 * 60 * 1000; // 48 hours in milliseconds
                
                if (fileAge > maxAge) {
                    fs.unlink(filepath, (err) => {
                        if (err) {
                            console.error('Error deleting old file:', err);
                        } else {
                            console.log('Deleted old PDF file:', file);
                        }
                    });
                }
            });
        });
    });
}, 60 * 60 * 1000); // Run every hour

// 🔥 API Endpoint חדש לניתוח גליון עם Gemini
app.post('/api/analyze-sheet', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { sheetData, sheetName, analysisType } = req.body;

    if (!sheetData || !sheetName) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

        const unifiedAnalysisPrompt = `
You are an expert financial analyst. Your task is to analyze the provided Google Sheet data and generate a structured response with three distinct sections for different audiences.

**Sheet Name:** ${sheetName}
**Sheet Data:**
\`\`\`json
${JSON.stringify(sheetData, null, 2)}
\`\`\`

**YOUR TASK:**
Generate a response containing ALL THREE sections below, using the exact headings as specified.

---

### Section 1: User Summary
- **Goal:** To provide a quick, high-level confirmation to the user that you've understood their financial model.
- **Audience:** **External.** This will be displayed directly to the end-user in the chat interface. It must be brief (3-4 lines max) and non-technical.
- **Language:** The summary needs to be written in the primary language of the Google Sheet provided.

### Section 2: AI Editing & Analysis
- **Goal:** To create a comprehensive technical guide for a future AI agent that will perform edits on this sheet.
- **Audience:** **Internal Only.** This is a system instruction. Avoid user-facing language.
- **CRITICAL - Spatial Layout:** Financial models have a visual and spatial structure. Tables are placed above, below, or next to each other for a reason. Your analysis MUST consider this. For example, if adding 10 rows to a "Projects" table will overwrite a "Summary" table below it, your instructions must explicitly state: "First, select and move the 'Summary' table down by 10 rows before adding new data to the 'Projects' table."
- **Process:**
    1.  **High-Level Analysis:** First, describe the sheet's overall structure and data flow. **Crucially, detail the spatial layout by describing the relationships between key tables/blocks (e.g., "'Projects Table' is in A5:E30, directly above the 'Summary Table' which starts at A35").** Your analysis must be based **exclusively** on the provided sheet structure. Do not assume standard financial statement layouts if they contradict the provided data.
    2.  **Specific Instructions:** Based on your analysis, provide a clear, actionable list of editing guidelines. Include what cells are safe to update (inputs), what cells are forbidden (formulas), and explicit warnings about preserving the spatial layout. When your instructions involve adding new rows to an existing table, you must also instruct the AI to analyze the formulas in the calculated columns of that table and replicate their logic for the newly added rows.

### Section 3: Data Extraction Guidelines
- **Goal:** To create a checklist that will guide the AI in extracting the correct data from future financial documents for this model.
- **Audience:** **Internal Only.** This is also part of the system instructions.
- **Content:**
    - List the key data points to look for.
    - Warn about potentially confusing data (e.g., "Look for 'Net Profit attributable to shareholders', not just 'Net Profit'").
    - **Units of Measure:** Pay close attention to units (e.g., thousands, millions) in both the source document and the sheet, and ensure consistency.
    - **Data Formatting:** When extracting numerical or date values, pay close attention to the formatting used in the existing sheet (e.g., currency symbols, decimal separators, date format) and instruct the AI to use the exact same format.
    - Specify what data is irrelevant to this specific model.

---

**OUTPUT FORMAT:**

### SUMMARY_FOR_USER ###
(Your 3-4 line summary in the sheet's language goes here)

### EDITING_INSTRUCTIONS_FOR_AI ###
(Your detailed analysis and editing instructions go here)

### DATA_EXTRACTION_GUIDELINES ###
(Your data extraction checklist goes here)
`;

        console.log('🔥 Analyzing sheet with a unified prompt:', sheetName);
        logger.logDetailed('sheet_analysis', 'unified_prompt', { prompt: unifiedAnalysisPrompt }, { description: "פרומפט מאוחד לניתוח גיליון: נשלח למודל ליצירת סיכום והוראות.", sheetName, model: 'gemini-2.5-flash' });

        const result = await model.generateContent(unifiedAnalysisPrompt);
        const fullResponseText = await result.response.text();

        logger.logDetailed('sheet_analysis', 'unified_response', { response: fullResponseText }, { description: "תשובה מאוחדת מהמודל: מכילה גם את הסיכום וגם את ההוראות.", sheetName, model: 'gemini-2.5-flash' });

        const summaryMatch = fullResponseText.match(/### SUMMARY_FOR_USER ###([\s\S]*?)### EDITING_INSTRUCTIONS_FOR_AI ###/);
        const editingInstructionsMatch = fullResponseText.match(/### EDITING_INSTRUCTIONS_FOR_AI ###([\s\S]*?)### DATA_EXTRACTION_GUIDELINES ###/);
        const extractionGuidelinesMatch = fullResponseText.match(/### DATA_EXTRACTION_GUIDELINES ###([\s\S]*)/);

        const summary = summaryMatch ? summaryMatch[1].trim() : "Failed to parse summary.";
        const editingInstructions = editingInstructionsMatch ? editingInstructionsMatch[1].trim() : "Failed to parse editing instructions.";
        const extractionGuidelines = extractionGuidelinesMatch ? extractionGuidelinesMatch[1].trim() : "Failed to parse extraction guidelines.";
        
        const instructions = `
## AI Editing & Analysis
${editingInstructions}

---

## Data Extraction Guidelines
${extractionGuidelines}
`;

        console.log('📊 Sheet analysis completed and parsed for:', sheetName);

        res.json({
            summary: summary,
            instructions: instructions,
            sheetName: sheetName,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error analyzing sheet with Gemini:', error);
        res.status(500).json({ 
            error: 'Failed to analyze sheet',
            details: error.message 
        });
    }
});

// New endpoint for executing change plans after clarification
app.post('/api/execute-change-plan', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { planId, clarificationAnswers, spreadsheetId, accessToken, sheetsMetadata, selectedSheetName } = req.body;

    if (!planId || !clarificationAnswers || clarificationAnswers.length !== 5) {
        return res.status(400).json({ error: 'Plan ID and exactly 5 clarification answers are required' });
    }

    try {
        // Find the change plan
        const changePlan = await ChangePlan.findByPlanId(planId);
        if (!changePlan || changePlan.userId.toString() !== req.user._id.toString()) {
            return res.status(404).json({ error: 'Change plan not found' });
        }

        if (changePlan.status !== 'PENDING_CLARIFICATION') {
            return res.status(400).json({ error: 'Change plan is not in pending clarification status' });
        }

        // Update plan with clarification answers
        await ChangePlan.addClarificationAnswers(planId, clarificationAnswers);

        // Generate final execution plan based on clarifications
        const executionPrompt = `
You are "Fin-Copilot" executing a pre-planned complex change to a Google Sheets financial model.

**Original User Request:** "${changePlan.userRequest}"

**Your Previous Analysis:**
- Complexity: ${changePlan.analysisResult.complexity}
- Data Movement: ${changePlan.analysisResult.dataMovement}
- Formula Impact: ${changePlan.analysisResult.formulaImpact}
- Structural Changes: ${changePlan.analysisResult.structuralChanges}
- Potential Issues: ${changePlan.analysisResult.potentialIssues.join(', ')}

**Your Clarification Questions & User Answers:**
${changePlan.analysisResult.clarificationQuestions.map((q, i) => 
  `Q${i + 1}: ${q}\nA${i + 1}: ${clarificationAnswers[i]}`
).join('\n\n')}

**Your Previous Analysis:**
Complexity: ${changePlan.analysisResult.complexity}

**Your Detailed Execution Plan:**
${changePlan.analysisResult.executionPlan}

**Potential Issues Identified:**
${changePlan.analysisResult.potentialIssues}

**Now Execute:** Follow your detailed execution plan above. Use the clarification answers to guide your decisions and execute the appropriate actions based on the user's responses.

**Available Actions:**
- UPDATE: {"type": "UPDATE", "cell": "A1", "value": "new value"}
- CLEAR: {"type": "CLEAR", "cell": "A1"}

**IMPORTANT:** Respond in the same language as the original user request.

**Return Format:**
{
  "actions": [array of action objects],
  "explanation": "Summary of what will be executed based on clarifications",
  "warnings": ["Any final warnings or notes"]
}

Return ONLY the JSON object.`;

        const modelName = "gemini-2.5-flash";
        const model = genAI.getGenerativeModel({ model: modelName });
        
        const executionResult = await model.generateContent(executionPrompt);
        const executionResponse = await executionResult.response;
        const executionText = executionResponse.text();
        
        let finalPlan;
        try {
            const cleanedText = executionText
                .replace(/```json/g, '')
                .replace(/```/g, '')
                .replace(/\n(?!["}])/g, ' ')
                .replace(/\s*(["\-=+*/(){}[\],:.])\s*/g, '$1')
                .replace(/\s{2,}/g, ' ')
                .trim();
            finalPlan = JSON.parse(cleanedText);
        } catch (parseError) {
            console.error('Failed to parse execution plan');
            return res.status(500).send("שגיאה ביצירת תוכנית הביצוע הסופית.");
        }

        // Save final actions to the plan
        changePlan.finalActions = finalPlan;
        changePlan.status = 'READY_FOR_EXECUTION';
        await changePlan.save();

        // Execute the actions
        const { actions, explanation, warnings } = finalPlan;
        
        if (actions && Array.isArray(actions) && actions.length > 0) {
            if (!accessToken || !spreadsheetId) {
                return res.status(400).send("Cannot execute: Missing Access Token or Spreadsheet ID.");
            }

            const activeSheet = sheetsMetadata.find(s => s.name === selectedSheetName);
            if (!activeSheet) {
                throw new Error(`Sheet not found: '${selectedSheetName}'`);
            }
            const activeSheetId = activeSheet.id;

            const oauth2Client = new google.auth.OAuth2();
            oauth2Client.setCredentials({ access_token: accessToken });
            const sheets = google.sheets({ version: 'v4', auth: oauth2Client });

            // Take snapshot and execute
            const cellAddresses = actions.map(action => action.cell);
            console.log(`📸 Taking snapshot for planned execution: ${cellAddresses.join(', ')}`);
            
            const snapshot = await takeSnapshot(cellAddresses, sheets, spreadsheetId, selectedSheetName, activeSheetId);
            
            // Build and execute requests
            let requests = [];
            console.log(`[PLANNED EXECUTION] Building ${actions.length} actions`);
            
            actions.forEach(action => {
                const range = {
                    sheetId: activeSheetId,
                    startRowIndex: parseInt(action.cell.match(/\d+/) - 1),
                    endRowIndex: parseInt(action.cell.match(/\d+/) - 1) + 1,
                    startColumnIndex: action.cell.match(/[A-Z]+/)[0].charCodeAt(0) - 'A'.charCodeAt(0),
                    endColumnIndex: action.cell.match(/[A-Z]+/)[0].charCodeAt(0) - 'A'.charCodeAt(0) + 1
                };

                switch (action.type) {
                    case 'UPDATE':
                        const userEnteredValue = getCorrectValueType(action.value);
                        
                        requests.push({
                            updateCells: {
                                rows: [{ values: [{ userEnteredValue: userEnteredValue }] }],
                                range: range,
                                fields: "userEnteredValue"
                            }
                        });
                        requests.push({
                            repeatCell: {
                                range: range,
                                cell: { userEnteredFormat: { backgroundColor: { "red": 0.85, "green": 0.95, "blue": 0.85 } } },
                                fields: "userEnteredFormat.backgroundColor"
                            }
                        });
                        break;

                    case 'CLEAR':
                        requests.push({
                            updateCells: {
                                range: range,
                                fields: "*"
                            }
                        });
                        break;
                }
            });

            // Execute all requests
            if (requests.length > 0) {
                await sheets.spreadsheets.batchUpdate({
                    spreadsheetId: spreadsheetId,
                    resource: { requests: requests }
                });
            }

            // Save to action history
            const actionHistory = new ActionHistory({
                userId: req.user._id,
                sessionId: changePlan.sessionId,
                snapshotBefore: snapshot,
                changeRequest: finalPlan,
                actionType: 'AI_ACTION',
                status: 'EXECUTED',
                spreadsheetId: spreadsheetId,
                sheetId: activeSheetId,
                selectedSheetName: selectedSheetName,
                changedCells: cellAddresses
            });
            await actionHistory.save();

            // Update plan status
            changePlan.status = 'EXECUTED';
            await changePlan.save();

            console.log(`✅ Planned execution completed: ${actions.length} actions`);
        }

        const finalResponse = `
✅ **תוכנית בוצעה בהצלחה!**

**מה בוצע:** ${explanation}

${warnings && warnings.length > 0 ? `
**⚠️ הערות חשובות:**
${warnings.map(w => `• ${w}`).join('\n')}
` : ''}

**📊 סיכום:** ${actions ? actions.length : 0} פעולות בוצעו בגליון.

**מזהה תוכנית:** \`${planId}\` (הושלמה)
`;

        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.write(finalResponse);
        res.end();

    } catch (error) {
        console.error('Error executing change plan:', error);
        res.status(500).send("שגיאה בביצוע התוכנית. אנא נסה שוב.");
    }
});

app.listen(PORT, () => {
    console.log('🚀 Login & Extraction server running on http://localhost:' + PORT);
    console.log('📱 Frontend should be running on http://localhost:3000');
});

// 🔥 NEW: Excel to Google Sheets conversion endpoint
app.post('/api/excel-to-sheets', upload.single('excel'), async (req, res) => {
    console.log('🔍 /api/excel-to-sheets endpoint called');
    console.log('🔐 Authentication status:', req.isAuthenticated());
    
    if (!req.isAuthenticated()) {
        console.log('❌ User not authenticated for Excel conversion - requires Google Drive access');
        return res.status(401).json({
            error: 'Authentication required',
            message: 'Please log in with Google to convert Excel files to Google Sheets',
            requiresAuth: true
        });
    }

    if (!req.file) {
        return res.status(400).json({ error: 'No Excel file uploaded' });
    }

    try {
        console.log(`[${new Date().toISOString()}] Starting Excel to Google Sheets conversion for: ${req.file.originalname}`);
        
        // Parse Excel file using xlsx library
        const XLSX = require('xlsx');
        const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
        
        // Get all sheets from the workbook
        const sheetsData = {};
        workbook.SheetNames.forEach(sheetName => {
            const worksheet = workbook.Sheets[sheetName];
            // Convert to 2D array format
            const jsonData = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: '' });
            sheetsData[sheetName] = jsonData;
        });
        
        // Create OAuth2 client with user's access token
        const oauth2Client = new google.auth.OAuth2();
        oauth2Client.setCredentials({ access_token: req.user.accessToken });
        
        // Initialize Google APIs
        const drive = google.drive({ version: 'v3', auth: oauth2Client });
        const sheets = google.sheets({ version: 'v4', auth: oauth2Client });
        
        // Helper function to find or create TLV500-AI folder
        async function findOrCreateTLV500Folder() {
            const folderName = 'TLV500-AI';
            
            // Search for existing folder
            const searchResponse = await drive.files.list({
                q: `name='${folderName}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
                fields: 'files(id, name)'
            });
            
            if (searchResponse.data.files && searchResponse.data.files.length > 0) {
                console.log(`Found existing TLV500-AI folder: ${searchResponse.data.files[0].id}`);
                return searchResponse.data.files[0].id;
            }
            
            // Create new folder if it doesn't exist
            console.log('Creating new TLV500-AI folder...');
            const createResponse = await drive.files.create({
                resource: {
                    name: folderName,
                    mimeType: 'application/vnd.google-apps.folder'
                },
                fields: 'id'
            });
            
            console.log(`Created TLV500-AI folder: ${createResponse.data.id}`);
            return createResponse.data.id;
        }
        
        // Get or create the TLV500-AI folder
        const folderId = await findOrCreateTLV500Folder();
        
        // Extract filename without extension for the new sheet name
        const originalFileName = req.file.originalname.replace(/\.(xlsx?|csv)$/i, '');
        const spreadsheetTitle = `${originalFileName} (Converted ${new Date().toLocaleDateString()})`;
        
        // Create a new Google Spreadsheet in the TLV500-AI folder
        console.log(`Creating new Google Spreadsheet: ${spreadsheetTitle} in TLV500-AI folder`);
        const createResponse = await sheets.spreadsheets.create({
            resource: {
                properties: {
                    title: spreadsheetTitle
                }
            }
        });
        
        const spreadsheetId = createResponse.data.spreadsheetId;
        const spreadsheetUrl = createResponse.data.spreadsheetUrl;
        
        console.log(`Created spreadsheet with ID: ${spreadsheetId}`);
        
        // Move the spreadsheet to the TLV500-AI folder
        console.log(`Moving spreadsheet to TLV500-AI folder...`);
        await drive.files.update({
            fileId: spreadsheetId,
            addParents: folderId,
            fields: 'id, parents'
        });
        
        console.log(`Spreadsheet moved to TLV500-AI folder successfully`);
        
        // Prepare batch update requests for all sheets
        const requests = [];
        const sheetNames = Object.keys(sheetsData);
        
        // If there are multiple sheets, we need to add them (first sheet already exists)
        if (sheetNames.length > 1) {
            for (let i = 1; i < sheetNames.length; i++) {
                requests.push({
                    addSheet: {
                        properties: {
                            title: sheetNames[i],
                            index: i
                        }
                    }
                });
            }
        }
        
        // Rename the first sheet if needed
        if (sheetNames.length > 0 && sheetNames[0] !== 'Sheet1') {
            requests.push({
                updateSheetProperties: {
                    properties: {
                        sheetId: 0,
                        title: sheetNames[0]
                    },
                    fields: 'title'
                }
            });
        }
        
        // Execute sheet structure updates if any
        if (requests.length > 0) {
            await sheets.spreadsheets.batchUpdate({
                spreadsheetId: spreadsheetId,
                resource: { requests }
            });
        }
        
        // Now populate each sheet with data
        const dataUpdateRequests = [];
        sheetNames.forEach((sheetName, sheetIndex) => {
            const data = sheetsData[sheetName];
            if (data && data.length > 0) {
                // Convert data to proper format for Google Sheets
                const values = data.map(row => {
                    return row.map(cell => {
                        // Handle different data types
                        if (cell === null || cell === undefined) return '';
                        if (typeof cell === 'number') return cell;
                        if (typeof cell === 'boolean') return cleanValueConversion(cell);
                        if (cell instanceof Date) return cell.toISOString();
                        return cleanValueConversion(cell);
                    });
                });
                
                dataUpdateRequests.push({
                    range: `${sheetName}!A1`,
                    values: values
                });
            }
        });
        
        // Batch update all sheet data
        if (dataUpdateRequests.length > 0) {
            await sheets.spreadsheets.values.batchUpdate({
                spreadsheetId: spreadsheetId,
                resource: {
                    valueInputOption: 'USER_ENTERED',
                    data: dataUpdateRequests
                }
            });
        }
        
        console.log(`Successfully populated ${sheetNames.length} sheets with data`);
        
        // Optional: Set permissions (make it accessible to the user)
        try {
            await drive.permissions.create({
                fileId: spreadsheetId,
                resource: {
                    type: 'user',
                    role: 'writer',
                    emailAddress: req.user.email
                }
            });
        } catch (permError) {
            // Permission might already exist, continue
            console.log('Permission setting skipped (might already exist):', permError.message);
        }
        
        // Return success response with the new spreadsheet URL
        res.json({
            success: true,
            spreadsheetId: spreadsheetId,
            spreadsheetUrl: spreadsheetUrl,
            fileName: req.file.originalname,
            sheetsCount: sheetNames.length,
            message: `Successfully converted Excel file to Google Sheets with ${sheetNames.length} sheet(s)`
        });
        
        console.log(`[${new Date().toISOString()}] Excel to Google Sheets conversion completed successfully`);
        
    } catch (error) {
        console.error('Error converting Excel to Google Sheets:', error);
        res.status(500).json({
            error: 'Failed to convert Excel to Google Sheets',
            details: error.message
        });
    }
});

// 🔥 Endpoint to check if PDF exists and download it
app.get('/api/download-pdf/:fileId', (req, res) => {
    const { fileId } = req.params;
    const filePath = path.join(__dirname, 'uploads', `${fileId}.pdf`);
    
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).json({ error: 'PDF file not found' });
    }
});

app.head('/api/download-pdf/:fileId', (req, res) => {
    const { fileId } = req.params;
    const filePath = path.join(__dirname, 'uploads', `${fileId}.pdf`);
    
    if (fs.existsSync(filePath)) {
        res.status(200).end();
    } else {
        res.status(404).end();
    }
});
