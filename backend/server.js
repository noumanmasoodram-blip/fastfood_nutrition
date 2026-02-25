import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import path from "path";
import Groq from "groq-sdk";
import pg from "pg";
import { Pool } from "pg";
import { fileURLToPath } from "url";
import fs from "fs";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import nodemailer from 'nodemailer';
import { OAuth2Client } from "google-auth-library";

// Load env
dotenv.config();

// __dirname for ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize app
const app = express();

// CORS and body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend static files
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// Rate limiter map for emails
const emailRateLimiter = new Map();

// Development helper endpoint (no top-level return statements)
if (process.env.NODE_ENV === 'development' && process.env.SEND_EMAILS_IN_DEV !== 'true') {
  console.log('🚀 DEVELOPMENT MODE: Using mock sendVerificationEmail (logs only). To send real emails in dev set SEND_EMAILS_IN_DEV=true');

  // Expose last code endpoint for dev
}

/* ===================== CORE MIDDLEWARE ===================== */

app.use(express.static("public"));
app.use(cors({
  origin: process.env.NODE_ENV === "production"
    ? ["https://www.fastfoodinsight.com"]
    : ["http://localhost:3000", "http://localhost:5173"],
  credentials: true
}));

/* ===================== DATABASE ===================== */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ===================== GOOGLE AUTH ===================== */
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const transporter = nodemailer.createTransport({
    host: process.env.SMTP2GO_HOST || 'mail.smtp2go.com',
    port: process.env.SMTP2GO_PORT || 587,
    secure: false, // Use STARTTLS
    requireTLS: true,
    auth: {
        user: process.env.SMTP2GO_USER,
        pass: process.env.SMTP2GO_PASSWORD
    },
    tls: {
        ciphers: 'SSLv3',
        rejectUnauthorized: false
    }
});


// Verify SMTP connection
transporter.verify(function(error, success) {
    if (error) {
        console.error('❌ SMTP2GO connection failed:', error);
    } else {
        console.log('✅ SMTP2GO server is ready to take our messages');
        console.log('📧 Server:', process.env.SMTP2GO_HOST);
    }
});

// Event listeners for debugging
transporter.on('log', (log) => {
    console.log('📧 SMTP Log:', log.message);
});

transporter.on('error', (error) => {
    console.error('❌ SMTP Error:', error);
});

transporter.on('sent', (info) => {
    console.log('✅ Email sent successfully via SMTP2GO');
    console.log('Message ID:', info.messageId);
});


// List of blocked temporary email domains
const BLOCKED_EMAIL_DOMAINS = [
    '10minutemail.com',
    'tempmail.io', 
    'mailinator.com',
    'guerrillamail.com',
    'throwawaymail.com',
    'yopmail.com',
    'temp-mail.org',
    'trashmail.com',
    'fakeinbox.com',
    'mailnesia.com',
    'getairmail.com',
    'maildrop.cc',
    'tempail.com',
    'discard.email'
];

// Helper function to check email domain
function isBlockedEmailDomain(email) {
    const domain = email.split('@')[1]?.toLowerCase();
    return BLOCKED_EMAIL_DOMAINS.includes(domain);
}
/* ============================================================
   🔐 AUTH HELPERS
============================================================ */
// Add CSP headers for Google OAuth
// Replace lines 108-123 with:
app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production') {
        res.setHeader(
            'Content-Security-Policy',
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' https://accounts.google.com https://apis.google.com https://www.gstatic.com; " +
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
            "font-src 'self' https://fonts.gstatic.com; " +
            "img-src 'self' data: https:; " +
            "frame-src 'self' https://accounts.google.com; " +
            "connect-src 'self' https://accounts.google.com https://*.googleapis.com https://*.fastfoodinsight.com;"
        );
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    }
    next();
});

function createToken(user) {
  const payload = { id: user.id };
  if (user.trial_end) payload.trial_end = user.trial_end;
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" }); // ✅ USE HERE
}
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return next();

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET); // ✅ USE HERE
  } catch {
    req.user = null;
  }
  next();
}

app.use(auth);

/* ============================================================
   🕒 ANONYMOUS MESSAGE TRACKING (PERSISTENT)
============================================================ */

const anonUsage = new Map();

function checkAnonLimit(anonId) {
  const now = Date.now();
  let data = anonUsage.get(anonId);

  if (!data) {
    data = { count: 0, firstSeen: now };
  }

  data.count += 1;
  anonUsage.set(anonId, data);

  return data.count > 10;
}
// === SERVE FAVICON EXPLICITLY ===
app.get('/favicon.ico', (req, res) => {
  const faviconPath = path.join(__dirname, '..', 'frontend', 'favicon.ico');
  if (fs.existsSync(faviconPath)) {
    res.sendFile(faviconPath);
  } else {
    res.sendStatus(404);
  }
});

// === DATABASE CONFIGURATION ===
const db = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// === TEST DATABASE CONNECTION ===
const testConnection = async () => {
    try {
        const client = await db.connect();
        console.log("✅ Connected to PostgreSQL!");
        client.release();
    } catch (err) {
        console.error("❌ Database Connection Error:", err.message);
        process.exit(1);
    }
};

// === UTILITY ===
const handleDatabaseError = (res, err, operation) => {
    console.error(`❌ ${operation} error:`, err);
    res.status(500).json({ error: "Database error" });
};
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// 2. The System Prompt (Tells Groq your DB Schema)
const DB_SCHEMA_CONTEXT = `
You are a Fast Food Nutrition Expert. Use the following PostgreSQL schema to answer questions.
Tables:
- countries (id, name)
- branches (id, name)
- branch_locations (id, branch_id, country_id)
- food_items (id, branch_location_id, name, serving_size, calories, total_fat, saturated_fat, trans_fat, cholesterol, sodium, carbohydrates, sugars, protein)

Rules:
1. Return ONLY a valid SQL query. Do not explain anything.
2. Join branch_locations with countries and branches to filter by brand or country.
3. Use ILIKE for name searches.
`;

async function sendVerificationEmail(toEmail, toName, verificationCode, verificationLink) {
    const now = Date.now();
    const lastSentTime = emailRateLimiter.get(toEmail.toLowerCase());
    
    if (lastSentTime && (now - lastSentTime) < 60000) { // 60 seconds cooldown
        console.log(`⏳ Rate limited: Email already sent to ${toEmail} within last 60 seconds`);
        return true; // Return true so calling code thinks it succeeded (code is already in DB)
    }
     emailRateLimiter.set(toEmail.toLowerCase(), now);
    // Update the rate limiter timestamp
    emailRateLimiter.set(toEmail.toLowerCase(), now);
    const subject = "Verify Your FastFoodInsight AI Account";
    const htmlContent = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #FF6B35;">Welcome to FastFoodInsight AI!</h2>
            <p>Hello ${toName || 'User'},</p>
            <p>Use the 6-digit verification code below to verify your email:</p>
            <div style="text-align: center; margin: 20px 0;">
                <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #FF6B35; background: #f5f5f5; padding: 15px; border-radius: 8px;">
                    ${verificationCode}
                </div>
            </div>
            <p>Or click the button below to verify directly:</p>
            <div style="text-align: center; margin: 20px 0;">
                <a href="${verificationLink}" 
                   style="background-color: #FF6B35; color: white; padding: 12px 24px; 
                          text-decoration: none; border-radius: 6px; display: inline-block;">
                    Verify Email Address
                </a>
            </div>
            <p>This code will expire in 24 hours.</p>
            <p>If you didn't create this account, you can safely ignore this email.</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #666; font-size: 12px;">
                FastFoodInsight AI • World's Largest Fast Food Nutrition Database
            </p>
        </div>
    `;

    // Always log for debugging
    console.log(`\n📧 ============ EMAIL VERIFICATION ============`);
    console.log(`📧 To: ${toEmail}`);
    console.log(`🔑 Verification Code: ${verificationCode}`);
    console.log(`🔗 Verification Link: ${verificationLink}`);

    // Save to global for dev access
    global.lastVerificationCode = verificationCode;
    global.lastVerificationEmail = toEmail;
    global.lastVerificationTime = new Date();

    // Save to database
    try {
        await pool.query(
            'UPDATE users SET verification_token = $1, verification_token_expiry = NOW() + INTERVAL \'24 hours\' WHERE LOWER(email) = LOWER($2)',
            [verificationCode, toEmail]
        );
        console.log(`💾 Code saved to database`);
    } catch (dbErr) {
        console.error('⚠️ Could not save to database:', dbErr.message);
    }

    // In development, skip actual sending unless explicitly enabled
    if (process.env.NODE_ENV === 'development' && process.env.SEND_EMAILS_IN_DEV !== 'true') {
        console.log('🚀 DEV MODE: Email not sent. Code available at /api/dev/latest-code');
        return true;
    }

    // Production: Send via SMTP2GO
    try {
        console.log(`📤 Sending email via SMTP2GO...`);
        
        const mailOptions = {
            from: `"${process.env.SMTP2GO_FROM_NAME || 'FastFoodInsight AI'}" <${process.env.SMTP2GO_FROM || 'support@fastfoodinsight.com'}>`,
            to: toEmail,
            subject,
            html: htmlContent,
            text: `Welcome to FastFoodInsight AI! Your verification code is: ${verificationCode}. Verify at: ${verificationLink}`,
        };

        const info = await transporter.sendMail(mailOptions);
        console.log(`✅ Email sent successfully! Message ID: ${info.messageId}`);
        return true;
    } catch (smtpErr) {
        console.error('❌ SMTP2GO failed:', smtpErr.message);
        
        // Fallback to Gmail if configured
        if (process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
            try {
                console.log('🔄 Trying Gmail fallback...');
                const fallbackTransporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: process.env.EMAIL_USER,
                        pass: process.env.EMAIL_PASSWORD
                    }
                });

                const fallbackOptions = {
                    from: `"FastFoodInsight AI" <${process.env.EMAIL_USER}>`,
                    to: toEmail,
                    subject,
                    html: htmlContent,
                    text: `Your verification code: ${verificationCode}. Verify: ${verificationLink}`
                };

                const info = await fallbackTransporter.sendMail(fallbackOptions);
                console.log(`✅ Email sent via Gmail! Message ID: ${info.messageId}`);
                return true;
            } catch (fallbackErr) {
                console.error('❌ Gmail fallback failed:', fallbackErr.message);
                return false;
            }
        }
        
        return false;
    }
}
// Fallback function using Gmail SMTP
async function sendVerificationEmailFallback(toEmail, toName, verificationCode, verificationLink) {
    try {
        const fallbackTransporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD
            }
        });
        
        const mailOptions = {
            from: `"FastFoodInsight AI" <${process.env.EMAIL_USER}>`,
            to: toEmail,
            subject: "Verify Your FastFoodInsight AI Account",
            html: `...same HTML content as above...`,
            text: `Welcome to FastFoodInsight AI! Your verification code is: ${verificationCode}. You can also verify by clicking: ${verificationLink}`
        };
        
        const info = await fallbackTransporter.sendMail(mailOptions);
        console.log(`✅ Verification email sent via Gmail fallback to ${toEmail}`);
        return true;
    } catch (fallbackErr) {
        console.error('❌ Gmail fallback also failed:', fallbackErr.message);
        return false;
    }
}



// Add this endpoint to test SMTP connection

// Simple direct SMTP test
// Add this endpoint to server.js (somewhere before the chat endpoints)

// Add this test endpoint to server.js (somewhere before the chat endpoints):


app.post('/api/auth/email', async (req, res) => {
    try {
        const { email } = req.body;
        
        console.log('📧 Email auth attempt for:', email);
        
        if (!email || !email.includes('@')) {
            return res.status(400).json({
                success: false,
                error: 'Valid email address required'
            });
        }
        
        // Check if user exists
        const userResult = await pool.query(
            'SELECT id, email, name, trial_end, is_verified, verification_token FROM users WHERE LOWER(email) = LOWER($1)',
            [email.toLowerCase()]
        );
        
        if (userResult.rows.length > 0) {
            // User exists
            const user = userResult.rows[0];
            
            // Check if user is verified
            if (!user.is_verified) {
                console.log('⚠️ Unverified user attempting email auth');
                
                // Generate new verification code
                const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
                const verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
                
                // Update verification token
                await pool.query(
                    'UPDATE users SET verification_token = $1, verification_token_expiry = $2 WHERE id = $3',
                    [verificationCode, verificationTokenExpiry, user.id]
                );
                
                // Send verification email
                const verificationLink = `${process.env.APP_URL || 'http://localhost:3000'}/verify-email?token=${verificationCode}`;
                await sendVerificationEmail(email, user.name, verificationCode, verificationLink);
                
                return res.json({
                    success: false,
                    requiresVerification: true,
                    email: email,
                    showVerificationPopup: true,
                    message: 'Please verify your email first. A new verification code has been sent.'
                });
            }
            
            // User is verified, create temporary token
            const tempToken = jwt.sign(
                {
                    id: user.id,
                    email: user.email,
                    temp: true
                },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );
            
            res.json({
                success: true,
                token: tempToken,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    trialEnd: user.trial_end,
                    isVerified: true
                },
                message: 'Email authentication successful'
            });
            
        } else {
            // New user - create account with verification
            console.log('👤 Creating new user for email auth:', email);
            
            const name = email.split('@')[0];
            const trialStart = new Date();
            const trialEnd = new Date(trialStart);
            trialEnd.setDate(trialEnd.getDate() + 30);
            
            // Generate verification code
            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            const verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
            
            const newUserResult = await pool.query(
                `INSERT INTO users (email, name, trial_start, trial_end, user_identifier, 
                                   verification_token, verification_token_expiry, created_at) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) 
                 RETURNING id, email, name, trial_end`,
                [email.toLowerCase(), name, trialStart, trialEnd, email.toLowerCase(), 
                 verificationCode, verificationTokenExpiry]
            );
            
            const user = newUserResult.rows[0];
            
            // Send verification email
            const verificationLink = `${process.env.APP_URL || 'http://localhost:3000'}/verify-email?token=${verificationCode}`;
            await sendVerificationEmail(email, name, verificationCode, verificationLink);
            
            // Create temporary token
            const tempToken = jwt.sign(
                {
                    id: user.id,
                    email: user.email,
                    temp: true
                },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );
            
            res.json({
                success: true,
                requiresVerification: true,
                email: email,
                token: tempToken,
                user: user,
                showVerificationPopup: true,
                message: 'Account created! Please check your email for the verification code.'
            });
        }
        
    } catch (error) {
        console.error('Email auth error:', error);
        
        if (error.code === '23505') {
            return res.status(400).json({
                success: false,
                error: 'Email already exists'
            });
        }
        
        res.status(500).json({
            success: false,
            error: 'Authentication failed'
        });
    }
});


/* ============================================================
   🔑 LOGIN / REGISTER / VERIFY ENDPOINTS (existing + new)
============================================================ */

app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, name, password } = req.body;
        
        console.log('📝 Registration attempt for:', email);
        
        // Validate input
        if (!email || !name || !password) {
            return res.status(400).json({
                success: false,
                error: 'Email, name, and password are required'
            });
        }
        
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                error: 'Password must be at least 8 characters'
            });
        }
        
        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT id, is_verified FROM users WHERE LOWER(email) = LOWER($1)',
            [email]
        );
        
        if (existingUser.rows.length > 0) {
            const user = existingUser.rows[0];
            
            // If user exists but is not verified, resend verification
            if (!user.is_verified) {
                const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
                const verificationLink = `${process.env.APP_URL || 'http://localhost:3000'}/verify-email?token=${verificationCode}`;
                
                await pool.query(
                    'UPDATE users SET verification_token = $1, verification_token_expiry = NOW() + INTERVAL \'24 hours\' WHERE id = $2',
                    [verificationCode, user.id]
                );
                
                const userResult = await pool.query(
                    'SELECT name FROM users WHERE id = $1',
                    [user.id]
                );
                
                const userName = userResult.rows[0]?.name || name;
                await sendVerificationEmail(email, userName, verificationCode, verificationLink);
                
                return res.json({
                    success: true,
                    requiresVerification: true,
                    email: email,
                    message: 'Account already exists but not verified. New verification code sent.',
                    showVerificationPopup: true
                });
            }
            
            return res.status(400).json({
                success: false,
                error: 'Email already exists. Please log in.'
            });
        }
        
        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);
        
        // Generate verification code
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        // Create user with verification token
        const userResult = await pool.query(
            `INSERT INTO users (email, name, password_hash, verification_token, verification_token_expiry, 
                               trial_start, trial_end, user_identifier, created_at) 
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '30 days', $6, NOW()) 
             RETURNING id, email, name`,
            [email.toLowerCase(), name, passwordHash, verificationCode, verificationTokenExpiry, email.toLowerCase()]
        );
        
        const user = userResult.rows[0];
        
        // Send verification email via SMTP2GO
        const verificationLink = `${process.env.APP_URL || 'http://localhost:3000'}/verify-email?token=${verificationCode}`;
        const emailSent = await sendVerificationEmail(email, name, verificationCode, verificationLink);
        
        if (!emailSent) {
            console.error('Failed to send verification email, but user created');
        }
        
        res.json({
            success: true,
            requiresVerification: true,
            email: email,
            message: 'Account created successfully! Please check your email for the verification code.',
            showVerificationPopup: true
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        
        // Handle duplicate email error
        if (error.code === '23505') {
            return res.status(400).json({
                success: false,
                error: 'Email already exists. Please try logging in.'
            });
        }
        
        res.status(500).json({
            success: false,
            error: 'Registration failed. Please try again.'
        });
    }
});
// Temporary token for unverified users (development only)

app.post('/api/auth/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email || !email.includes('@')) {
            return res.status(400).json({
                success: false,
                error: 'Valid email address required'
            });
        }

        console.log('🔄 Resending verification to:', email);

        // Find user
        const result = await pool.query(
            `SELECT id, name, is_verified 
             FROM users 
             WHERE LOWER(email) = LOWER($1) 
             LIMIT 1`,
            [email.toLowerCase()]
        );

        if (result.rows.length === 0) {
            // Don't reveal if user exists (security)
            return res.json({
                success: true,
                message: 'If your email exists, a verification code will be sent.'
            });
        }

        const user = result.rows[0];

        if (user.is_verified) {
            return res.json({
                success: true,
                message: 'Email is already verified.'
            });
        }

        // Generate new verification code
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

        // Update in database
        await pool.query(
            `UPDATE users 
             SET verification_token = $1, 
                 verification_token_expiry = $2 
             WHERE id = $3`,
            [verificationCode, verificationTokenExpiry, user.id]
        );

        // Send verification email
        const verificationLink = `${process.env.APP_URL || 'http://localhost:3000'}/verify-email?token=${verificationCode}`;
        const emailSent = await sendVerificationEmail(
            email, 
            user.name || email.split('@')[0], 
            verificationCode, 
            verificationLink
        );

        if (emailSent) {
            res.json({
                success: true,
                message: 'New verification code sent to your email.',
                email: email
            });
        } else {
            res.status(500).json({
                success: false,
                error: 'Failed to send verification email. Please try again.'
            });
        }

    } catch (error) {
        console.error('Resend verification error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to resend verification code'
        });
    }
});
app.post('/api/auth/verify-code', async (req, res) => {
    try {
        const { email, code } = req.body;

        if (!email || !code) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email and code are required' 
            });
        }

        console.log('🔍 Verifying code for:', email, 'Code:', code);

        // Lookup user by email and verification token
        const result = await pool.query(
            `SELECT id, email, name, verification_token_expiry 
             FROM users 
             WHERE LOWER(email) = LOWER($1) 
             AND verification_token = $2
             LIMIT 1`,
            [email.toLowerCase(), code]
        );

        if (result.rows.length === 0) {
            console.log('❌ Invalid code or email');
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid verification code' 
            });
        }

        const user = result.rows[0];

        // Check expiry
        if (user.verification_token_expiry && new Date(user.verification_token_expiry) < new Date()) {
            console.log('❌ Verification code expired');
            return res.status(400).json({ 
                success: false, 
                error: 'Verification code expired. Please request a new one.' 
            });
        }

        // Mark user as verified and clear token
        await pool.query(
            `UPDATE users 
             SET is_verified = true, 
                 verification_token = NULL, 
                 verification_token_expiry = NULL,
                 trial_start = COALESCE(trial_start, NOW()),
                 trial_end = COALESCE(trial_end, NOW() + INTERVAL '30 days')
             WHERE id = $1`,
            [user.id]
        );

        console.log('✅ User verified:', user.email);

        // Create full JWT token
        const authToken = jwt.sign(
            { 
                id: user.id, 
                email: user.email, 
                name: user.name,
                type: 'email' 
            },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            token: authToken,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                isVerified: true
            },
            message: 'Email verified successfully!'
        });

    } catch (error) {
        console.error('Verify code error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Verification failed. Please try again.' 
        });
    }
});
// Get the latest verification code

app.post('/api/auth/resend-code', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, error: 'Email is required' });

        // Find user
        const result = await pool.query(
            `SELECT id, name, is_verified FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1`,
            [email.toLowerCase()]
        );

        if (result.rows.length === 0) {
            // Security: respond with success message to avoid revealing user existence
            return res.json({ success: true, message: 'If your email exists, a verification code will be sent.' });
        }

        const user = result.rows[0];
        if (user.is_verified) {
            return res.json({ success: true, message: 'Account already verified' });
        }

        // Generate new code and expiry
        const newCode = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

        await pool.query(
            `UPDATE users SET verification_token = $1, verification_token_expiry = $2 WHERE id = $3`,
            [newCode, verificationTokenExpiry, user.id]
        );

        const verificationLink = `${process.env.APP_URL || 'http://localhost:3000'}/verify-email?token=${newCode}`;
        await sendVerificationEmail(email, user.name || email.split('@')[0], newCode, verificationLink);

        res.json({ success: true, message: 'Verification code resent if the email exists' });

    } catch (error) {
        console.error('Resend code error:', error);
        res.status(500).json({ success: false, error: 'Failed to resend code' });
    }
});


/* ============================================================
   EXISTING AUTH LOGIN (unchanged except uses verification flags)
============================================================ */

// Replace /api/auth/login endpoint in server.js with this:
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        console.log('🔐 Login attempt for:', email);
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false,
                error: 'Email and password are required'
            });
        }

        // Check if user exists
        const result = await pool.query(
            'SELECT id, email, password_hash, name, trial_end, is_verified, verification_token FROM users WHERE LOWER(email) = LOWER($1)',
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ 
                success: false,
                error: 'Invalid email or password'
            });
        }

        const user = result.rows[0];
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash || '');
        
        if (!validPassword) {
            return res.status(401).json({ 
                success: false,
                error: 'Invalid email or password'
            });
        }
        
        // ✅ FIX: Check if email is verified
        if (!user.is_verified) {
            console.log('⚠️ Unverified user attempting to login:', email);
            
            // Generate new verification code
            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            const verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
            
            // Update verification token in database
            await pool.query(
                'UPDATE users SET verification_token = $1, verification_token_expiry = $2 WHERE id = $3',
                [verificationCode, verificationTokenExpiry, user.id]
            );
            
            // Send verification email
            const verificationLink = `${process.env.APP_URL || 'http://localhost:3000'}/verify-email?token=${verificationCode}`;
            const emailSent = await sendVerificationEmail(email, user.name, verificationCode, verificationLink);
            
            if (!emailSent) {
                console.error('⚠️ Failed to send verification email');
            }
            
            // ✅ CRITICAL: Return proper response to trigger frontend modal
            return res.status(401).json({ 
                success: false,
                requiresVerification: true,
                showVerificationPopup: true,
                email: email,
                verification_code: verificationCode, // For dev mode
                message: 'Please verify your email. A verification code has been sent.',
                error: 'Email verification required'
            });
        }

        // User is verified - create token
        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                name: user.name,
                trialEnd: user.trial_end
            },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        // ✅ CORRECT: Return success response
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                trialEnd: user.trial_end,
                isVerified: true
            }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Login failed. Please try again.' 
        });
    }
});
/* ===================== HELPER FUNCTIONS ===================== */

async function getUserById(userId) {
    try {
        const result = await pool.query(
            'SELECT id, email, name, trial_end FROM users WHERE id = $1',
            [userId]
        );
        return result.rows[0] || null;
    } catch (error) {
        console.error('Error getting user by ID:', error);
        return null;
    }
}

app.get('/api/auth/verify', async (req, res) => {
    try {
        // 1️⃣ Try JWT (manual login)
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            const user = await getUserById(decoded.id);
            if (!user) {
                return res.json({ success: false });
            }

            return res.json({
                success: true,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name
                }
            });
        }

        // 2️⃣ Try Google session (OAuth)
        if (req.user) {
            return res.json({
                success: true,
                user: {
                    id: req.user.id,
                    email: req.user.email,
                    name: req.user.name
                }
            });
        }

        // 3️⃣ No auth
        return res.json({ success: false });

    } catch (err) {
        console.error('Auth verify error:', err);
        return res.json({ success: false });
    }
});



/* ============================================================
   🔑 LOGIN
   NOTE: updated to use password_hash column
============================================================ */
// Manual verification for development


app.post('/api/auth/verify-email', async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ 
                success: false, 
                error: 'Token is required' 
            });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fastfoodinsight-secret-key-2024');
        
        const userResult = await pool.query(
            'SELECT id, email, name, trial_end FROM users WHERE id = $1',
            [decoded.id]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ 
                success: false, 
                error: 'User not found' 
            });
        }
        
        // Create long-lived session token
        const sessionToken = jwt.sign(
            {
                id: userResult.rows[0].id,
                email: userResult.rows[0].email
            },
            process.env.JWT_SECRET || 'fastfoodinsight-secret-key-2024',
            { expiresIn: '7d' }
        );
        
        res.json({
            success: true,
            token: sessionToken,
            user: userResult.rows[0]
        });
        
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(401).json({ 
            success: false, 
            error: 'Invalid or expired token' 
        });
    }
});


/* ============================================================
   💬 CHAT ENDPOINT (LIMIT ENFORCED)
   NOTE: this earlier simple chat endpoint remains but you'll
   have an enhanced /api/chat later in the file that replaces it.
   Keeping it here (as you originally had) but it has been left
   as-is functionally.
============================================================ */


// Google OAuth client
// In server.js, around line 21

// Professional branding
const BRANDING = {
    name: "FastFoodInsight AI",
    tagline: "World's Largest Fast Food Nutrition Database",
    stats: "23,000+ items • 9 global chains • 100+ countries"
};

const HEALTH_THRESHOLDS = {
    weight_loss: { calories: 500, focus: 'Calorie Control', emoji: '🏃' },
    weight_gain: { protein: 20, calories: 400, focus: 'Protein Focus', emoji: '💪' },
    diabetes: { sugar: 12, carbs: 40, focus: 'Sugar Control', emoji: '🩺' },
    bp: { sodium: 600, focus: 'Sodium Control', emoji: '❤️' },
    heart: { cholesterol: 100, saturated_fat: 10, focus: 'Heart Health', emoji: '❤️' },
    basic: { focus: 'Nutrition Details', emoji: '📊' }
};

// ALL COUNTRIES DATABASE
const ALL_COUNTRIES = [
    'United States', 'United Kingdom', 'Canada', 'Australia', 'India', 'Pakistan',
    'Germany', 'France', 'Japan', 'UAE', 'China', 'Mexico', 'Brazil', 'Spain',
    'Italy', 'South Korea', 'Russia', 'Turkey', 'Saudi Arabia', 'South Africa',
    'Thailand', 'Vietnam', 'Indonesia', 'Malaysia', 'Philippines', 'Singapore',
    'Hong Kong', 'Taiwan', 'New Zealand', 'Ireland', 'Netherlands', 'Belgium',
    'Switzerland', 'Austria', 'Sweden', 'Norway', 'Denmark', 'Finland',
    'Poland', 'Czech Republic', 'Hungary', 'Romania', 'Greece', 'Portugal',
    'Israel', 'Egypt', 'Morocco', 'Argentina', 'Chile', 'Colombia', 'Peru',
    'Venezuela', 'Costa Rica', 'Panama', 'Jamaica', 'Bahrain', 'Qatar', 'Kuwait',
    'Oman', 'Jordan', 'Lebanon', 'Bangladesh', 'Sri Lanka', 'Nepal', 'Myanmar',
    'Cambodia', 'Laos', 'Mongolia', 'Kazakhstan', 'Ukraine', 'Belarus', 'Serbia',
    'Croatia', 'Slovenia', 'Slovakia', 'Bulgaria', 'Estonia', 'Latvia', 'Lithuania',
    'Iceland', 'Luxembourg', 'Malta', 'Cyprus', 'Algeria', 'Tunisia', 'Kenya',
    'Nigeria', 'Ghana', 'Ethiopia', 'Uganda', 'Tanzania', 'Zimbabwe', 'Mozambique',
    'Angola', 'Namibia', 'Botswana', 'Mauritius', 'Madagascar', 'Fiji', 'Papua New Guinea',
    'Samoa', 'Tonga', 'Solomon Islands', 'Vanuatu', 'New Caledonia'
];

// KEEP ALL YOUR EXISTING FUNCTIONS EXACTLY AS THEY ARE
// Keep extractQueryEntities, getBranchLocationId, getNutritionData, 
// createNutritionTable, formatProfessionalResponse functions from your original code

function extractQueryEntities(message) {
    const lowerMsg = message.toLowerCase().trim();
    const entities = {
        branch: null,
        country: null,
        foodItem: null,
        queryType: 'basic',
        goal: 'basic',
        itemType: 'any' // 'food', 'drink', or 'any'
    };
    
    // Detect if user is asking specifically for drinks or food
    if (/(drink|beverage|soda|coffee|tea|juice|smoothie|milkshake|soft.?drink|energy.?drink)/i.test(lowerMsg)) {
        entities.itemType = 'drink';
    }
    if (/(food|meal|burger|pizza|sandwich|wrap|salad|nuggets|chicken|fries)/i.test(lowerMsg) && !entities.itemType) {
        entities.itemType = 'food';
    }
    
    // Detect query type
    if (/(diabet|sugar|glucose|a1c)/i.test(lowerMsg)) {
        entities.queryType = 'diabetes';
        entities.goal = 'diabetes';
    }
    if (/(blood.?pressure|hypertension|bp|sodium|salt)/i.test(lowerMsg)) {
        entities.queryType = 'bp';
        entities.goal = 'bp';
    }
    if (/(weight.?loss|lose.?weight|dieting|low.?calorie|calorie.?control|slimming)/i.test(lowerMsg)) {
        entities.queryType = 'weight_loss';
        entities.goal = 'weight_loss';
    }
    if (/(gain.?weight|muscle.?gain|bulk|bulking|high.?protein|bodybuilding|athlete)/i.test(lowerMsg)) {
        entities.queryType = 'weight_gain';
        entities.goal = 'weight_gain';
    }
    if (/(heart|cholesterol|cardio|cardiovascular)/i.test(lowerMsg)) {
        entities.queryType = 'heart';
        entities.goal = 'heart';
    }
    if (/(unhealthy|worst|avoid|limit|skip|bad|junk|poor)/i.test(lowerMsg)) {
        entities.queryType = 'avoid';
    }
    if (/(best|healthy|recommend|top|popular|favorite)/i.test(lowerMsg)) {
        entities.queryType = 'best';
    }
    if (/(compare|ranking|rank|highest|lowest|most|least)/i.test(lowerMsg)) {
        entities.queryType = 'compare';
    }
    if (/(vegetarian|vegan|gluten.?free|dairy.?free|halal|kosher)/i.test(lowerMsg)) {
        entities.queryType = 'dietary';
    }
    
    // Restaurant detection
    const branchPatterns = [
        { pattern: /mcdonald|mcd|mc donald/, name: 'McDonalds' },
        { pattern: /kfc|kentucky/, name: 'KFC' },
        { pattern: /burger king|bk/, name: 'Burger King' },
        { pattern: /starbucks/, name: 'Starbucks' },
        { pattern: /pizza hut/, name: 'Pizza Hut' },
        { pattern: /domino/, name: 'Dominos' },
        { pattern: /taco bell/, name: 'Taco Bell' },
        { pattern: /wendy/, name: 'Wendys' },
        { pattern: /dunkin/, name: 'Dunkin' }
    ];
    
    for (const branch of branchPatterns) {
        if (branch.pattern.test(lowerMsg)) {
            entities.branch = branch.name;
            break;
        }
    }
    
    // Country detection from ALL_COUNTRIES
    for (const country of ALL_COUNTRIES) {
        const countryLower = country.toLowerCase();
        const patterns = [
            countryLower,
            countryLower.replace(/\s+/g, ''),
            countryLower.replace(/\s+/g, '.?')
        ];
        
        for (const pattern of patterns) {
            const regex = new RegExp(`\\b${pattern}\\b`, 'i');
            if (regex.test(lowerMsg)) {
                entities.country = country;
                break;
            }
        }
        if (entities.country) break;
    }
    
    // Special country abbreviations
    const countryAbbr = {
        'usa': 'United States', 'us': 'United States', 'america': 'United States',
        'uk': 'United Kingdom', 'britain': 'United Kingdom', 'england': 'United Kingdom',
        'uae': 'UAE', 'emirates': 'UAE',
        'u.k.': 'United Kingdom', 'u.s.': 'United States', 'u.s.a.': 'United States'
    };
    
    for (const [abbr, fullName] of Object.entries(countryAbbr)) {
        if (lowerMsg.includes(abbr)) {
            entities.country = fullName;
            break;
        }
    }
    
    // SMART FOOD ITEM EXTRACTION - DYNAMIC, NOT PREDEFINED
    // Remove common query words to extract the actual food item
    let queryWords = lowerMsg.split(/\s+/);
    
    // Remove stop words and query patterns
    const stopWords = [
        'at', 'in', 'from', 'for', 'with', 'and', 'or', 'the', 'a', 'an',
        'nutrition', 'calories', 'protein', 'fat', 'carbs', 'sugar', 'sodium',
        'healthy', 'unhealthy', 'best', 'worst', 'low', 'high', 'options',
        'items', 'food', 'foods', 'drink', 'drinks', 'beverage', 'beverages',
        'mcdonalds', 'kfc', 'burger king', 'starbucks', 'pizza hut', 'dominos',
        'taco bell', 'wendys', 'dunkin',
        'usa', 'uk', 'canada', 'australia', 'india', 'pakistan', 'germany',
        'france', 'japan', 'uae', 'china', 'mexico'
    ];
    
    // Also remove country names
    ALL_COUNTRIES.forEach(country => {
        stopWords.push(country.toLowerCase());
    });

    // Filter out stop words
    let potentialFoodWords = queryWords.filter(word => 
        !stopWords.includes(word.toLowerCase()) && 
        word.length > 2
    );
    
    // Join remaining words as potential food item
    if (potentialFoodWords.length > 0) {
        entities.foodItem = potentialFoodWords.join(' ');
        
        // Check if it's a generic term
        const genericTerms = ['nutrition', 'calories', 'protein', 'fat', 'carbs', 'sugar', 'sodium'];
        if (genericTerms.some(term => entities.foodItem.includes(term))) {
            entities.foodItem = 'general';
        }
    }
    
    // If no specific food found, check for general queries
    if (!entities.foodItem || entities.foodItem === '') {
        if (lowerMsg.includes('nutrition') || lowerMsg.includes('calories') || 
            lowerMsg.includes('protein') || lowerMsg.includes('fat') ||
            lowerMsg.includes('carbs') || lowerMsg.includes('sugar') || 
            lowerMsg.includes('sodium')) {
            entities.foodItem = 'general';
        }
    }
    
    // If user specifically asked for "drinks" or "drink" without specifying which drink
    if ((lowerMsg.includes('drinks') || lowerMsg.includes('drink')) && (!entities.foodItem || entities.foodItem === 'general')) {
        entities.foodItem = 'drink';
        entities.itemType = 'drink';
    }
    
    // If user specifically asked for "food" or "foods" without specifying which food
    if ((lowerMsg.includes('foods') || lowerMsg.includes('food')) && (!entities.foodItem || entities.foodItem === 'general') && !entities.itemType) {
        entities.foodItem = 'food';
        entities.itemType = 'food';
    }
    
    // Clean up the food item
    if (entities.foodItem && entities.foodItem !== 'general' && entities.foodItem !== 'drink' && entities.foodItem !== 'food') {
        // Remove any remaining common prefixes/suffixes
        entities.foodItem = entities.foodItem
            .replace(/^(what|how|show|give|find|search|get|tell)\s+/i, '')
            .replace(/\s+(please|thanks|thank you)$/i, '')
            .trim();
        
        // If after cleaning it's empty or too short, set to general
        if (entities.foodItem.length < 2) {
            entities.foodItem = 'general';
        }
    }
    
    console.log('Extracted food item:', entities.foodItem);
    return entities;
}

// Get branch location ID
async function getBranchLocationId(branchName, countryName) {
    try {
        const query = `
            SELECT bl.id 
            FROM branch_locations bl
            JOIN branches b ON bl.branch_id = b.id
            JOIN countries c ON bl.country_id = c.id
            WHERE b.name = $1 AND c.name = $2
            LIMIT 1
        `;
        
        const result = await pool.query(query, [branchName, countryName]);
        
        if (result.rows.length > 0) {
            return result.rows[0].id;
        } else {
            // Try case-insensitive search
            const query2 = `
                SELECT bl.id 
                FROM branch_locations bl
                JOIN branches b ON bl.branch_id = b.id
                JOIN countries c ON bl.country_id = c.id
                WHERE LOWER(b.name) = LOWER($1) AND LOWER(c.name) = LOWER($2)
                LIMIT 1
            `;
            const result2 = await pool.query(query2, [branchName, countryName]);
            return result2.rows.length > 0 ? result2.rows[0].id : null;
        }
    } catch (error) {
        console.error('Error getting branch location:', error.message);
        return null;
    }
}

// Get nutrition data with advanced filtering - FIXED: Removed fiber column
// Get nutrition data with smart filtering - PRIORITIZE COMPLETE DATA
// Get nutrition data with smart filtering - FIXED SQL SYNTAX
// Get nutrition data with flexible search - UPDATED
async function getNutritionData(entities, limit = 10) {
    try {
        const branchLocationId = await getBranchLocationId(entities.branch, entities.country);
        
        if (!branchLocationId) {
            console.log(`No branch location found for ${entities.branch} in ${entities.country}`);
            return []; // Return empty array instead of throwing error
        }
        
        // Build base query
        let baseSql = `
            SELECT 
                f.id,
                f.name,
                f.calories,
                f.protein,
                f.sugars,
                f.sodium,
                f.carbohydrates,
                f.total_fat,
                f.saturated_fat,
                f.trans_fat,
                f.cholesterol,
                f.serving_size,
                v.ffi_score,
                c.name as country_name,
                b.name as branch_name,
                -- Calculate completeness score: 1 for each non-null nutrition field
                CASE 
                    WHEN f.calories IS NOT NULL AND f.calories > 0 THEN 1 ELSE 0 
                END +
                CASE 
                    WHEN f.protein IS NOT NULL THEN 1 ELSE 0 
                END +
                CASE 
                    WHEN f.sugars IS NOT NULL THEN 1 ELSE 0 
                END +
                CASE 
                    WHEN f.sodium IS NOT NULL THEN 1 ELSE 0 
                END +
                CASE 
                    WHEN f.carbohydrates IS NOT NULL THEN 1 ELSE 0 
                END +
                CASE 
                    WHEN f.total_fat IS NOT NULL THEN 1 ELSE 0 
                END +
                CASE 
                    WHEN f.saturated_fat IS NOT NULL THEN 1 ELSE 0 
                END as completeness_score,
                -- Calculate similarity score for food item search
                CASE 
                    WHEN f.name ILIKE $${entities.foodItem && entities.foodItem !== 'general' && entities.foodItem !== 'drink' && entities.foodItem !== 'food' ? 2 : 1} THEN 100
                    WHEN f.name ILIKE $${entities.foodItem && entities.foodItem !== 'general' && entities.foodItem !== 'drink' && entities.foodItem !== 'food' ? 3 : 2} THEN 80
                    WHEN f.name ILIKE $${entities.foodItem && entities.foodItem !== 'general' && entities.foodItem !== 'drink' && entities.foodItem !== 'food' ? 4 : 3} THEN 60
                    ELSE 0
                END as similarity_score
            FROM food_items f
            LEFT JOIN view_food_items_ffi v ON f.id = v.id
            JOIN branch_locations bl ON f.branch_location_id = bl.id
            JOIN branches b ON bl.branch_id = b.id
            JOIN countries c ON bl.country_id = c.id
            WHERE f.branch_location_id = $1
            AND f.calories IS NOT NULL
            AND f.calories > 0
        `;
        
        const params = [branchLocationId];
        let paramIndex = 2;
        
        // Add food/drink type filtering
        if (entities.itemType === 'drink') {
            // Filter for drinks
            baseSql += ` AND (
                f.name ILIKE '%drink%' OR 
                f.name ILIKE '%soda%' OR 
                f.name ILIKE '%coffee%' OR 
                f.name ILIKE '%tea%' OR 
                f.name ILIKE '%juice%' OR 
                f.name ILIKE '%smoothie%' OR 
                f.name ILIKE '%milkshake%' OR 
                f.name ILIKE '%shake%' OR 
                f.name ILIKE '%beverage%' OR
                f.name ILIKE '%coke%' OR
                f.name ILIKE '%pepsi%' OR
                f.name ILIKE '%fanta%' OR
                f.name ILIKE '%sprite%' OR
                f.name ILIKE '%lemonade%' OR
                f.name ILIKE '%water%' OR
                f.name ILIKE '%latte%' OR
                f.name ILIKE '%cappuccino%' OR
                f.name ILIKE '%espresso%' OR
                f.name ILIKE '%frappuccino%' OR
                f.name ILIKE '%mocha%'
            )`;
        } else if (entities.itemType === 'food') {
            // Filter for food (exclude drinks)
            baseSql += ` AND NOT (
                f.name ILIKE '%drink%' OR 
                f.name ILIKE '%soda%' OR 
                f.name ILIKE '%coffee%' OR 
                f.name ILIKE '%tea%' OR 
                f.name ILIKE '%juice%' OR 
                f.name ILIKE '%smoothie%' OR 
                f.name ILIKE '%milkshake%' OR 
                f.name ILIKE '%shake%' OR 
                f.name ILIKE '%beverage%' OR
                f.name ILIKE '%coke%' OR
                f.name ILIKE '%pepsi%' OR
                f.name ILIKE '%fanta%' OR
                f.name ILIKE '%sprite%' OR
                f.name ILIKE '%lemonade%' OR
                f.name ILIKE '%water%' OR
                f.name ILIKE '%latte%' OR
                f.name ILIKE '%cappuccino%' OR
                f.name ILIKE '%espresso%' OR
                f.name ILIKE '%frappuccino%' OR
                f.name ILIKE '%mocha%'
            )`;
        }
        
        // Add food item filter with flexible matching
        if (entities.foodItem && entities.foodItem !== 'general' && entities.foodItem !== 'drink' && entities.foodItem !== 'food') {
            // Add multiple search patterns for better matching
            params.push(`%${entities.foodItem}%`); // Exact phrase
            params.push(`%${entities.foodItem.split(' ')[0]}%`); // First word
            if (entities.foodItem.includes(' ')) {
                params.push(`%${entities.foodItem.split(' ').pop()}%`); // Last word
            } else {
                params.push(`%${entities.foodItem}%`); // Same as first if single word
            }
            paramIndex += 3;
        }
        
        // Apply filters based on query type
        switch (entities.queryType) {
            case 'diabetes':
                baseSql += ` AND f.sugars <= 12 AND f.carbohydrates <= 40`;
                break;
            case 'bp':
                baseSql += ` AND f.sodium <= 600`;
                break;
            case 'weight_loss':
                baseSql += ` AND f.calories <= 500`;
                break;
            case 'weight_gain':
                baseSql += ` AND f.protein >= 20 AND f.calories >= 300`;
                break;
            case 'heart':
                baseSql += ` AND f.cholesterol <= 100 AND f.saturated_fat <= 10`;
                break;
        }
        
        // First: Get COMPLETE items (all 7 nutrition fields populated)
        // Order by similarity score first (if searching for specific item), then completeness, then FFI
        let completeItemsSql = baseSql + ` 
            AND f.calories IS NOT NULL 
            AND f.protein IS NOT NULL 
            AND f.sugars IS NOT NULL 
            AND f.sodium IS NOT NULL 
            AND f.carbohydrates IS NOT NULL 
            AND f.total_fat IS NOT NULL 
            AND f.saturated_fat IS NOT NULL 
            ORDER BY similarity_score DESC, v.ffi_score DESC 
            LIMIT $${paramIndex}`;
        
        const completeParams = [...params, limit];
        const completeResult = await pool.query(completeItemsSql, completeParams);
        
        console.log(`Found ${completeResult.rows.length} COMPLETE ${entities.itemType === 'drink' ? 'DRINKS' : entities.itemType === 'food' ? 'FOODS' : 'ITEMS'}`);
        
        // If we have enough complete items, return them
        if (completeResult.rows.length >= limit) {
            return completeResult.rows.slice(0, limit);
        }
        
        // If we need more items, get partial items
        const neededItems = limit - completeResult.rows.length;
        
        // Second: Get items with MOST COMPLETE data (but not necessarily all 7 fields)
        let partialItemsSql = baseSql + ` 
            AND NOT (
                f.calories IS NOT NULL 
                AND f.protein IS NOT NULL 
                AND f.sugars IS NOT NULL 
                AND f.sodium IS NOT NULL 
                AND f.carbohydrates IS NOT NULL 
                AND f.total_fat IS NOT NULL 
                AND f.saturated_fat IS NOT NULL
            )
            ORDER BY similarity_score DESC, completeness_score DESC, v.ffi_score DESC 
            LIMIT $${paramIndex}`;
        
        const partialParams = [...params, neededItems];
        const partialResult = await pool.query(partialItemsSql, partialParams);
        
        console.log(`Found ${partialResult.rows.length} PARTIAL items to complete the list`);
        
        // Combine complete and partial items
        const allItems = [...completeResult.rows, ...partialResult.rows];
        
        // Sort by similarity score first, then completeness score, then by FFI score
        allItems.sort((a, b) => {
            // First sort by similarity (for specific item searches)
            if (b.similarity_score !== a.similarity_score) {
                return b.similarity_score - a.similarity_score;
            }
            // Then by completeness
            if (b.completeness_score !== a.completeness_score) {
                return b.completeness_score - a.completeness_score;
            }
            // Finally by FFI score
            return (b.ffi_score || 0) - (a.ffi_score || 0);
        });
        
        return allItems.slice(0, limit);
        
    } catch (error) {
         console.error('Database error in getNutritionData:', error.message);
        console.error('Full error:', error);
        return []; // Return empty array on error
    }
}

// Create beautiful HTML table - FIXED: Removed fiber references
// Create beautiful HTML table - HANDLE PARTIAL DATA BETTER
function createNutritionTable(items, detailed = false) {
    if (items.length === 0) return '';
    
    let tableHTML = '<table style="width: 100%; border-collapse: collapse; margin: 20px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">';
    
    // Table header
    if (detailed) {
        tableHTML += `
            <thead style="background: linear-gradient(135deg, #2D3047 0%, #1a1c2b 100%); color: white;">
                <tr>
                    <th style="padding: 12px 15px; text-align: left; border-bottom: 2px solid #FF6B35;">Item</th>
                    <th style="padding: 12px 15px; text-align: center;">Calories</th>
                    <th style="padding: 12px 15px; text-align: center;">Protein (g)</th>
                    <th style="padding: 12px 15px; text-align: center;">Fat (g)</th>
                    <th style="padding: 12px 15px; text-align: center;">Carbs (g)</th>
                    <th style="padding: 12px 15px; text-align: center;">Sugar (g)</th>
                    <th style="padding: 12px 15px; text-align: center;">Sodium (mg)</th>
                    <th style="padding: 12px 15px; text-align: center;">FFI Score</th>
                </tr>
            </thead>
        `;
    } else {
        tableHTML += `
            <thead style="background: linear-gradient(135deg, #2D3047 0%, #1a1c2b 100%); color: white;">
                <tr>
                    <th style="padding: 12px 15px; text-align: left; border-bottom: 2px solid #FF6B35;">Nutrient</th>
                    <th style="padding: 12px 15px; text-align: center;">Amount</th>
                    <th style="padding: 12px 15px; text-align: center;">Daily Value %</th>
                </tr>
            </thead>
        `;
    }
    
    // Table body
    tableHTML += '<tbody>';
    
    if (detailed) {
        items.forEach((item, index) => {
            const ffiScore = parseFloat(item.ffi_score) || 0;
            const ffiColor = ffiScore >= 70 ? '#10B981' : 
                           ffiScore >= 40 ? '#F59E0B' : 
                           '#EF4444';
            const ffiIcon = ffiScore >= 70 ? '🟢' :
                           ffiScore >= 40 ? '🟡' : 
                           '🔴';
            
            // Check if this is a "partial" item (has some N/A values)
            const isPartialItem = item.completeness_score < 7;
            const rowStyle = isPartialItem ? 'background: #FFF8E1;' : 
                            (index % 2 === 0 ? 'background: #F8FAFC;' : 'background: white;');
            const partialIndicator = isPartialItem ? ' ⚠️' : '';
            
            tableHTML += `
                <tr style="${rowStyle}">
                    <td style="padding: 10px 15px; border-bottom: 1px solid #E5E7EB;">
                        <strong>${item.name}</strong>${partialIndicator}
                    </td>
                    <td style="padding: 10px 15px; text-align: center; border-bottom: 1px solid #E5E7EB;">
                        ${item.calories || '-'}
                    </td>
                    <td style="padding: 10px 15px; text-align: center; border-bottom: 1px solid #E5E7EB;">
                        ${item.protein || '-'}
                    </td>
                    <td style="padding: 10px 15px; text-align: center; border-bottom: 1px solid #E5E7EB;">
                        ${item.total_fat || '-'}
                    </td>
                    <td style="padding: 10px 15px; text-align: center; border-bottom: 1px solid #E5E7EB;">
                        ${item.carbohydrates || '-'}
                    </td>
                    <td style="padding: 10px 15px; text-align: center; border-bottom: 1px solid #E5E7EB;">
                        ${item.sugars || '-'}
                    </td>
                    <td style="padding: 10px 15px; text-align: center; border-bottom: 1px solid #E5E7EB;">
                        ${item.sodium || '-'}
                    </td>
                    <td style="padding: 10px 15px; text-align: center; border-bottom: 1px solid #E5E7EB; color: ${ffiColor}; font-weight: bold;">
                        ${ffiScore || 0} ${ffiIcon}
                    </td>
                </tr>
            `;
        });
    } else {
        // Single item detailed view
        const item = items[0];
        const isPartialItem = item.completeness_score < 7;
        
        const nutrients = [
            { name: 'Calories', value: item.calories, unit: 'kcal', dv: 2000 },
            { name: 'Protein', value: item.protein, unit: 'g', dv: 50 },
            { name: 'Total Fat', value: item.total_fat, unit: 'g', dv: 65 },
            { name: 'Saturated Fat', value: item.saturated_fat, unit: 'g', dv: 20 },
            { name: 'Trans Fat', value: item.trans_fat || 0, unit: 'g', dv: null },
            { name: 'Cholesterol', value: item.cholesterol, unit: 'mg', dv: 300 },
            { name: 'Sodium', value: item.sodium, unit: 'mg', dv: 2300 },
            { name: 'Carbohydrates', value: item.carbohydrates, unit: 'g', dv: 300 },
            { name: 'Sugar', value: item.sugars, unit: 'g', dv: 50 }
        ];
        
        nutrients.forEach((nutrient, index) => {
            const value = nutrient.value;
            const hasValue = value !== null && value !== undefined;
            const dvPercent = hasValue && nutrient.dv ? Math.round((value / nutrient.dv) * 100) : '-';
            const rowStyle = !hasValue ? 'background: #FFF8E1;' : 
                           (index % 2 === 0 ? 'background: #F8FAFC;' : 'background: white;');
            
            tableHTML += `
                <tr style="${rowStyle}">
                    <td style="padding: 10px 15px; border-bottom: 1px solid #E5E7EB;">
                        <strong>${nutrient.name}</strong>${!hasValue ? ' ⚠️' : ''}
                    </td>
                    <td style="padding: 10px 15px; text-align: center; border-bottom: 1px solid #E5E7EB;">
                        ${hasValue ? `${value} ${nutrient.unit}` : 'Data not available'}
                    </td>
                    <td style="padding: 10px 15px; text-align: center; border-bottom: 1px solid #E5E7EB;">
                        ${dvPercent}${dvPercent !== '-' ? '%' : ''}
                    </td>
                </tr>
            `;
        });
        
        // Add FFI score row
        const ffiScore = parseFloat(item.ffi_score) || 0;
        const ffiColor = ffiScore >= 70 ? '#10B981' : 
                       ffiScore >= 40 ? '#F59E0B' : 
                       '#EF4444';
        const ffiIcon = ffiScore >= 70 ? '🟢' :
                       ffiScore >= 40 ? '🟡' : 
                       '🔴';
        
        tableHTML += `
            <tr style="background: linear-gradient(135deg, #F8FAFC 0%, #F1F5F9 100%);">
                <td style="padding: 10px 15px;">
                    <strong>FFI Score</strong>
                </td>
                <td style="padding: 10px 15px; text-align: center; color: ${ffiColor}; font-weight: bold;">
                    ${ffiScore}/100
                </td>
                <td style="padding: 10px 15px; text-align: center;">
                    ${ffiIcon} ${ffiScore >= 70 ? 'Excellent' : ffiScore >= 40 ? 'Good' : 'Poor'}
                </td>
            </tr>
        `;
    }
    
    tableHTML += '</tbody></table>';
    
    // Add note if there are partial items
    const hasPartialItems = items.some(item => item.completeness_score < 7);
    if (hasPartialItems) {
        tableHTML += `<p style="margin-top: 10px; font-size: 12px; color: #F59E0B;">
            ⚠️ Items marked with warning symbol have incomplete nutrition data. Complete data items are prioritized.
        </p>`;
    }
    
    return tableHTML;
}

// Format professional response
// Format professional response
// Format professional response - UPDATED with drink/food headers
// Format professional response as HTML
function formatProfessionalResponse(items, entities) {
    if (items.length === 0) {
        // Try to give more helpful suggestions (HTML version)
        const suggestions = [
            "Try checking if the item exists in that country",
            "Try a different restaurant chain",
            "Try asking for general recommendations",
            "Check if you spelled the item correctly"
        ];

        let response = `<h1 style="color:#FF6B35;">🔍 No Results Found</h1>\n\n`;
        response += `<p>I searched for <strong>${entities.foodItem || 'items'}</strong> at <strong>${entities.branch}</strong> in <strong>${entities.country}</strong> but couldn't find any matching items.</p>\n\n`;

        response += `<p><strong>Possible reasons:</strong></p>\n<ul>`;
        suggestions.forEach(suggestion => {
            response += `<li>${suggestion}</li>\n`;
        });
        response += `</ul>\n\n`;

        response += `<p><strong>Try these formats instead:</strong></p>\n<ul>`;
        response += `<li>Big Mac at McDonalds in USA</li>\n`;
        response += `<li>Zinger Burger at KFC in Pakistan</li>\n`;
        response += `<li>Coffee at Starbucks in Australia</li>\n`;
        response += `<li>Popular items at ${entities.branch} in ${entities.country}</li>\n`;
        response += `</ul>\n\n`;

        response += `<p><em>Searching across 23,000+ items in FastFoodInsight database</em></p>`;
        return response;
    }

    const goalInfo = HEALTH_THRESHOLDS[entities.goal] || HEALTH_THRESHOLDS.basic;
    const goalNames = {
        weight_loss: 'Weight Loss',
        weight_gain: 'Muscle Gain', 
        diabetes: 'Diabetes Management',
        bp: 'Blood Pressure Control',
        heart: 'Heart Health',
        basic: 'Nutrition Details'
    };

    // Create appropriate header based on item type
    let header = '';
    if (entities.itemType === 'drink') {
        header = `🥤 ${entities.foodItem === 'drink' ? 'Drinks' : entities.foodItem.charAt(0).toUpperCase() + entities.foodItem.slice(1)} - ${entities.branch} (${entities.country})`;
    } else if (entities.itemType === 'food') {
        header = `🍔 ${entities.foodItem === 'food' ? 'Food Items' : entities.foodItem.charAt(0).toUpperCase() + entities.foodItem.slice(1)} - ${entities.branch} (${entities.country})`;
    } else {
        header = `${goalInfo.emoji} ${entities.foodItem ? entities.foodItem.charAt(0).toUpperCase() + entities.foodItem.slice(1) : goalNames[entities.goal]} - ${entities.branch} (${entities.country})`;
    }

    let response = `<h1 style="color:#FF6B35; margin-bottom:0;">${header}</h1>\n\n`;

    // Query-specific introduction
    const queryTypes = {
        diabetes: `🍭 <strong>Diabetes Management:</strong> Showing items with low sugar content (<12g) suitable for diabetes control.`,
        bp: `🧂 <strong>Blood Pressure Friendly:</strong> Showing items with low sodium content (<600mg) for hypertension management.`,
        weight_loss: `⚖️ <strong>Weight Loss:</strong> Showing low-calorie options (<500 calories) for effective weight management.`,
        weight_gain: `💪 <strong>Muscle Gain:</strong> Showing high-protein options (>20g protein) for muscle building.`,
        heart: `❤️ <strong>Heart Health:</strong> Showing low-cholesterol and low-saturated fat options.`,
        avoid: `⚠️ <strong>Items to Limit:</strong> Showing items with lower FFI scores that should be consumed in moderation.`,
        best: `⭐ <strong>Top Recommendations:</strong> Showing items with highest FFI scores for optimal nutrition.`,
        basic: `📊 <strong>Nutrition Analysis:</strong> Detailed nutrition information for requested items.`
    };

    response += `<p>${queryTypes[entities.queryType] || queryTypes.basic}</p>\n\n`;

    // Count complete vs partial items
    const completeItems = items.filter(item => item.completeness_score === 7).length;
    const partialItems = items.filter(item => item.completeness_score < 7).length;

    if (partialItems > 0) {
        response += `<p><strong>Note:</strong> Showing ${completeItems} items with complete nutrition data and ${partialItems} items with partial data (marked with ⚠️). Complete data items are always prioritized.</p>\n\n`;
    }

    // Display items
    if (entities.foodItem && entities.foodItem !== 'general' && entities.foodItem !== 'drink' && entities.foodItem !== 'food' && items.length <= 3) {
        // Single or few items - detailed view
        response += `<h2>📋 Detailed Nutrition Information</h2>\n\n`;
        response += createNutritionTable(items, false);

        if (items[0].serving_size) {
            response += `\n<p><strong>Serving Size:</strong> ${items[0].serving_size}</p>\n`;
        }
    } else {
        // Multiple items - summary view
        const tableTitle = entities.itemType === 'drink' ? `Top ${items.length} Drinks` : 
                         entities.itemType === 'food' ? `Top ${items.length} Food Items` : 
                         `Top ${items.length} Items`;

        response += `<h2>📊 ${tableTitle}</h2>\n\n`;
        response += createNutritionTable(items, true);

        if (items.length >= 10) {
            response += `\n<p><strong>Note:</strong> Showing 10 items. ${partialItems > 0 ? `${partialItems} have partial data. ` : ''}Ask for "more items" to see additional options.</p>\n`;
        }
    }

    // Health recommendations
    response += `\n<h2>💡 Health Recommendations</h2>\n\n<ul>\n`;

    const recommendations = {
        diabetes: [
            '✅ Choose items with <12g sugar per serving',
            '✅ Monitor total carbohydrate intake',
            '✅ Pair with protein-rich foods for better blood sugar control',
            '❌ Avoid sugary drinks and desserts',
            '⚠️ Check portion sizes carefully'
        ],
        bp: [
            '✅ Select items with <600mg sodium',
            '✅ Look for potassium-rich options (when available)',
            '✅ Avoid extra salt and salty sauces',
            '❌ Limit processed and packaged foods',
            '💧 Drink plenty of water to help flush excess sodium'
        ],
        weight_loss: [
            '✅ Aim for items under 500 calories',
            '✅ Choose high-fiber options to stay full longer',
            '✅ Include lean protein in every meal',
            '❌ Avoid calorie-dense sauces and dressings',
            '🏃 Combine with regular physical activity'
        ],
        weight_gain: [
            '✅ Focus on protein-rich options (>20g per serving)',
            '✅ Include healthy fats for extra calories',
            '✅ Consider protein shakes or supplements if needed',
            '🏋️ Combine with strength training for optimal results',
            '📈 Track your daily calorie and protein intake'
        ],
        heart: [
            '✅ Choose items with <100mg cholesterol',
            '✅ Limit saturated fat to <10g per serving',
            '✅ Look for omega-3 rich options when available',
            '❌ Avoid trans fats completely',
            '❤️ Combine with regular cardiovascular exercise'
        ],
        basic: [
            '⭐ FFI Score of 70-100 indicates excellent nutritional balance',
            '📏 Pay attention to serving sizes',
            '🍎 Balance fast food with whole foods in your diet',
            '💧 Stay hydrated with water instead of sugary drinks',
            '📱 Use FastFoodInsight for all your nutrition queries'
        ]
    };

    const recList = recommendations[entities.goal] || recommendations.basic;
    recList.forEach(rec => {
        response += `  <li>${rec}</li>\n`;
    });
    response += `</ul>\n\n`;

    // FFI explanation (as a simple table)
    response += `<h2>📈 Understanding FFI Scores</h2>\n`;
    response += `<table style="width:100%; border-collapse:collapse; margin:10px 0;">\n`;
    response += `<thead><tr style="background:#2D3047; color:white;"><th>Score</th><th>Category</th><th>Meaning</th></tr></thead>\n`;
    response += `<tbody>\n`;
    response += `<tr style="background:#F8FAFC;"><td><strong>70-100</strong></td><td>🟢 Excellent</td><td>Optimal nutrient balance, great choice</td></tr>\n`;
    response += `<tr><td><strong>40-69</strong></td><td>🟡 Good</td><td>Moderate nutrition, suitable in moderation</td></tr>\n`;
    response += `<tr style="background:#F8FAFC;"><td><strong>0-39</strong></td><td>🔴 Poor</td><td>Consider portion control or alternatives</td></tr>\n`;
    response += `</tbody>\n</table>\n\n`;

    // Data quality note
    if (partialItems > 0) {
        response += `<h3>ℹ️ Data Quality Information</h3>\n<ul>\n`;
        response += `<li>Items marked with ⚠️ have incomplete nutrition data</li>\n`;
        response += `<li>Complete data items are always shown first</li>\n`;
        response += `<li>Partial items are only included when needed to reach 10 items</li>\n`;
        response += `<li>We continuously work to improve data completeness</li>\n`;
        response += `</ul>\n\n`;
    }

    // Footer
    response += `<hr>\n`;
    response += `<p><em>${BRANDING.stats} • Data from official nutrition guides</em><br>\n`;
    response += `<em>For specific dietary concerns, consult with a healthcare professional</em></p>\n`;

    return response;
}
// ============ NEW AUTHENTICATION & USAGE TRACKING FUNCTIONS ============

// Helper: Check message usage
// Helper: Check message usage (simplified)
// In server.js, find the checkMessageUsage function and ensure it has this logic:
async function checkMessageUsage(userId, anonymousId) {
    try {
        let query;
        let params;
        
        if (userId) {
            // Logged-in user
            query = `
                SELECT 
                    COALESCE(SUM(cu.message_count), 0) as total_messages,
                    u.trial_end,
                    CASE 
                        WHEN u.trial_end IS NULL THEN false
                        WHEN u.trial_end > NOW() THEN true
                        ELSE false
                    END as is_in_trial
                FROM users u
                LEFT JOIN chat_usage cu ON cu.user_id = u.id
                WHERE u.id = $1
                GROUP BY u.id, u.trial_end
            `;
            params = [userId];
        } else {
            // Anonymous user
            query = `
                SELECT COALESCE(SUM(message_count), 0) as total_messages
                FROM chat_usage
                WHERE anonymous_id = $1
                GROUP BY anonymous_id
            `;
            params = [anonymousId];
        }
        
        const result = await pool.query(query, params);
        const totalMessages = parseInt(result.rows[0]?.total_messages) || 0;
        const trialEnd = result.rows[0]?.trial_end;
        const isInTrial = result.rows[0]?.is_in_trial || false;
        
        console.log('Server usage check:', { userId, totalMessages, trialEnd, isInTrial });
        
        // Calculate limits
        const maxMessages = userId ? (isInTrial ? 999999 : 0) : 10;
        const remainingMessages = Math.max(0, maxMessages - totalMessages);
        const isBlocked = totalMessages >= maxMessages;
        
        return {
            totalMessages,
            remainingMessages,
            maxMessages,
            isInTrial,
            trialEnd,
            blocked: isBlocked,
            warningNeeded: !isBlocked && remainingMessages === 1
        };
    } catch (error) {
        console.error('Error checking message usage:', error);
        return { 
            totalMessages: 0, 
            remainingMessages: 10, 
            maxMessages: 10, 
            blocked: false,
            warningNeeded: false
        };
    }
}

// Helper: Track message usage
async function trackMessageUsage(userId, anonymousId, messageCount = 1) {
    try {
        await pool.query(
            `INSERT INTO chat_usage (user_id, anonymous_id, message_count) 
             VALUES ($1, $2, $3)`,
            [userId || null, anonymousId || null, messageCount]
        );
        return true;
    } catch (error) {
        console.error('Error tracking message usage:', error);
        return false;
    }
}

// Helper: Store chat history
async function storeChatHistory(userId, anonymousId, userMessage, aiResponse, entities) {
    try {
        await pool.query(
            `INSERT INTO chat_history (user_id, anonymous_id, user_message, ai_response, entities) 
             VALUES ($1, $2, $3, $4, $5)`,
            [userId || null, anonymousId || null, userMessage, aiResponse, entities]
        );
        return true;
    } catch (error) {
        console.error('Error storing chat history:', error);
        return false;
    }
}

// NOTE: I did not remove or change your features; I fixed DB column names used in any auth/signup/login queries
// Keep extractQueryEntities, getBranchLocationId, getNutritionData, createNutritionTable, formatProfessionalResponse functions as you had them (no changes here).
// Also kept your enhanced endpoints for /api/auth/register, /api/auth/login, /api/auth/google, /api/chat (authenticateOptional) intact — but made sure the earlier signup/login queries above use correct column names too.

// ============ NEW/EXISTING ENDPOINTS ============
// Your later register/login/google endpoints already used the correct columns (email, password_hash, name).



// Resend verification email endpoint


// Forgot password endpoint
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email is required'
            });
        }
        
        // Check if user exists
        const result = await pool.query(
            'SELECT id, name FROM users WHERE LOWER(email) = LOWER($1) AND is_verified = true',
            [email]
        );
        
        if (result.rows.length === 0) {
            // Don't reveal if user exists
            return res.json({
                success: true,
                message: 'If your email exists, you will receive a password reset link shortly.'
            });
        }
        
        const user = result.rows[0];
        
        // Generate password reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = new Date(Date.now() + 1 * 60 * 60 * 1000); // 1 hour
        
        await pool.query(
            `UPDATE users 
             SET reset_token = $1, 
                 reset_token_expiry = $2 
             WHERE id = $3`,
            [resetToken, resetTokenExpiry, user.id]
        );
        
        // Send reset email
        const resetLink = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
        
        const sendSmtpEmail = new SendSmtpEmail();
        sendSmtpEmail.subject = "Reset Your FastFoodInsight AI Password";
        sendSmtpEmail.htmlContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #FF6B35;">Password Reset Request</h2>
                <p>Hello ${user.name},</p>
                <p>You requested to reset your password. Click the button below to create a new password:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${resetLink}" 
                       style="background-color: #FF6B35; color: white; padding: 12px 24px; 
                              text-decoration: none; border-radius: 6px; display: inline-block;">
                        Reset Password
                    </a>
                </div>
                <p>Or copy and paste this link in your browser:</p>
                <p style="background: #f5f5f5; padding: 10px; border-radius: 4px; word-break: break-all;">
                    ${resetLink}
                </p>
                <p><strong>This link will expire in 1 hour.</strong></p>
                <p>If you didn't request this, you can safely ignore this email.</p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="color: #666; font-size: 12px;">
                    FastFoodInsight AI • World's Largest Fast Food Nutrition Database
                </p>
            </div>
        `;
        sendSmtpEmail.sender = { 
            name: "FastFoodInsight AI", 
            email: "support@fastfoodinsight.com" 
        };
        sendSmtpEmail.to = [{ email: email, name: user.name }];

        await brevoApi.sendTransacEmail(sendSmtpEmail);
        
        res.json({
            success: true,
            message: 'Password reset link sent to your email.'
        });
        
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to send reset email'
        });
    }
});

// Reset password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, password } = req.body;
        
        if (!token || !password) {
            return res.status(400).json({
                success: false,
                error: 'Token and password are required'
            });
        }
        
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                error: 'Password must be at least 8 characters'
            });
        }
        
        // Find user with valid reset token
        const result = await pool.query(
            `SELECT id FROM users 
             WHERE reset_token = $1 
             AND reset_token_expiry > NOW()`,
            [token]
        );
        
        if (result.rows.length === 0) {
            return res.status(400).json({
                success: false,
                error: 'Invalid or expired reset token'
            });
        }
        
        const user = result.rows[0];
        const passwordHash = await bcrypt.hash(password, 10);
        
        // Update password and clear reset token
        await pool.query(
            `UPDATE users 
             SET password_hash = $1, 
                 reset_token = NULL, 
                 reset_token_expiry = NULL 
             WHERE id = $2`,
            [passwordHash, user.id]
        );
        
        res.json({
            success: true,
            message: 'Password reset successfully. You can now sign in with your new password.'
        });
        
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to reset password'
        });
    }
});
app.post('/api/auth/google/manual', async (req, res) => {
    try {
        const { email, name } = req.body;
        
        // Check if user exists
        let userResult = await pool.query(
            'SELECT id, email, name, trial_end FROM users WHERE email = $1',
            [email.toLowerCase()]
        );
        
        let user;
        
        if (userResult.rows.length === 0) {
            // Create new user with trial
            const trialStart = new Date();
            const trialEnd = new Date(trialStart);
            trialEnd.setDate(trialEnd.getDate() + 30);
            
            const userIdentifier = email.toLowerCase();
            
            userResult = await pool.query(
                `INSERT INTO users (email, name, trial_start, trial_end, user_identifier, created_at) 
                 VALUES ($1, $2, $3, $4, $5, NOW()) 
                 RETURNING id, email, name, trial_end`,
                [email.toLowerCase(), name || email.split('@')[0], trialStart, trialEnd, userIdentifier]
            );
            user = userResult.rows[0];
        } else {
            user = userResult.rows[0];
        }
        
        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET || 'fastfoodinsight-secret-key-2024',
            { expiresIn: '7d' }
        );
        
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                trialEnd: user.trial_end
            }
        });
        
    } catch (error) {
        console.error('Manual Google auth error:', error);
        res.status(500).json({ success: false, error: 'Authentication failed' });
    }
});
// Add this endpoint to server.js (before the /api/chat endpoint)
app.get('/api/auth/google/config', (req, res) => {
    res.json({
        success: true,
        clientId: process.env.GOOGLE_CLIENT_ID || '367624804140-nn5nphkhshsljla92cv66sccaksifopt.apps.googleusercontent.com'
    });
});
// FIXED Google OAuth endpoint (lines 793-843)
// FIXED Google OAuth endpoint with proper verification
// Enhanced Google OAuth endpoint with security checks
// In the Google OAuth endpoint (around line 840-880)
app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ 
                success: false, 
                error: 'Google token is required' 
            });
        }
        
        console.log('🔐 Processing Google auth token...');
        
        // Verify the token with Google
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID
        });
        
        const payload = ticket.getPayload();
        
        if (!payload.email || !payload.sub) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid Google token' 
            });
        }
        
        const { email, name, picture } = payload;
        const googleId = payload.sub;
        
        console.log('👤 Google user:', { email, name });
        
        // Check if user exists
        let userResult = await pool.query(
            'SELECT id, email, name, trial_end FROM users WHERE email = $1',
            [email.toLowerCase()]
        );
        
        let user;
        
        if (userResult.rows.length === 0) {
            // Create new user
            const trialStart = new Date();
            const trialEnd = new Date(trialStart);
            trialEnd.setDate(trialEnd.getDate() + 30);
            
            userResult = await pool.query(
                `INSERT INTO users (email, name, google_id, avatar_url, trial_start, trial_end, user_identifier, created_at) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) 
                 RETURNING id, email, name, trial_end`,
                [
                    email.toLowerCase(),
                    name || email.split('@')[0],
                    googleId,
                    picture || null,
                    trialStart,
                    trialEnd,
                    email.toLowerCase()  // user_identifier
                ]
            );
            user = userResult.rows[0];
            console.log('✅ New user created via Google');
        } else {
            user = userResult.rows[0];
            console.log('✅ Existing user found');
        }
        
        // Create JWT token
        // Change this:
const jwtToken = jwt.sign(
  { 
    id: user.id,
    email: user.email,
    type: 'google'
  },
  process.env.JWT_SECRET, // ✅ USE HERE
  { expiresIn: '7d' }
);
        
        res.json({
            success: true,
            token: jwtToken,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                trialEnd: user.trial_end
            }
        });
        
    } catch (error) {
        console.error('❌ Google auth error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'Authentication failed. Please try again.' 
        });
    }
});

// Verify token endpoint
app.get('/api/auth/verify', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                error: 'No token provided' 
            });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        const userResult = await pool.query(
            'SELECT id, email, name, trial_end FROM users WHERE id = $1',
            [decoded.id]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ 
                success: false, 
                error: 'User not found' 
            });
        }
        
        res.json({
            success: true,
            user: userResult.rows[0]
        });
    } catch (error) {
        res.status(401).json({ 
            success: false, 
            error: 'Invalid token' 
        });
    }
});

// ============ ENHANCED CHAT ENDPOINT WITH USAGE TRACKING ============
// ============ MIDDLEWARE ============

/**
 * Optional authentication middleware
 * Allows anonymous users with limits
 */
// In server.js, update the authenticateOptional middleware (around line 900-950)
// In server.js, update the authenticateOptional middleware (around line 900)
// Replace it with this simpler version:

const authenticateOptional = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        req.user = null;
        return next();
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Get user from database
        const result = await pool.query(
            'SELECT id, email, name, trial_end FROM users WHERE id = $1',
            [decoded.id]
        );
        
        if (result.rows.length > 0) {
            req.user = result.rows[0];
        } else {
            req.user = null;
        }
    } catch (error) {
        req.user = null;
    }
    
    next();
};

/**
 * Check message limits middleware
 * Must be used AFTER authenticateOptional
 */
const IS_DEVELOPMENT = process.env.NODE_ENV !== 'production';
const checkMessageLimit = async (req, res, next) => {
    let userId = req.user ? req.user.id : null;
    let anonymousId = req.body.anonymous_id;
    
    console.log('🔍 checkMessageLimit:', { 
        userId, 
        anonymousId, 
        hasUser: !!req.user,
        body: req.body 
    });
    
    // CRITICAL: If user is logged in, skip ALL limits
    if (userId && req.user) {
        console.log('✅ Logged-in user detected - SKIPPING ALL LIMITS');
        req.messageUsage = {
            totalMessages: 0,
            remainingMessages: 999999,
            maxMessages: 999999,
            isInTrial: true,
            trialEnd: req.user.trial_end || null,
            isBlocked: false,
            warningNeeded: false
        };
        return next();
    }
    
    // For anonymous users, require anonymous_id
    if (!anonymousId) {
        console.log('❌ No anonymous ID - creating temporary one');
        // Create a temporary anonymous ID for this request
        req.body.anonymous_id = 'temp_' + Date.now();
        anonymousId = req.body.anonymous_id;
    }
    
    try {
        console.log('🔍 Checking anonymous user message count for:', anonymousId);
        const result = await pool.query(
            'SELECT COUNT(*) as total_messages FROM chat_usage WHERE anonymous_id = $1',
            [anonymousId]
        );
        
        let totalMessages = 0;
        if (result.rows.length > 0) {
            totalMessages = parseInt(result.rows[0].total_messages) || 0;
            console.log('✅ Anonymous user message count:', totalMessages);
        }
        
        // Set limits: 10 for anonymous users
        const maxMessages = 10;
        const remainingMessages = Math.max(0, maxMessages - totalMessages);
        const isBlocked = totalMessages >= maxMessages;
        const warningNeeded = !isBlocked && remainingMessages <= 3;
        
        console.log('📊 Usage limits:', { 
            totalMessages, 
            maxMessages, 
            remainingMessages, 
            isBlocked, 
            warningNeeded
        });
        
        req.messageUsage = {
            totalMessages,
            remainingMessages,
            maxMessages,
            isInTrial: false,
            trialEnd: null,
            isBlocked,
            warningNeeded
        };
        
        if (isBlocked && anonymousId && !anonymousId.startsWith('temp_')) {
            console.log('🚫 Anonymous user reached limit:', anonymousId);
            return res.status(403).json({
                requiresLogin: true,
                error: 'message_limit_reached',
                message: 'You have used all 10 free messages. Please sign up to continue.',
                usage: req.messageUsage
            });
        }
        
        next();
    } catch (error) {
        console.error('❌ Error in checkMessageLimit:', error);
        // Allow messages if there's an error (for now)
        req.messageUsage = {
            totalMessages: 0,
            remainingMessages: 10,
            maxMessages: 10,
            isInTrial: false,
            trialEnd: null,
            isBlocked: false,
            warningNeeded: false
        };
        next();
    }
};

// Helper function to track message
async function trackMessage(userId, anonymousId) {
    try {
        await pool.query(
            'INSERT INTO chat_usage (user_id, anonymous_id, message_count) VALUES ($1, $2, 1)',
            [userId || null, anonymousId || null]
        );
        return true;
    } catch (error) {
        console.error('Error tracking message:', error);
        return false;
    }
}
// ============ ENHANCED CHAT ENDPOINT ============

// ============ FIXED ENDPOINTS TO ADD TO server.js ============

// Add this endpoint for checking usage WITHOUT counting toward limits
async function checkUsage() {
    try {
        console.log('📊 Checking usage...');
        
        const response = await fetch('/api/check-usage-only', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                anonymous_id: currentState.anonymousId
            })
        });
        
        const data = await response.json();
        
        if (data.success && data.usage) {
            currentState.usage = data.usage;
            console.log('📈 Usage data:', currentState.usage);
            updateUsageUI();
        }
        
        // Enable/disable input based on usage
        const userInput = document.getElementById('userInput');
        const sendButton = document.getElementById('sendButton');
        
        if (currentState.usage.blocked) {
            if (currentState.user) {
                userInput.disabled = true;
                userInput.placeholder = 'Trial expired. Please subscribe.';
                sendButton.disabled = true;
                showNotification('Your trial has ended. Please subscribe.', 'warning');
            } else {
                userInput.disabled = true;
                userInput.placeholder = 'Sign up for unlimited access';
                sendButton.disabled = true;
                showNotification('Free limit reached. Sign up for unlimited access.', 'warning');
            }
        } else {
            // User can send messages
            userInput.disabled = false;
            sendButton.disabled = false;
            
            if (currentState.user && currentState.usage.isInTrial) {
                userInput.placeholder = 'Ask about any food item... (Trial Active)';
                console.log('✅ Trial user - unlimited access');
            } else if (currentState.user) {
                userInput.placeholder = 'Ask about any food item... (Subscribed)';
            } else {
                userInput.placeholder = `Ask about any food item... (${currentState.usage.remainingMessages} messages left)`;
            }
        }
        
    } catch (error) {
        console.error('Usage check failed:', error);
        // Allow messages if check fails
        document.getElementById('userInput').disabled = false;
        document.getElementById('sendButton').disabled = false;
    }
}
// Add this endpoint for Google OAuth config
app.get('/api/auth/google/config', (req, res) => {
    res.json({
        clientId: process.env.GOOGLE_CLIENT_ID || '',
        success: !!process.env.GOOGLE_CLIENT_ID
    });
});

// Update the /api/chat endpoint to fix message tracking
// ============ ENHANCED CHAT ENDPOINT WITH USAGE TRACKING ============
app.post('/api/chat', authenticateOptional, checkMessageLimit, async (req, res) => {
    try {
        console.log('=== CHAT ENDPOINT START ===');
        console.log('Request body:', req.body);
        console.log('User from auth:', req.user);
        console.log('Message usage:', req.messageUsage);
        
        const { message, goal: userGoal, anonymous_id, chat_session_id } = req.body;
        
        console.log(`\n📨 Query: "${message}" - User: ${req.user?.id || 'anonymous'}, Session: ${chat_session_id || 'default'}`);
        
        // CRITICAL: If user is logged in, use their user_id
        const effectiveUserId = req.user ? req.user.id : null;
        const effectiveAnonymousId = req.user ? null : anonymous_id;
        
        console.log('Effective IDs:', { effectiveUserId, effectiveAnonymousId });
        
        if (!req.user && !effectiveAnonymousId) {
            console.log('❌ No user or anonymous ID');
            return res.status(400).json({
                text: `## ⚠️ Session Error\n\nPlease refresh the page to continue using FastFoodInsight AI.`,
                goal: 'basic',
                requiresLogin: false
            });
        }
        
        // Extract entities
        const entities = extractQueryEntities(message);
        
        // Override with user goal if provided
        if (userGoal && userGoal !== 'basic') {
            entities.goal = userGoal;
            entities.queryType = userGoal;
        }
        
        // Check if we need to validate restaurant and country
if (!entities.branch) {
    return res.json({
        text: `<h2 style="color:#FF6B35;">🍔 Select Restaurant</h2>
               <p>Please specify which restaurant chain:</p>
               <p><strong>Available chains:</strong> McDonalds, KFC, Burger King, Starbucks, Pizza Hut, Dominos, Taco Bell, Wendys, Dunkin</p>
               <p><strong>Format:</strong> "[Food Item] at [Restaurant] in [Country]"<br>
               <strong>Example:</strong> "Zinger Burger at KFC in Pakistan"<br>
               <strong>Example:</strong> "Big Mac at McDonalds in USA"</p>
               <p><em>FastFoodInsight covers 100+ countries worldwide</em></p>`,
        goal: 'basic',
        requiresLogin: false,
        usage: req.messageUsage
    });
}
        
        if (!entities.country) {
            const suggestedCountries = ALL_COUNTRIES.slice(0, 15).join(', ');
            return res.json({
                text: `## 🌍 Select Country\n\nPlease specify which country:\n\n` +
                      `**Available in 100+ countries including:** ${suggestedCountries}\n\n` +
                      `**Format:** "[Food Item] at [Restaurant] in [Country]"\n` +
                      `**Example:** "Zinger Burger at KFC in Pakistan"\n` +
                      `**Example:** "Coffee at Starbucks in Australia"\n\n` +
                      `*FastFoodInsight AI supports global nutrition analysis*`,
                goal: 'basic',
                requiresLogin: false,
                usage: req.messageUsage
            });
        }
        try {
            // Process the query
            const items = await getNutritionData(entities, 10);
            let response = formatProfessionalResponse(items, entities);
            
            // Add warning if needed (9th message for anonymous users)
            if (req.messageUsage.warningNeeded && !req.user) {
                response += `\n\n---\n\n⚠️ **You have 1 free message left.** Sign up to continue using FastFoodInsight AI with unlimited messages during our 7-day free trial!`;
            }
            
            // Track this message
            await trackMessage(effectiveUserId, effectiveAnonymousId);
            
            // Store chat history ONLY for logged-in users
            try {
                if (effectiveUserId) {
            try {
                // Create or update chat session
                await pool.query(`
                    INSERT INTO chat_sessions (user_id, session_id, session_name, created_at, updated_at, is_active)
                    VALUES ($1, $2, $3, NOW(), NOW(), true)
                    ON CONFLICT (session_id) 
                    DO UPDATE SET updated_at = NOW(), is_active = true
                `, [
                    effectiveUserId, 
                    chat_session_id, 
                    `Chat ${new Date().toLocaleDateString()}`
                ]);
            } catch (sessionError) {
                console.log('Note: Session creation skipped:', sessionError.message);
            }
        }
            } catch (error) {
                console.log('Note: Chat history not saved (table might not exist or error):', error.message);
            }
            
            // Return response
            return res.json({
                text: response,
                goal: entities.goal,
                found: items.length,
                branch: entities.branch,
                country: entities.country,
                foodItem: entities.foodItem,
                queryType: entities.queryType,
                requiresLogin: false,
                usageWarning: req.messageUsage.warningNeeded && !req.user,
                usage: req.messageUsage
            });
            
        } catch (dbError) {
            console.error('Database error in chat:', dbError);
            
            // Return a helpful error message
            return res.json({
                text: `## 🔧 Database Connection Issue\n\nI'm having trouble connecting to the FastFoodInsight database.\n\n**Please try:**\n1. Checking if the database is running\n2. Trying again in a moment\n3. Using the quick queries in the sidebar\n\n*Common queries that should work:*\n• "Big Mac at McDonalds in USA"\n• "Zinger Burger at KFC in UK"\n• "Coffee at Starbucks in Australia"`,
                goal: 'basic',
                found: 0,
                requiresLogin: false,
                usage: req.messageUsage
            });
        }
        
    } catch (error) {
        console.error('❌ Chat endpoint error:', error);
        
        return res.json({
            text: `## ⚠️ System Error\n\nFastFoodInsight AI encountered an issue. Please:\n\n` +
                  `1. **Try a simpler query:** "Big Mac at McDonalds in USA"\n` +
                  `2. **Check your format:** "[Food] at [Restaurant] in [Country]"\n` +
                  `3. **Try quick queries** from the sidebar\n\n` +
                  `*Accessing 23,000+ nutrition records across 100+ countries*\n` +
                  `*If the problem persists, please report it*`,
            goal: 'basic',
            requiresLogin: false
        });
    }
});
// ============ CHAT HISTORY ENDPOINT ============
// Add this endpoint to server.js (before the chat endpoints)



// ============ CHAT HISTORY ENDPOINT - UPDATED ============
// Replace existing /api/chat/history handler with this robust version
app.get('/api/chat/history', authenticateOptional, async (req, res) => {
  try {
    // If user is authenticated -> return sessions (existing behavior)
    if (req.user) {
      const sessionsResult = await pool.query(`
        SELECT 
          cs.session_id,
          cs.session_name,
          cs.created_at,
          cs.updated_at,
          COALESCE(COUNT(ch.id),0) as message_count
        FROM chat_sessions cs
        LEFT JOIN chat_history ch ON cs.session_id = ch.chat_session_id
        WHERE cs.user_id = $1
        GROUP BY cs.session_id, cs.session_name, cs.created_at, cs.updated_at
        ORDER BY cs.updated_at DESC
        LIMIT 50
      `, [req.user.id]);

      return res.json({
        success: true,
        type: 'sessions',
        sessions: sessionsResult.rows
      });
    }

    // Anonymous users: require anonymous_id query parameter
    const anonymousId = req.query.anonymous_id || req.body.anonymous_id;
    if (!anonymousId) {
      return res.status(400).json({ success: false, error: 'anonymous_id required for unauthenticated requests' });
    }

    // Fetch last 50 history rows for anonymous id (most recent first)
    const historyResult = await pool.query(`
      SELECT id,
             user_id,
             anonymous_id,
             user_message,
             ai_response,
             entities,
             EXTRACT(EPOCH FROM created_at) as timestamp
      FROM chat_history
      WHERE anonymous_id = $1
      ORDER BY created_at DESC
      LIMIT 50
    `, [anonymousId]);

    return res.json({
      success: true,
      type: 'history',
      history: historyResult.rows
    });

  } catch (err) {
    console.error('Error in /api/chat/history:', err && err.stack ? err.stack : err);
    return res.status(500).json({
      success: false,
      error: 'Failed to load chat history',
      detail: err && err.message ? err.message : String(err)
    });
  }
});

// Get messages for specific session - FIXED
app.get('/api/chat/session/:sessionId', authenticateOptional, async (req, res) => {
    try {
        const { sessionId } = req.params;
        
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        
        const messagesResult = await pool.query(`
            SELECT ch.id, ch.user_message, ch.ai_response, 
                   EXTRACT(EPOCH FROM ch.created_at) as timestamp,
                   COALESCE(ch.entities->>'branch', 'Unknown') as restaurant
            FROM chat_history ch
            WHERE ch.user_id = $1 AND ch.chat_session_id = $2
            ORDER BY ch.created_at ASC
        `, [req.user.id, sessionId]);
        
        res.json({
            success: true,
            messages: messagesResult.rows,
            session_id: sessionId
        });
    } catch (error) {
        console.error('Error fetching session messages:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/chat/session', authenticateOptional, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        
        const { session_id, session_name } = req.body;
        
        // Simple insert without ON CONFLICT for now
        await pool.query(
            `INSERT INTO chat_sessions (user_id, session_id, session_name, created_at, updated_at, is_active)
             VALUES ($1, $2, $3, NOW(), NOW(), true)`,
            [req.user.id, session_id, session_name || 'New Chat']
        );
        
        res.json({ success: true, session_id });
    } catch (error) {
        console.error('Error creating session:', error.message);
        // If duplicate, still return success
        if (error.code === '23505') { // Unique violation
            res.json({ success: true, session_id: req.body.session_id });
        } else {
            res.status(500).json({ success: false, error: error.message });
        }
    }
});

app.get('/api/chat/sessions', authenticateOptional, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        
        // First, just try to get sessions without checking specific columns
        try {
            const result = await pool.query(`
                SELECT 
                    COALESCE(session_id, 'default_session') as session_id,
                    COALESCE(session_name, 'New Chat') as session_name,
                    created_at, 
                    updated_at
                FROM chat_sessions
                WHERE user_id = $1
                ORDER BY updated_at DESC
                LIMIT 20
            `, [req.user.id]);
            
            res.json({ success: true, sessions: result.rows });
        } catch (dbError) {
            // If table doesn't exist or has issues, return empty array
            console.log('Note: Could not fetch sessions, table might not exist:', dbError.message);
            res.json({ success: true, sessions: [] });
        }
        
    } catch (error) {
        console.error('Error fetching sessions:', error.message);
        // Return empty array instead of error
        res.json({ success: true, sessions: [] });
    }
});

// ============ EXISTING ENDPOINTS (KEEP AS IS) ============

// Keep all your existing endpoints exactly as they are
app.post('/api/set-goal', (req, res) => {
    // Your existing set-goal endpoint
    const { goal } = req.body;
    
    const validGoals = ['weight_loss', 'weight_gain', 'diabetes', 'bp', 'heart', 'basic'];
    if (!validGoals.includes(goal)) {
        return res.status(400).json({ error: 'Invalid goal' });
    }
    
    const goalNames = {
        weight_loss: 'Weight Loss',
        weight_gain: 'Muscle Gain',
        diabetes: 'Diabetes Management',
        bp: 'Blood Pressure Control',
        heart: 'Heart Health',
        basic: 'Basic Nutrition'
    };
    
    res.json({
        success: true,
        goal: goal,
        message: `FastFoodInsight AI goal set to ${goalNames[goal]}`,
        emoji: HEALTH_THRESHOLDS[goal]?.emoji || '🍔'
    });
});

// ============ USAGE CHECK ENDPOINT ============

// ============ USAGE CHECK ENDPOINT - FIXED ============
app.get('/api/usage', authenticateOptional, async (req, res) => {
    try {
        const anonymousId = req.query.anonymous_id;
        
        // For logged-in users, return unlimited usage
        if (req.user) {
            return res.json({
                success: true,
                usage: {
                    totalMessages: 0,
                    remainingMessages: 999999,
                    maxMessages: 999999,
                    isInTrial: true,
                    trialEnd: req.user.trial_end || null,
                    blocked: false,
                    warningNeeded: false
                }
            });
        }
        
        // For anonymous users, require anonymous_id
        if (!anonymousId) {
            return res.status(400).json({ 
                success: false, 
                error: 'Anonymous ID required for unauthenticated users' 
            });
        }
        
        try {
            const result = await pool.query(
                'SELECT COUNT(*) as total_messages FROM chat_usage WHERE anonymous_id = $1',
                [anonymousId]
            );
            
            let totalMessages = 0;
            if (result.rows.length > 0) {
                totalMessages = parseInt(result.rows[0].total_messages) || 0;
            }
            
            // Set limits: 10 for anonymous users
            const maxMessages = 10;
            const remainingMessages = Math.max(0, maxMessages - totalMessages);
            const isBlocked = totalMessages >= maxMessages;
            const warningNeeded = !isBlocked && remainingMessages <= 3;
            
            res.json({
                success: true,
                usage: {
                    totalMessages,
                    remainingMessages,
                    maxMessages,
                    isInTrial: false,
                    trialEnd: null,
                    blocked: isBlocked,
                    warningNeeded: warningNeeded
                }
            });
            
        } catch (dbError) {
            console.error('Database error in usage check:', dbError);
            // Return default usage if database error
            res.json({
                success: true,
                usage: {
                    totalMessages: 0,
                    remainingMessages: 10,
                    maxMessages: 10,
                    isInTrial: false,
                    trialEnd: null,
                    blocked: false,
                    warningNeeded: false
                }
            });
        }
        
    } catch (error) {
        console.error('Error checking usage:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to check usage' 
        });
    }
});

app.get('/api/health', async (req, res) => {
    try {
        // Simple DB check without heavy queries
        await pool.query('SELECT 1');
        
        res.json({
            status: 'healthy',
            service: 'FastFoodInsight API',
            version: '4.0.0',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(503).json({
            status: 'unhealthy',
            error: 'Database connection failed',
            timestamp: new Date().toISOString()
        });
    }
});
// Add this function near the top of your server.js after database setup
async function cleanupOldHistory() {
    try {
        const result = await pool.query(
            'DELETE FROM chat_history WHERE created_at < NOW() - INTERVAL \'3 months\''
        );
        console.log(`🧹 Cleaned up ${result.rowCount} old chat history records`);
    } catch (error) {
        console.error('Error cleaning up old history:', error);
    }
}

// Run cleanup on server start and then weekly
cleanupOldHistory();
setInterval(cleanupOldHistory, 7 * 24 * 60 * 60 * 1000); // Weekly

// Also add this endpoint for manual cleanup if needed
app.post('/api/cleanup-history', async (req, res) => {
    try {
        await cleanupOldHistory();
        res.json({ success: true, message: 'History cleanup completed' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});
app.get('/api/available-data', async (req, res) => {
    try {
        const branches = await pool.query('SELECT name FROM branches ORDER BY name');
        const countries = await pool.query('SELECT name FROM countries ORDER BY name LIMIT 50');
        
        res.json({
            branches: branches.rows.map(r => r.name),
            countries: countries.rows.map(r => r.name),
            total_items: 23000,
            service: 'FastFoodInsight AI'
        });
    } catch (error) {
        // Fallback data
        res.json({
            branches: ['McDonalds', 'KFC', 'Burger King', 'Starbucks', 'Pizza Hut', 'Dominos', 'Taco Bell', 'Wendys', 'Dunkin'],
            countries: ALL_COUNTRIES.slice(0, 20),
            total_items: 23000,
            service: 'FastFoodInsight AI'
        });
    }
});
// Add this endpoint for updating user name
app.post('/api/auth/update-name', authenticateOptional, async (req, res) => {
    try {
        const { name } = req.body;
        
        if (!name || name.trim().length < 2) {
            return res.status(400).json({
                success: false,
                error: 'Name must be at least 2 characters'
            });
        }
        
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required'
            });
        }
        
        await pool.query(
            'UPDATE users SET name = $1 WHERE id = $2',
            [name.trim(), req.user.id]
        );
        
        res.json({
            success: true,
            message: 'Name updated successfully'
        });
        
    } catch (error) {
        console.error('Error updating name:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update name'
        });
    }
});
// ===
// === API ROUTES ===
app.get("/api/countries", async (req, res) => {
    try {
        const result = await db.query("SELECT id, name FROM countries");
        res.json(result.rows);
    } catch (err) {
        handleDatabaseError(res, err, "Fetch countries");
    }
});

app.get("/api/branches", async (req, res) => {
    const countryId = req.query.country_id;
    if (!countryId) return res.status(400).json({ error: "country_id is required" });

    try {
        const result = await db.query(
            `SELECT b.id, b.name
             FROM branches b
             JOIN branch_locations bl ON bl.branch_id = b.id
             WHERE bl.country_id = $1`,
            [countryId]
        );
        res.json(result.rows);
    } catch (err) {
        handleDatabaseError(res, err, "Fetch branches");
    }
});

app.get("/api/items", async (req, res) => {
    const { country_id, branch_id } = req.query;
    if (!country_id || !branch_id)
        return res.status(400).json({ error: "country_id and branch_id are required" });

    try {
        const result = await db.query(
            `SELECT fi.id, fi.name, fi.serving_size, fi.calories, fi.total_fat, fi.saturated_fat,
                   fi.trans_fat, fi.cholesterol, fi.sodium, fi.carbohydrates, fi.sugars, fi.protein
             FROM food_items fi
             JOIN branch_locations bl ON fi.branch_location_id = bl.id
             WHERE bl.country_id = $1 AND bl.branch_id = $2`,
            [country_id, branch_id]
        );
        res.json(result.rows);
    } catch (err) {
        handleDatabaseError(res, err, "Fetch food items");
    }
});

app.get("/api/item", async (req, res) => {
    const id = req.query.id;
    if (!id) return res.status(400).json({ error: "id is required" });

    try {
        const result = await db.query("SELECT * FROM food_items WHERE id = $1", [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: "Item not found" });
        res.json(result.rows[0]);
    } catch (err) {
        handleDatabaseError(res, err, "Fetch item");
    }
});

app.post("/api/items", async (req, res) => {
    const data = req.body;
    const sql = `
      INSERT INTO food_items (
        branch_location_id, name, serving_size, calories, total_fat, saturated_fat,
        trans_fat, cholesterol, sodium, carbohydrates, sugars, protein
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      RETURNING id`;
    const values = [
        data.branch_location_id, data.name, data.serving_size, data.calories,
        data.total_fat, data.saturated_fat, data.trans_fat,
        data.cholesterol, data.sodium, data.carbohydrates, data.sugars, data.protein
    ];
    try {
        const result = await db.query(sql, values);
        res.status(201).json({ id: result.rows[0].id });
    } catch (err) {
        handleDatabaseError(res, err, "Insert food item");
    }
});
app.get("/api", (req, res) => {
  res.json({ status: "FastFood API live ✅" });
});

app.delete("/api/items/:id", async (req, res) => {
    const { id } = req.params;
    try {
        await db.query("DELETE FROM food_items WHERE id = $1", [id]);
        res.sendStatus(204);
    } catch (err) {
        handleDatabaseError(res, err, "Delete food item");
    }
});


// === START SERVER ===
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

const startServer = async () => {
    await testConnection();
    app.listen(PORT, HOST, () => {
        console.log(`🚀 Server running at http://${HOST}:${PORT}`);
    });
};

startServer();
