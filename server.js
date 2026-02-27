// --- Sahyog Medical Delivery Backend (server.js) - v6.2 (Auto-Sync Enabled) ---

import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import path from 'path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { google } from 'googleapis';
import cron from 'node-cron';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

const allowedOrigins = [
  "https://sahyogdelivery.vercel.app",
  "http://localhost:3000",
  "http://localhost:5500"
];

// Cashfree webhook requires raw body for signature verification.
app.use('/api/cashfree-webhook', express.raw({ type: "application/json" }));
app.use(express.json());
app.use(cors({
  origin: function (origin, callback) {
    // Postman / server-side / cron ke liye
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

// 🔥 VERY IMPORTANT
app.options("*", cors());

import admin from 'firebase-admin';
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
  })
});

const sendNotification = async (token, title, body, userId = null, options = {}) => {
  // Debug: show we are attempting to send (mask token partially)
  try {
    const masked = token ? `${token.toString().slice(0, 6)}...` : 'no-token';
    console.log("→ sendNotification: Attempting to send FCM", { title, to: masked });
  } catch (e) { /* ignore masking errors */ }

  const message = {
    token,
    webpush: {
      headers: options.headers || { Urgency: "high" },
      notification: {
        title,
        body,
        icon: options.icon || "https://sahyogdelivery.vercel.app/favicon.png",
        badge: options.badge || "https://sahyogdelivery.vercel.app/favicon.png",
        tag: options.tag || `msg-${Date.now()}`,
        requireInteraction: options.requireInteraction ?? true
      },
      fcmOptions: {
        link: options.link || "https://sahyogdelivery.vercel.app"
      }
    }
  };

  try {
    await admin.messaging().send(message);
    console.log("✅ FCM sent to", token ? `${token.toString().slice(0, 6)}...` : token);
  } catch (err) {
    console.error("❌ FCM FAILED:", err.code, err.message);
    const invalidCodes = ['messaging/invalid-registration-token', 'messaging/registration-token-not-registered'];
    if (userId && invalidCodes.includes(err.code)) {
      await User.findByIdAndUpdate(userId, { $pull: { fcmTokens: token } });
      console.log("🧹 Removed invalid token for user", userId);
    }
  }
};

function getISTTime() {
  return new Date().toLocaleTimeString('en-IN', {
    timeZone: 'Asia/Kolkata',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function extractPincode(address = '') {
  const m = address.match(/\b\d{6}\b/);
  return m ? m[0] : null;
}

function parseMargmartEmail(body) {
  return {
    orderNumber: body.match(/Order Number\s*:\s*(.+)/i)?.[1]?.trim(),
    customerName: body.match(/Customer's Name\s*:\s*(.+)/i)?.[1]?.trim(),
    phone: body.match(/Contact\s*:\s*(\d+)/i)?.[1]?.trim(),
    address: body.match(/Shipping Address\s*:\s*(.+)/i)?.[1]?.trim(),
    amount: Number(body.match(/Total Amount\s*:\s*([\d.]+)/i)?.[1]),
  };
}

// --- 1. Environment Variables ---
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const CASHFREE_APP_ID = process.env.CASHFREE_APP_ID;
const CASHFREE_SECRET_KEY = process.env.CASHFREE_SECRET_KEY;
const CASHFREE_BASE_URL = process.env.CASHFREE_BASE_URL || 'https://sandbox.cashfree.com/pg';

// --- Verification of Critical Environment Variables ---
if (!CASHFREE_APP_ID || !CASHFREE_SECRET_KEY) {
  console.warn("⚠️ WARNING: CASHFREE_APP_ID or CASHFREE_SECRET_KEY is missing. Payment features will fail.");
}



if (!MONGO_URI || !JWT_SECRET || !VAPID_PUBLIC_KEY) {
  console.error('FATAL ERROR: Environment Variables are not set.');
  process.exit(1);
}

// --- 2. MongoDB Connect ---
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB से जुड़ गए!'))
  .catch(err => console.error('MongoDB से जुड़ने में गड़बड़ी:', err));


// --- (NEW) Google Sheets API Setup ---
const GOOGLE_SHEET_ID = process.env.GOOGLE_SHEET_ID;
const GOOGLE_SERVICE_ACCOUNT_EMAIL = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
const GOOGLE_PRIVATE_KEY = process.env.GOOGLE_PRIVATE_KEY;

// Check if Google Sheet variables are set
if (!GOOGLE_SHEET_ID || !GOOGLE_SERVICE_ACCOUNT_EMAIL || !GOOGLE_PRIVATE_KEY) {
  console.warn("WARNING: Google Sheets environment variables missing! Sync feature will fail.");
}

let sheets;
if (GOOGLE_SHEET_ID && GOOGLE_SERVICE_ACCOUNT_EMAIL && GOOGLE_PRIVATE_KEY) {
  const googleAuth = new google.auth.GoogleAuth({
    credentials: {
      client_email: GOOGLE_SERVICE_ACCOUNT_EMAIL,
      private_key: GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'), // Replace escaped newlines
    },
    scopes: ['https://www.googleapis.com/auth/spreadsheets'], // Read/write to sheets
  });

  sheets = google.sheets({ version: 'v4', auth: googleAuth });
  console.log("Google Sheets API authenticated.");
} else {
  console.log("Google Sheets API setup skipped due to missing env variables.");
}

// --- Auth Middleware (Moved early to prevent ReferenceError) ---
const auth = (roles = []) => {
  return (req, res, next) => {
    try {
      if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Authentication failed: No token provided' });
      }
      const token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      if (roles.length > 0 && !roles.includes(decoded.role)) {
        return res.status(403).json({ message: 'Forbidden: Insufficient role' });
      }
      next();
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        res.status(401).json({ message: 'Authentication failed: Token expired' });
      } else if (error.name === 'JsonWebTokenError') {
        res.status(401).json({ message: 'Authentication failed: Invalid token signature' });
      } else {
        console.error("Auth Middleware Error:", error);
        res.status(401).json({ message: 'Authentication failed: Invalid token' });
      }
    }
  };
};

// --- 3.1. FCM Token Save Endpoint ---
app.post('/api/save-fcm-token', auth(['admin', 'manager', 'delivery']), async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ message: "FCM token missing" });
  }

  await User.findByIdAndUpdate(req.user.userId, {
    $addToSet: { fcmTokens: token }
  });

  // Debugging: log token save (masked)
  try { console.log(`[FCM] Saved token for user ${req.user.userId}:`, token ? `${token.toString().slice(0, 6)}...` : 'no-token'); } catch (e) { }

  res.json({ message: "FCM token saved" });
});


// --- 4. Schemas ---

// 4.1. User Schema (No changes)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true }, // Username
  password: { type: String, required: true },
  phone: { type: String },
  role: { type: String, enum: ['admin', 'manager', 'delivery'], required: true },
  isActive: { type: Boolean, default: true },
  fcmTokens: { type: [String], default: [] },
  createdByManager: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

// 4.2. Delivery Schema (No changes)
const deliverySchema = new mongoose.Schema({
  customerName: String,
  customerAddress: String,
  customerPhone: String,
  trackingId: { type: String, unique: true, required: true },
  otp: String,
  paymentMethod: { type: String, enum: ['COD', 'Prepaid'], default: 'Prepaid' },
  billAmount: { type: Number, default: 0 },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // Delivery Boy ID
  assignedByManager: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // Manager ID
  assignedBoyDetails: { name: String, phone: String },
  statusUpdates: [{ status: String, timestamp: { type: Date, default: Date.now } }],
  codPaymentStatus: { type: String, enum: ['Pending', 'Paid - Cash', 'Paid - Online', 'Not Applicable'], default: 'Pending' },
  cashReceivedByAdmin: { type: Boolean, default: false },
  cashReceivedAt: { type: Date, default: null },
  completedAt: { type: Date, default: null },
  assignedAt: { type: Date, default: null }
}, { timestamps: true });

deliverySchema.virtual('currentStatus').get(function () {
  if (this.statusUpdates.length === 0) return 'Pending';
  const lastUpdate = this.statusUpdates[this.statusUpdates.length - 1];
  if (lastUpdate.status === 'Cancelled') return 'Cancelled';
  for (let i = this.statusUpdates.length - 1; i >= 0; i--) {
    if (this.statusUpdates[i].status !== 'Cancelled') {
      return this.statusUpdates[i].status;
    }
  }
  return 'Pending';
});
deliverySchema.set('toJSON', { virtuals: true });
const Delivery = mongoose.model('Delivery', deliverySchema);

// 4.3 Business Settings Schema (No changes)
const BusinessSettingsSchema = new mongoose.Schema({
  businessName: { type: String, default: 'Sahyog Medical' },
  businessAddress: { type: String, default: 'Your Business Address, City, State, Country, PIN' },
  businessPhone: { type: String, default: '+91 9876543210' },
  logoUrl: { type: String, default: '' }, // URL for the business logo
  upiId: { type: String, default: '' },
  upiName: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});
const BusinessSettings = mongoose.model('BusinessSettings', BusinessSettingsSchema);


// --- (NEW) 4.5. Google Sheet Auto-Sync Helper Function ---

// (Yeh headers ab aapki sheet se 100% match karte hain)
const GOOGLE_SHEET_HEADERS = [
  'Tracking ID', 'Customer Name', 'Status', 'Payment', 'Payment Status',
  'Assigned Manager', 'Assigned Boy', 'OTP', 'Date'
];
// Light Red color (#fbe9e7) for deleted rows
const DELETED_ROW_COLOR = { "red": 0.98431, "green": 0.91372, "blue": 0.90588 };

async function syncSingleDeliveryToSheet(deliveryId, action = 'update') {
  if (!sheets) {
    console.warn("Google Sheets API not configured, skipping auto-sync.");
    return;
  }

  let delivery;
  try {
    // 1. Get the full delivery data from DB
    delivery = await Delivery.findById(deliveryId)
      .populate('assignedByManager', 'name')
      .populate('assignedTo', 'name');

    if (!delivery && action !== 'delete') {
      console.warn(`Auto-sync: Delivery ${deliveryId} not found.`);
      return;
    }

    if (action === 'delete' && !delivery) {
      console.warn(`Auto-sync: Cannot highlight deleted delivery ${deliveryId}, already gone.`);
      return;
    }

  } catch (dbError) {
    console.error("Auto-sync DB Error:", dbError.message);
    return;
  }

  try {
    // 2. Find the row in the sheet
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: GOOGLE_SHEET_ID,
      range: 'Sheet1!A:A', // Check only Tracking ID column
    });

    const sheetData = response.data.values || [];
    let rowNumber = -1;

    for (let i = 0; i < sheetData.length; i++) {
      if (sheetData[i][0] === delivery.trackingId) {
        rowNumber = i + 1; // 1-based index
        break;
      }
    }

    // 3. Prepare the data row (FIXED - 9 Columns)
    const rowData = [
      delivery.trackingId || 'N/A',
      delivery.customerName || 'N/A',
      delivery.currentStatus || 'N/A',
      (delivery.paymentMethod === 'COD' ? `₹${delivery.billAmount}` : 'Prepaid'),
      (delivery.paymentMethod === 'COD' ? (delivery.codPaymentStatus || 'Pending') : 'N/A'),
      delivery.assignedByManager ? delivery.assignedByManager.name : 'N/A',
      delivery.assignedTo ? delivery.assignedTo.name : 'N/A',
      delivery.otp || 'N/A',
      new Date(delivery.createdAt).toLocaleDateString('en-IN') // Simple Date
    ];


    // 4. Perform the correct action
    if (action === 'delete') {
      // --- ACTION: DELETE (Highlight Row) ---
      if (rowNumber > 0) {
        console.log(`Auto-sync: Highlighting deleted row ${rowNumber} for ${delivery.trackingId}`);
        await sheets.spreadsheets.batchUpdate({
          spreadsheetId: GOOGLE_SHEET_ID,
          resource: {
            requests: [{
              "repeatCell": {
                "range": {
                  "sheetId": 0,
                  "startRowIndex": rowNumber - 1,
                  "endRowIndex": rowNumber,
                  "startColumnIndex": 0,
                  "endColumnIndex": GOOGLE_SHEET_HEADERS.length
                },
                "cell": { "userEnteredFormat": { "backgroundColor": DELETED_ROW_COLOR } },
                "fields": "userEnteredFormat.backgroundColor"
              }
            }]
          }
        });
      }
    } else if (rowNumber > 0) {
      // --- ACTION: UPDATE ---
      console.log(`Auto-sync: Updating row ${rowNumber} for ${delivery.trackingId}`);
      await sheets.spreadsheets.values.update({
        spreadsheetId: GOOGLE_SHEET_ID,
        range: `Sheet1!A${rowNumber}`,
        valueInputOption: 'USER_ENTERED',
        resource: { values: [rowData] }
      });
      // Clear background color just in case it was red
      await sheets.spreadsheets.batchUpdate({
        spreadsheetId: GOOGLE_SHEET_ID,
        resource: {
          requests: [{
            "repeatCell": {
              "range": { "sheetId": 0, "startRowIndex": rowNumber - 1, "endRowIndex": rowNumber, "startColumnIndex": 0, "endColumnIndex": GOOGLE_SHEET_HEADERS.length },
              "cell": { "userEnteredFormat": { "backgroundColor": null } },
              "fields": "userEnteredFormat.backgroundColor"
            }
          }]
        }
      });
    } else if (action === 'create') {
      // --- ACTION: CREATE (Append Row) ---
      console.log(`Auto-sync: Creating new row for ${delivery.trackingId}`);
      if (sheetData.length === 0) { // Agar sheet bilkul khaali hai
        await sheets.spreadsheets.values.append({
          spreadsheetId: GOOGLE_SHEET_ID,
          range: 'Sheet1!A1',
          valueInputOption: 'USER_ENTERED',
          resource: { values: [GOOGLE_SHEET_HEADERS] } // Pehle Headers daalo
        });
      }
      await sheets.spreadsheets.values.append({
        spreadsheetId: GOOGLE_SHEET_ID,
        range: 'Sheet1!A1',
        valueInputOption: 'USER_ENTERED',
        resource: { values: [rowData] }
      });
    }
  } catch (sheetError) {
    console.error(`Auto-sync Error for ${deliveryId}:`, sheetError.message);
  }
}

// 4.6 DraftOrder Schema (ADD THIS)
const draftOrderSchema = new mongoose.Schema({
  source: { type: String, default: 'margmart' },
  orderNumber: { type: String, unique: true, required: true },
  customerName: String,
  phone: String,
  address: String,
  pincode: String,
  amount: Number,
  paymentMethod: { type: String, default: 'Prepaid' },
  status: { type: String, enum: ['DRAFT', 'SENT', 'CONVERTED', 'SKIPPED'], default: 'DRAFT' },
  rawEmailId: String
}, { timestamps: true });

const DraftOrder = mongoose.model('DraftOrder', draftOrderSchema);


// --- 5. Auth APIs --- (No changes)
// 5.1. Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) return res.status(404).json({ message: 'User not found' });
    if (!user.isActive) return res.status(403).json({ message: 'User deactivated' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid password' });

    const token = jwt.sign(
      { userId: user._id, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '3d' }
    );

    res.json({ message: 'Login successful!', token, name: user.name, role: user.role });
  } catch (e) {
    res.status(500).json({ message: 'Server error during login' });
  }
});

// --- (NEW) 5.5. Static File Server ---
// Yeh manifest.json, style.css, etc. jaisi files ko serve karega
// Yeh line HTML routes (Section 6) se PEHLE honi zaroori hai
app.use(express.static(path.join(__dirname)));


// --- 6. HTML Page Routes --- (No changes)
//app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
//---app.get('/track', (req, res) => res.sendFile(path.join(__dirname, 'track.html')));
//app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
//app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
//app.get('/delivery', (req, res) => res.sendFile(path.join(__dirname, 'delivery.html')));
//app.get('/manager', (req, res) => res.sendFile(path.join(__dirname, 'manager.html')));
app.get('/firebase-messaging-sw.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.sendFile(path.join(__dirname, 'firebase-messaging-sw.js'));
});


// --- 7. Admin API Routes ---

// 7.1. Book Courier (Assigns to Manager)
app.post('/book', auth(['admin']), async (req, res) => {
  try {
    const { name, address, phone, paymentMethod, billAmount, managerId } = req.body;
    if (!name || !address) {
      return res.status(400).json({ message: 'Customer Name and Address are required.' });
    }
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    const trackingId = 'SAHYOG' + Date.now().toString().slice(-6);

    const newDelivery = new Delivery({
      customerName: name, customerAddress: address, customerPhone: phone,
      trackingId: trackingId, otp: otp,
      paymentMethod: paymentMethod, billAmount: billAmount || 0,
      assignedTo: null,
      assignedByManager: managerId || null,
      assignedBoyDetails: null,
      statusUpdates: [{ status: 'Booked' }],
      codPaymentStatus: (paymentMethod === 'Prepaid') ? 'Not Applicable' : 'Pending'
    });
    await newDelivery.save();

    // 🔥 DRAFT CONVERT FIX (EXACT PLACE)
    if (req.body.draftId) {
      await DraftOrder.findByIdAndUpdate(
        req.body.draftId,
        { status: 'CONVERTED' }
      );
    }

    // --- AUTO-SYNC (CREATE) ---
    syncSingleDeliveryToSheet(newDelivery._id, 'create').catch(console.error);

    // 🔔 NOTIFY MANAGER ON BOOKING
    if (managerId) {
      const manager = await User.findById(managerId);

      if (manager?.fcmTokens?.length) {
        for (const token of manager.fcmTokens) {
          await sendNotification(
            token,
            "🆕 New Delivery Booked",
            `Manager saahab aapko ek nayi picup request mili hai ise jaldi se delivery waale bhaiya ko assign kar dijiye.  
Tracking ID: ${trackingId} | ${getISTTime()}`,
            manager._id,
            {
              headers: { Urgency: "high" },
              requireInteraction: true,
              tag: `booking-${trackingId}`,
              link: "https://sahyogdelivery.vercel.app/login.html",
              icon: "https://sahyogdelivery.vercel.app/favicon.png"
            }
          );
        }

        console.log("🔔 FCM SENT → MANAGER (BOOKING)");
      }
    }


    res.status(201).json({ message: 'Courier booked successfully!', trackingId: trackingId, otp: otp });
  } catch (error) {
    console.error("Booking Error:", error);
    if (error.name === 'ValidationError') {
      res.status(400).json({ message: 'Booking validation failed', errors: error.errors });
    } else {
      res.status(500).json({ message: 'Booking failed due to server error', error: error.message });
    }
  }
});

// 7.2. Get All Deliveries (No changes)
app.get('/admin/deliveries', auth(['admin']), async (req, res) => {
  try {
    const deliveries = await Delivery.find()
      .populate('assignedByManager', 'name')
      .populate('assignedTo', 'name email isActive phone')
      .sort({ createdAt: -1 });
    res.json(deliveries);
  } catch (error) {
    console.error("Fetch Deliveries Error:", error);
    res.status(500).json({ message: 'Error fetching deliveries' });
  }
});

// 7.2b. Get COD cash orders pending admin cash handover
app.get('/admin/cash-orders', auth(['admin']), async (req, res) => {
  try {
    const deliveries = await Delivery.find({
      paymentMethod: 'COD',
      codPaymentStatus: 'Paid - Cash',
      statusUpdates: { $elemMatch: { status: 'Delivered' } },
      cashReceivedByAdmin: { $ne: true }
    })
      .populate('assignedByManager', 'name')
      .populate('assignedTo', 'name email isActive phone')
      .sort({ completedAt: -1, createdAt: -1 });
    res.json(deliveries);
  } catch (error) {
    console.error("Fetch Cash Orders Error:", error);
    res.status(500).json({ message: 'Error fetching cash orders' });
  }
});

// 7.2c. Get completed deliveries from admin settlement perspective
app.get('/admin/completed-deliveries', auth(['admin']), async (req, res) => {
  try {
    const deliveries = await Delivery.find({
      statusUpdates: { $elemMatch: { status: 'Delivered' } },
      $or: [
        { paymentMethod: 'Prepaid' },
        { codPaymentStatus: 'Paid - Online' },
        { codPaymentStatus: 'Not Applicable' },
        { paymentMethod: 'COD', codPaymentStatus: 'Paid - Cash', cashReceivedByAdmin: true }
      ]
    })
      .populate('assignedByManager', 'name')
      .populate('assignedTo', 'name email isActive phone')
      .sort({ completedAt: -1, createdAt: -1 });
    res.json(deliveries);
  } catch (error) {
    console.error("Fetch Admin Completed Deliveries Error:", error);
    res.status(500).json({ message: 'Error fetching completed deliveries' });
  }
});

// 7.3. Get All Users (Removed duplicate route)
app.get('/admin/users', auth(['admin']), async (req, res) => {
  try {
    const users = await User.find({}, '-password')
      .populate('createdByManager', '_id name')
      .sort({ role: 1, name: 1 });
    res.json(users);
  } catch (error) {
    console.error("Fetch Users Error:", error);
    res.status(500).json({ message: 'Error fetching users' });
  }
});

// 7.3b. Get All ACTIVE Managers (No changes)
app.get('/admin/managers', auth(['admin']), async (req, res) => {
  try {
    const managers = await User.find(
      { role: 'manager', isActive: true },
      'name _id'
    ).sort({ name: 1 });
    res.json(managers);
  } catch (error) {
    console.error("Fetch Active Managers Error:", error);
    res.status(500).json({ message: 'Error fetching managers' });
  }
});

// 7.4. Create User (No changes)
app.post('/admin/create-user', auth(['admin']), async (req, res) => {
  const { name, email, password, phone, role, managerId } = req.body;

  if (role === "delivery" && !managerId) {
    return res.status(400).json({ message: "Manager required for delivery boy" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({
    name, email: email.toLowerCase(), password: hashedPassword,
    phone, role,
    createdByManager: role === "delivery" ? managerId : null
  });

  try {
    await newUser.save();
    res.status(201).json({ message: 'User created successfully!' });
  } catch (error) {
    console.error("Create User Error:", error);
    if (error.code === 11000) {
      res.status(409).json({ message: 'Email already exists.' });
    } else {
      res.status(500).json({ message: 'Server error creating user', error: error.message });
    }
  }
});

app.get('/manager/pending', auth(['manager']), async (req, res) => {
  const deliveries = await Delivery.find({
    assignedByManager: req.user.userId,
    statusUpdates: { $not: { $elemMatch: { status: 'Delivered' } } }
  }).populate('assignedTo', 'name');
  res.json(deliveries);
});

app.get('/manager/completed', auth(['manager']), async (req, res) => {
  const deliveries = await Delivery.find({
    assignedByManager: req.user.userId,
    statusUpdates: { $elemMatch: { status: 'Delivered' } }
  }).populate('assignedTo', 'name');
  res.json(deliveries);
});

app.get('/manager/completed-deliveries', auth(['manager']), async (req, res) => {
  const list = await Delivery.find({
    assignedByManager: req.user.userId,
    statusUpdates: { $elemMatch: { status: 'Delivered' } }
  }).populate('assignedTo', 'name');
  res.json(list);
});

app.get('/delivery/completed-deliveries', auth(['delivery']), async (req, res) => {
  const list = await Delivery.find({
    assignedTo: req.user.userId,
    statusUpdates: { $elemMatch: { status: 'Delivered' } }

  });
  res.json(list);
});

app.get('/delivery/completed', auth(['delivery']), async (req, res) => {
  const deliveries = await Delivery.find({
    assignedTo: req.user.userId,
    statusUpdates: { $elemMatch: { status: 'Delivered' } }

  });
  res.json(deliveries);
});

// 7.5. Update User Details (No changes)
app.put('/admin/user/:userId', auth(['admin']), async (req, res) => {
  try {
    const { userId } = req.params;
    const { name, email, phone, role, managerId } = req.body;
    if (!name || !email || !role || !['admin', 'manager', 'delivery'].includes(role)) {
      return res.status(400).json({ message: 'Valid Name, Email, Role required' });
    }
    if (role === 'delivery' && !managerId) {
      return res.status(400).json({ message: 'Manager required for delivery boy' });
    }
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    user.name = name;
    user.email = email.toLowerCase();
    user.phone = phone;
    user.role = role;
    user.createdByManager = role === 'delivery' ? managerId : null;
    await user.save();
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    console.error("Update User Error:", error);
    if (error.code === 11000) {
      res.status(409).json({ message: 'Email already exists for another user.' });
    } else {
      res.status(500).json({ message: 'Server error updating user', error: error.message });
    }
  }
});

// 7.6. Update User Password (No changes)
app.patch('/admin/user/:userId/password', auth(['admin']), async (req, res) => {
  try {
    const { userId } = req.params;
    const { password } = req.body;
    if (!password || password.length < 6) {
      return res.status(400).json({ message: 'New password required (min 6 chars)' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await User.findByIdAndUpdate(userId, { password: hashedPassword });
    if (!result) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error("Update Password Error:", error);
    res.status(500).json({ message: 'Server error updating password', error: error.message });
  }
});

// 7.7. Toggle User Active Status (No changes)
app.patch('/admin/user/:userId/toggle-active', auth(['admin']), async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    user.isActive = !user.isActive;
    await user.save();
    res.json({ message: `User ${user.isActive ? 'activated' : 'deactivated'}` });
  } catch (error) {
    console.error("Toggle Active Error:", error);
    res.status(500).json({ message: 'Server error toggling status', error: error.message });
  }
});

// 7.8. Cancel Delivery
app.patch('/admin/delivery/:deliveryId/cancel', auth(['admin']), async (req, res) => {
  try {
    const { deliveryId } = req.params;
    const delivery = await Delivery.findById(deliveryId);
    if (!delivery) {
      return res.status(404).json({ message: 'Delivery not found' });
    }
    if (!['Delivered', 'Cancelled'].includes(delivery.currentStatus)) {
      delivery.statusUpdates.push({ status: 'Cancelled' });
      delivery.codPaymentStatus = 'Not Applicable';
      await delivery.save();

      // --- AUTO-SYNC (UPDATE) ---
      syncSingleDeliveryToSheet(delivery._id, 'update').catch(console.error);


      res.json({ message: 'Delivery cancelled' });
    } else {
      res.status(400).json({ message: 'Delivery already completed or cancelled' });
    }
  } catch (error) {
    console.error("Cancel Delivery Error:", error);
    res.status(500).json({ message: 'Server error cancelling delivery', error: error.message });
  }
});

// 7.9. Delete Delivery
app.delete('/admin/delivery/:deliveryId', auth(['admin']), async (req, res) => {
  try {
    const { deliveryId } = req.params;

    // --- AUTO-SYNC (DELETE/HIGHLIGHT) ---
    // Delete karne se PEHLE call karna zaroori hai
    syncSingleDeliveryToSheet(deliveryId, 'delete').catch(console.error);

    const result = await Delivery.findByIdAndDelete(deliveryId);
    if (!result) {
      return res.status(404).json({ message: 'Delivery not found' });
    }
    res.json({ message: 'Delivery deleted successfully' });
  } catch (error) {
    console.error("Delete Delivery Error:", error);
    res.status(500).json({ message: 'Server error deleting delivery', error: error.message });
  }
});

// 7.9b. Mark COD cash as received by admin
app.patch('/admin/delivery/:deliveryId/receive-cash', auth(['admin']), async (req, res) => {
  try {
    const { deliveryId } = req.params;
    const delivery = await Delivery.findById(deliveryId);
    if (!delivery) {
      return res.status(404).json({ message: 'Delivery not found' });
    }

    if (delivery.paymentMethod !== 'COD') {
      return res.status(400).json({ message: 'Only COD deliveries are eligible' });
    }
    if (delivery.codPaymentStatus !== 'Paid - Cash') {
      return res.status(400).json({ message: 'Cash was not marked as collected by delivery boy' });
    }
    if (delivery.currentStatus !== 'Delivered') {
      return res.status(400).json({ message: 'Delivery is not completed yet' });
    }
    if (delivery.cashReceivedByAdmin) {
      return res.status(400).json({ message: 'Cash already received for this order' });
    }

    delivery.cashReceivedByAdmin = true;
    delivery.cashReceivedAt = new Date();
    await delivery.save();

    syncSingleDeliveryToSheet(delivery._id, 'update').catch(console.error);

    res.json({ message: 'Cash received and order moved to completed deliveries' });
  } catch (error) {
    console.error("Receive Cash Error:", error);
    res.status(500).json({ message: 'Server error while marking cash received', error: error.message });
  }
});

// 7.10. Bulk Cancel Deliveries (No auto-sync, use manual sync)
app.post('/admin/deliveries/bulk-cancel', auth(['admin']), async (req, res) => {
  try {
    const { deliveryIds } = req.body;
    if (!deliveryIds || !Array.isArray(deliveryIds) || deliveryIds.length === 0) {
      return res.status(400).json({ message: 'No delivery IDs provided.' });
    }
    const result = await Delivery.updateMany(
      { _id: { $in: deliveryIds }, 'statusUpdates.status': { $nin: ['Delivered', 'Cancelled'] } },
      { $push: { statusUpdates: { status: 'Cancelled' } }, $set: { codPaymentStatus: 'Not Applicable' } }
    );
    res.json({ message: `Attempted cancel on ${deliveryIds.length}. Updated: ${result.modifiedCount}.`, cancelledCount: result.modifiedCount });
  } catch (error) {
    console.error("Bulk Cancel Error:", error);
    res.status(500).json({ message: 'Bulk cancel failed', error: error.message });
  }
});

// 7.11. Bulk Delete Deliveries (No auto-sync, use manual sync)
app.post('/admin/deliveries/bulk-delete', auth(['admin']), async (req, res) => {
  try {
    const { deliveryIds } = req.body;
    if (!deliveryIds || !Array.isArray(deliveryIds) || deliveryIds.length === 0) {
      return res.status(400).json({ message: 'No delivery IDs provided.' });
    }
    // Note: We don't auto-sync bulk deletes. User should use the manual sync button,
    // which will find these missing rows and highlight them.
    const result = await Delivery.deleteMany({ _id: { $in: deliveryIds } });
    res.json({ message: `Attempted delete for ${deliveryIds.length}. Deleted: ${result.deletedCount}.`, deletedCount: result.deletedCount });
  } catch (error) {
    console.error("Bulk Delete Error:", error);
    res.status(500).json({ message: 'Bulk delete failed', error: error.message });
  }
});

// --- 7.12. Admin: Sync Deliveries (MANUAL) ---
app.post('/admin/sync-to-google-sheet', auth(['admin']), async (req, res) => {

  if (!sheets) {
    console.error("Google Sheets API is not configured. Check env variables.");
    return res.status(500).json({ message: 'Google Sheets API is not configured on the server.' });
  }

  try {
    // --- Smart Sync Logic (FIXED - 9 Columns) ---
    // 1. Get all data from DB
    const allDeliveries = await Delivery.find()
      .populate('assignedByManager', 'name')
      .populate('assignedTo', 'name')
      .sort({ createdAt: 1 });

    // 2. Get all data from Sheet
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: GOOGLE_SHEET_ID,
      range: 'Sheet1!A:I', // A se I (9 columns)
    });
    const sheetData = response.data.values || [];

    const sheetMap = new Map();
    if (sheetData.length > 1) {
      for (let i = 1; i < sheetData.length; i++) {
        const trackingId = sheetData[i][0];
        if (trackingId) {
          sheetMap.set(trackingId, { row: i + 1, data: sheetData[i] });
        }
      }
    }

    // Headers (FIXED - 9 Columns)
    const headerRow = [
      'Tracking ID', 'Customer Name', 'Status', 'Payment', 'Payment Status',
      'Assigned Manager', 'Assigned Boy', 'OTP', 'Date'
    ];

    // Check karo ki sheet khaali hai ya header galat hain
    if (sheetData.length === 0) {
      await sheets.spreadsheets.values.append({
        spreadsheetId: GOOGLE_SHEET_ID,
        range: 'Sheet1!A1',
        valueInputOption: 'USER_ENTERED',
        resource: { values: [headerRow] }
      });
      console.log("Manual Sync: Added headers to empty sheet.");
    } else {
      // Headers ko overwrite kardo taaki hamesha sahi rahein
      await sheets.spreadsheets.values.update({
        spreadsheetId: GOOGLE_SHEET_ID,
        range: 'Sheet1!A1', // Pehli row
        valueInputOption: 'USER_ENTERED',
        resource: { values: [headerRow] }
      });
    }

    const dbTrackingIds = new Set();
    const rowsToUpdate = [];
    const rowsToAppend = [];
    const resetColorRequests = []; // Highlight hatane ke liye

    // 3. Compare DB vs Sheet
    allDeliveries.forEach(d => {
      const trackingId = d.trackingId;
      dbTrackingIds.add(trackingId);

      // Data row (FIXED - 9 Columns)
      const rowData = [
        d.trackingId || 'N/A',
        d.customerName || 'N/A',
        d.currentStatus || 'N/A',
        (d.paymentMethod === 'COD' ? `₹${d.billAmount}` : 'Prepaid'),
        (d.paymentMethod === 'COD' ? (d.codPaymentStatus || 'Pending') : 'N/A'),
        d.assignedByManager ? d.assignedByManager.name : 'N/A',
        d.assignedTo ? d.assignedTo.name : 'N/A',
        d.otp || 'N/A',
        new Date(d.createdAt).toLocaleDateString('en-IN')
      ];

      const existingEntry = sheetMap.get(trackingId);
      if (existingEntry) {
        // --- Prepare for UPDATE ---
        rowsToUpdate.push({
          range: `Sheet1!A${existingEntry.row}`,
          values: [rowData]
        });
        // Un-highlight bhi karo (agar pehle deleted tha)
        resetColorRequests.push({
          "repeatCell": {
            "range": { "sheetId": 0, "startRowIndex": existingEntry.row - 1, "endRowIndex": existingEntry.row, "startColumnIndex": 0, "endColumnIndex": headerRow.length },
            "cell": { "userEnteredFormat": { "backgroundColor": null } },
            "fields": "userEnteredFormat.backgroundColor"
          }
        });
      } else {
        // --- Prepare for APPEND ---
        rowsToAppend.push(rowData);
      }
    });

    // 4. Find deleted items and prepare for HIGHLIGHT
    const highlightRequests = [];
    sheetMap.forEach((value, trackingId) => {
      if (!dbTrackingIds.has(trackingId)) {
        // Yeh Sheet me hai, par DB me nahi -> highlight karo
        highlightRequests.push({
          "repeatCell": {
            "range": {
              "sheetId": 0,
              "startRowIndex": value.row - 1, "endRowIndex": value.row,
              "startColumnIndex": 0, "endColumnIndex": headerRow.length
            },
            "cell": { "userEnteredFormat": { "backgroundColor": DELETED_ROW_COLOR } },
            "fields": "userEnteredFormat.backgroundColor"
          }
        });
      }
    });

    // 5. Execute all changes
    if (rowsToUpdate.length > 0) {
      await sheets.spreadsheets.values.batchUpdate({
        spreadsheetId: GOOGLE_SHEET_ID,
        resource: {
          valueInputOption: 'USER_ENTERED',
          data: rowsToUpdate
        }
      });
      console.log(`Manual Sync: Updated ${rowsToUpdate.length} rows.`);
    }
    if (rowsToAppend.length > 0) {
      await sheets.spreadsheets.values.append({
        spreadsheetId: GOOGLE_SHEET_ID,
        range: 'Sheet1!A1',
        valueInputOption: 'USER_ENTERED',
        resource: { values: rowsToAppend }
      });
      console.log(`Manual Sync: Appended ${rowsToAppend.length} new rows.`);
    }

    // Colors ko ek saath update karo
    const allColorRequests = [...highlightRequests, ...resetColorRequests];
    if (allColorRequests.length > 0) {
      await sheets.spreadsheets.batchUpdate({
        spreadsheetId: GOOGLE_SHEET_ID,
        resource: { requests: allColorRequests }
      });
      console.log(`Manual Sync: Highlighted ${highlightRequests.length} rows, Reset color for ${resetColorRequests.length} rows.`);
    }

    res.json({
      message: `Sync complete! Updated: ${rowsToUpdate.length}, Appended: ${rowsToAppend.length}, Highlighted: ${highlightRequests.length}.`
    });

  } catch (error) {
    console.error("Error syncing to Google Sheet:", error);
    res.status(500).json({ message: 'Error syncing to Google Sheet', error: error.message });
  }
});

app.get('/manager/assigned-pickups', auth(['manager']), async (req, res) => {
  try {
    const pickups = await Delivery.find({
      assignedByManager: req.user.userId,
      assignedTo: null
    }).sort({ createdAt: -1 });

    res.json(pickups);
  } catch (err) {
    res.status(500).json({ message: 'Failed to load pickups' });
  }
});

app.get('/manager/all-pending-deliveries', auth(['manager']), async (req, res) => {
  try {
    const deliveries = await Delivery.find({
      assignedByManager: req.user.userId,
      'statusUpdates.status': { $ne: 'Delivered' }
    })
      .populate('assignedTo', 'name phone')
      .sort({ createdAt: -1 });

    res.json(deliveries);
  } catch (err) {
    res.status(500).json({ message: 'Failed to load pending deliveries' });
  }
});

// --- 7.12 Draft Orders API Routes ---
// 📬 Get Draft Orders
app.get('/api/drafts', auth(['admin']), async (req, res) => {
  const drafts = await DraftOrder.find({ status: 'DRAFT' }).sort({ createdAt: -1 });
  res.json(drafts);
});

// DELETE Draft
// DELETE Draft Order
app.delete('/api/drafts/:id', auth(['admin']), async (req, res) => {
  try {
    const draft = await DraftOrder.findByIdAndDelete(req.params.id);
    if (!draft) {
      return res.status(404).json({ message: "Draft not found" });
    }
    res.json({ message: "Draft deleted successfully" });
  } catch (err) {
    console.error("Delete Draft Error:", err);
    res.status(500).json({ message: "Failed to delete draft" });
  }
});

// --- 7.13 Create Draft Order ---
// 📩 Fetch Margmart Orders from Email (MANUAL TRIGGER)
app.post('/api/fetch-margmart-orders', auth(['admin']), async (req, res) => {
  try {
    await fetchMargmartEmails();
    res.json({ message: 'Margmart emails fetched successfully' });
  } catch (err) {
    console.error('Email fetch error:', err);
    res.status(500).json({ message: 'Failed to fetch emails' });
  }
});

async function fetchMargmartEmails() {
  const auth = new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET,
    process.env.GMAIL_REDIRECT_URI
  );

  auth.setCredentials({
    refresh_token: process.env.GMAIL_REFRESH_TOKEN
  });

  const gmail = google.gmail({ version: 'v1', auth });

  // 🔴 YAHI PAR noreply@margmart.com LAGTA HAI
  const res = await gmail.users.messages.list({
    userId: 'me',
    q: 'from:noreply@margmart.com'
  });

  if (!res.data.messages) return;

  for (const msg of res.data.messages) {
    const full = await gmail.users.messages.get({
      userId: 'me',
      id: msg.id,
      format: 'full'
    });

    let body = "";

    if (full.data.payload.parts) {
      const textPart = full.data.payload.parts.find(
        p => p.mimeType === "text/plain"
      );
      const htmlPart = full.data.payload.parts.find(
        p => p.mimeType === "text/html"
      );

      const part = textPart || htmlPart;
      if (!part) continue;

      body = Buffer.from(part.body.data, "base64").toString("utf-8");
    } else if (full.data.payload.body?.data) {
      body = Buffer.from(
        full.data.payload.body.data,
        "base64"
      ).toString("utf-8");
    }

    const cleanText = body.replace(/<[^>]*>/g, ' ');
    const parsed = parseMargmartEmail(cleanText);


    if (!parsed?.orderNumber || !parsed?.address) {
      console.log("⚠️ Email parsed but required fields missing");
      continue;
    }

    // Duplicate check
    const exists = await DraftOrder.findOne({ orderNumber: parsed.orderNumber });
    if (exists) {
      console.log(`↩️ Draft already exists for order ${parsed.orderNumber}`);
      continue;
    }

    const pincode = extractPincode(parsed.address);

    // ❌ Skip if not serviceable pincode
    if (pincode !== '458110') {
      await DraftOrder.create({
        ...parsed,
        pincode,
        status: 'SKIPPED',
        rawEmailId: msg.id
      });
      console.log(`⛔ Skipped order ${parsed.orderNumber} (${pincode})`);
      continue;
    }

    // ✅ Create Draft
    await DraftOrder.create({
      ...parsed,
      pincode,
      rawEmailId: msg.id
    });

    // ✅ mark email as processed
    await gmail.users.messages.modify({
      userId: 'me',
      id: msg.id,
      requestBody: {
        removeLabelIds: ['UNREAD']
      }
    });
    console.log(`📨 Draft created for order ${parsed.orderNumber}`);
  }
}


// 🔁 Auto fetch Margmart emails every 5 minutes
cron.schedule("*/5 * * * *", async () => {
  console.log("⏰ Auto fetching Margmart emails...");
  try {
    await fetchMargmartEmails();
  } catch (e) {
    console.error("Auto fetch failed", e.message);
  }
});

// --- 7.14. Get Drafts ---
// 🔥 GET ALL DRAFT ORDERS (FOR ADMIN UI)
app.get('/admin/drafts', auth(['admin']), async (req, res) => {
  try {
    const drafts = await DraftOrder.find({
      status: 'DRAFT'
    }).sort({ createdAt: -1 });

    res.json(drafts);
  } catch (err) {
    console.error("Draft fetch error:", err);
    res.status(500).json({ message: 'Failed to fetch drafts' });
  }
});

// 7.x. Book Courier FROM Draft
app.post('/admin/book-from-draft/:draftId', auth(['admin']), async (req, res) => {
  try {
    const { draftId } = req.params;
    const { managerId } = req.body;

    // 1️⃣ Draft uthao
    const draft = await DraftOrder.findById(draftId);
    if (!draft) {
      return res.status(404).json({ message: "Draft not found" });
    }

    if (draft.status !== 'DRAFT') {
      return res.status(400).json({ message: "Draft already processed" });
    }

    // 2️⃣ Delivery banao
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    const trackingId = 'SAHYOG' + Date.now().toString().slice(-6);

    const delivery = new Delivery({
      customerName: draft.customerName,
      customerAddress: draft.address,
      customerPhone: draft.phone,
      trackingId,
      otp,
      paymentMethod: draft.paymentMethod || 'Prepaid',
      billAmount: draft.amount || 0,
      assignedByManager: managerId || null,
      statusUpdates: [{ status: 'Booked' }],
      codPaymentStatus: 'Not Applicable'
    });

    await delivery.save();

    // 3️⃣ 🔥 YAHI PAR ADD KARNA THA (IMPORTANT)
    draft.status = "CONVERTED";
    await draft.save();

    // 4️⃣ Google Sheet sync
    syncSingleDeliveryToSheet(delivery._id, 'create').catch(console.error);

    res.json({
      message: "Draft converted & courier booked",
      trackingId
    });

  } catch (err) {
    console.error("Book from draft error:", err);
    res.status(500).json({ message: "Failed to book from draft" });
  }
});

//--- Convert Draft to Comopleted Delivery ---
app.post('/admin/convert-draft-to-courier', auth(['admin']), async (req, res) => {
  try {
    const { draftId, managerId, paymentMethod } = req.body;

    const draft = await DraftOrder.findById(draftId);
    if (!draft) {
      return res.status(404).json({ message: "Draft not found" });
    }

    // ✅ 1. Courier create
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    const trackingId = 'SAHYOG' + Date.now().toString().slice(-6);

    const delivery = new Delivery({
      customerName: draft.customerName,
      customerAddress: draft.address,
      customerPhone: draft.phone,
      trackingId,
      otp,
      paymentMethod: paymentMethod || 'Prepaid',
      billAmount: draft.amount || 0,
      assignedByManager: managerId || null,
      statusUpdates: [{ status: 'Booked' }]
    });

    await delivery.save();

    // ✅ 2. 🔥 MOST IMPORTANT LINE (THIS WAS MISSING)
    draft.status = "CONVERTED";
    await draft.save();

    res.json({
      message: "Draft converted & courier booked",
      trackingId
    });

  } catch (err) {
    console.error("Convert draft error:", err);
    res.status(500).json({ message: "Conversion failed" });
  }
});

// --- 8. Manager API Routes ---

// 8.1. Manager: Get Pickups assigned (No changes)
app.get('/manager/assigned-pickups', auth(['manager']), async (req, res) => {
  try {
    const deliveries = await Delivery.find({
      assignedByManager: req.user.userId,
      assignedTo: null,
      'statusUpdates.status': 'Booked'
    }).sort({ createdAt: 1 });
    res.json(deliveries);
  } catch (error) {
    console.error("Fetch Assigned Pickups Error:", error);
    res.status(500).json({ message: 'Error fetching assigned pickups' });
  }
});

// 8.2. Manager: Get Delivery Boys (No changes)
app.get('/manager/my-boys', auth(['manager']), async (req, res) => {
  const boys = await User.find({
    role: 'delivery',
    createdByManager: req.user.userId
  }).select('-password');
  res.json(boys);
});


// 8.3. Manager: Create Delivery Boy (No changes)
app.post('/manager/create-delivery-boy', auth(['manager']), async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'Name, Email, Password required' });
    const lowerCaseEmail = email.toLowerCase();
    const existingUser = await User.findOne({ email: lowerCaseEmail });
    if (existingUser) return res.status(409).json({ message: 'Email already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email: lowerCaseEmail, password: hashedPassword, phone, role: 'delivery', createdByManager: req.user.userId });
    await newUser.save();
    res.status(201).json({ message: 'Delivery boy created!', user: { _id: newUser._id, name: newUser.name, email: newUser.email } });
  } catch (error) {
    console.error("Manager Create Boy Error:", error);
    if (error.code === 11000) {
      res.status(409).json({ message: 'Email already exists (DB constraint).' });
    } else {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  }
});

// 8.4. Manager: Assign Delivery to Boy
app.patch('/manager/assign-delivery/:deliveryId', auth(['manager']), async (req, res) => {
  try {
    const { deliveryId } = req.params;
    const { assignedBoyId } = req.body;
    if (!assignedBoyId) return res.status(400).json({ message: 'Delivery Boy ID is required' });

    const delivery = await Delivery.findById(deliveryId);
    if (!delivery) return res.status(404).json({ message: 'Delivery not found' });
    if (!delivery.assignedByManager || delivery.assignedByManager.toString() !== req.user.userId) return res.status(403).json({ message: 'Delivery not assigned to you' });
    if (delivery.assignedTo) return res.status(400).json({ message: 'Delivery already assigned to a boy' });

    const boy = await User.findOne({ _id: assignedBoyId, role: 'delivery', createdByManager: req.user.userId });
    if (!boy) return res.status(404).json({ message: 'Delivery boy not found or does not belong to you' });
    if (!boy.isActive) return res.status(400).json({ message: 'Cannot assign to inactive delivery boy' });

    delivery.assignedTo = boy._id;
    delivery.assignedBoyDetails = { name: boy.name, phone: boy.phone };
    delivery.assignedAt = new Date();
    delivery.statusUpdates.push({ status: 'Boy Assigned', timestamp: new Date() });
    await delivery.save();

    // --- AUTO-SYNC (UPDATE) ---
    syncSingleDeliveryToSheet(delivery._id, 'update').catch(console.error);

    // Debug: log token count for this boy
    const boyTokens = Array.isArray(boy.fcmTokens) ? boy.fcmTokens : (boy.fcmTokens ? [boy.fcmTokens] : []);
    console.log(`[Assign] Delivery ${delivery.trackingId} assigned to ${boy.name}. fcmTokens count:`, boyTokens.length);

    if (boyTokens.length) {
      try {
        for (const token of boyTokens) {
          await sendNotification(
            token,
            "Ooo Bhaiya naya picup mil gaya🚀",
            `Bhaiya aapko ek nayi delivery assign hui hai. Jaldi se pickup karne Sahyog par chale jayiye. Tracking ID: ${delivery.trackingId} | ${getISTTime()}`,
            boy._id,
            {
              headers: { Urgency: "high" },
              icon: "https://sahyogdelivery.vercel.app/favicon.png",
              badge: "https://sahyogdelivery.vercel.app/favicon.png",
              tag: `delivery-${Date.now()}`,
              requireInteraction: true,
              link: "https://sahyogdelivery.vercel.app/login.html"
            }
          );
        }
        console.log("🔔 FCM SENT → DELIVERY (assigned)");
      } catch (err) {
        console.error("❌ FCM FAILED → DELIVERY (assigned):", err.code, err.message);
      }
    } else {
      console.log("⚠️ DELIVERY has no FCM tokens:", boy.name);
    }



    // --- AUTO-SYNC (UPDATE) ---
    syncSingleDeliveryToSheet(delivery._id, 'update').catch(console.error);

    res.json({ message: 'Delivery assigned successfully', delivery: { _id: delivery._id, trackingId: delivery.trackingId, currentStatus: delivery.currentStatus } });
  } catch (error) {
    console.error("Assign Delivery Error:", error);
    res.status(500).json({ message: 'Server error during assignment', error: error.message });
  }
});

// 8.5. Manager: Get ALL pending deliveries (No changes)
app.get('/manager/all-pending-deliveries', auth(['manager']), async (req, res) => {
  try {
    const deliveries = await Delivery.find({
      assignedByManager: req.user.userId,
      'statusUpdates.status': { $nin: ['Delivered', 'Cancelled'] }
    })
      .populate('assignedTo', 'name phone')
      .sort({ createdAt: -1 });

    res.json(deliveries);
  } catch (error) {
    console.error("Fetch All Pending Deliveries Error:", error);
    res.status(500).json({ message: 'Error fetching all pending deliveries' });
  }
});

// 8.6. Manager: Reassign Delivery
app.post('/manager/reassign-delivery/:deliveryId', auth(['manager']), async (req, res) => {
  try {
    const { deliveryId } = req.params;
    const { newDeliveryBoyId } = req.body;
    const managerId = req.user.userId;

    const delivery = await Delivery.findById(deliveryId);

    if (!delivery) {
      return res.status(404).json({ message: 'Delivery not found' });
    }

    if (delivery.statusUpdates.some(update => update.status === 'Delivered')) {
      return res.status(400).json({ message: 'Cannot reassign a delivered delivery' });
    }

    const oldAssignedToId = delivery.assignedTo;
    const oldDeliveryBoy = oldAssignedToId ? await User.findById(oldAssignedToId) : null;

    const newDeliveryBoy = await User.findById(newDeliveryBoyId);
    if (!newDeliveryBoy || newDeliveryBoy.role !== 'delivery') {
      return res.status(404).json({ message: 'Delivery boy not found or invalid' });
    }
    if (!newDeliveryBoy.isActive) {
      return res.status(400).json({ message: 'Cannot assign to inactive delivery boy' });
    }

    delivery.assignedTo = newDeliveryBoy._id;
    delivery.assignedBoyDetails = { name: newDeliveryBoy.name, phone: newDeliveryBoy.phone };
    delivery.assignedByManager = managerId; // Ensure manager who reassigned is recorded
    delivery.assignedAt = new Date();

    // Add status update for reassignment
    delivery.statusUpdates.push({
      status: 'Reassigned',
      timestamp: new Date(),
      location: 'Manager Panel',
      remarks: `Reassigned from ${oldDeliveryBoy ? oldDeliveryBoy.name : 'Unassigned'} to ${newDeliveryBoy.name}`
    });

    // Also add a 'Boy Assigned' status so the newly assigned delivery boy can proceed with scanning.
    // Only add this if the parcel is not already in a post-pickup state and avoid duplicates.
    const unsafeStatuses = ['Picked Up', 'Out for Delivery', 'Delivered', 'Cancelled'];
    if (delivery.currentStatus !== 'Boy Assigned' && !unsafeStatuses.includes(delivery.currentStatus)) {
      delivery.statusUpdates.push({
        status: 'Boy Assigned',
        timestamp: new Date(),
        location: 'Manager Panel',
        remarks: `Assigned to ${newDeliveryBoy.name} after reassignment`
      });
    }

    await delivery.save();

    // --- AUTO-SYNC (UPDATE) ---
    syncSingleDeliveryToSheet(delivery._id, 'update').catch(console.error);

    // Debug: token counts
    console.log(`[Reassign] Delivery ${delivery.trackingId} reassigned from ${oldDeliveryBoy ? oldDeliveryBoy.name : 'Unassigned'} to ${newDeliveryBoy.name}. New tokens:`, Array.isArray(newDeliveryBoy?.fcmTokens) ? newDeliveryBoy.fcmTokens.length : (newDeliveryBoy?.fcmTokens ? 1 : 0), 'Old tokens:', Array.isArray(oldDeliveryBoy?.fcmTokens) ? oldDeliveryBoy.fcmTokens.length : (oldDeliveryBoy?.fcmTokens ? 1 : 0));

    // Send web push notifications
    const newTokens = Array.isArray(newDeliveryBoy?.fcmTokens) ? newDeliveryBoy.fcmTokens : (newDeliveryBoy?.fcmTokens ? [newDeliveryBoy.fcmTokens] : []);
    if (newTokens.length) {
      try {
        for (const token of newTokens) {
          await sendNotification(
            token,
            "Ooo Bhaiya naya picup mil gaya🚀",
            `Bhaiya aapko ek nayi delivery assign hui hai. Jaldi se pickup karne Sahyog par chale jayiye. Tracking ID: ${delivery.trackingId} | ${getISTTime()}`,
            newDeliveryBoy._id,
            {
              headers: { Urgency: "high" },
              icon: "https://sahyogdelivery.vercel.app/favicon.png",
              badge: "https://sahyogdelivery.vercel.app/favicon.png",
              tag: `delivery-${Date.now()}`,
              requireInteraction: true
            }
          );
        }
        console.log("🔔 FCM SENT → NEW DELIVERY BOY (ASSIGNED)");
      } catch (err) {
        console.error("❌ FCM FAILED → NEW DELIVERY BOY (ASSIGNED):", err.code, err.message);
      }
    } else {
      console.log("⚠️ NEW delivery boy has no FCM tokens:", newDeliveryBoy.name);
    }

    const oldTokens = Array.isArray(oldDeliveryBoy?.fcmTokens) ? oldDeliveryBoy.fcmTokens : (oldDeliveryBoy?.fcmTokens ? [oldDeliveryBoy.fcmTokens] : []);
    if (oldTokens.length) {
      try {
        for (const token of oldTokens) {
          await sendNotification(
            token,
            "Delivery Unassigned",
            `Aapki ek delivery unassign ho gayi hai. Tracking ID: ${delivery.trackingId} | ${getISTTime()}`,
            oldDeliveryBoy._id,
            {
              headers: { Urgency: "high" },
              icon: "https://sahyogdelivery.vercel.app/favicon.png",
              badge: "https://sahyogdelivery.vercel.app/favicon.png",
              tag: `delivery-unassigned-${Date.now()}`,
              requireInteraction: true
            }
          );
        }
        console.log("🔔 FCM SENT → OLD DELIVERY BOY (UNASSIGNED)");
      } catch (err) {
        console.error("❌ FCM FAILED → OLD DELIVERY BOY (UNASSIGNED):", err.code, err.message);
      }
    } else {
      if (oldDeliveryBoy) console.log("⚠️ OLD delivery boy has no FCM tokens:", oldDeliveryBoy.name);
    }

    res.json({ message: 'Delivery reassigned successfully', delivery });

  } catch (error) {
    console.error("Reassign Delivery Error:", error);
    res.status(500).json({ message: 'Error reassigning delivery' });
  }
});

// --- 9. Delivery Boy API Routes ---

// 9.1. Get Assigned Deliveries (No changes)
app.get('/delivery/my-deliveries', auth(['delivery']), async (req, res) => {
  try {
    const deliveries = await Delivery.find({
      assignedTo: req.user.userId,

      // ❌ Completed deliveries hide
      statusUpdates: {
        $not: {
          $elemMatch: { status: "Delivered" }
        }
      }
    })
      .select("trackingId billAmount customerPhone customerName customerAddress statusUpdates paymentMethod codPaymentStatus assignedTo currentStatus")
      .sort({ createdAt: -1 });

    res.json({ deliveries: deliveries || [] });

  } catch (error) {
    console.error("Fetch Assigned Error:", error);
    res.status(500).json({
      success: false,
      message: "Error fetching assigned deliveries"
    });
  }
});

// 9.2. Update Status (PRD Compliant + Legacy Support)
app.post('/delivery/update-status', auth(['delivery']), async (req, res) => {
  try {
    const { trackingId, status: inputStatus } = req.body;
    if (!trackingId) return res.status(400).json({ success: false, message: "trackingId required" });

    const delivery = await Delivery.findOne({ trackingId, assignedTo: req.user.userId });
    if (!delivery) return res.status(404).json({ success: false, message: 'Delivery not found or not assigned to you' });

    if (['Delivered', 'Cancelled'].includes(delivery.currentStatus)) {
      return res.status(400).json({ success: false, message: `Delivery is already ${delivery.currentStatus}` });
    }

    let finalStatus = inputStatus;

    // If status is not provided by frontend, infer it (Legacy Support)
    if (!finalStatus) {
      switch (delivery.currentStatus) {
        case 'Booked':
        case 'Boy Assigned':
          finalStatus = 'Picked Up';
          break;
        case 'Picked Up':
          finalStatus = 'Out for Delivery';
          break;
        default:
          return res.status(400).json({ success: false, message: `Cannot update status from ${delivery.currentStatus}` });
      }
    }

    // Validate status (PRD Requirement)
    const validStatuses = ['Picked Up', 'Out for Delivery'];
    if (!validStatuses.includes(finalStatus)) {
      return res.status(400).json({ success: false, message: `Invalid status: ${finalStatus}. Allowed: ${validStatuses.join(', ')}` });
    }

    delivery.statusUpdates.push({ status: finalStatus, timestamp: new Date() });
    await delivery.save();

    // --- AUTO-SYNC (UPDATE) ---
    syncSingleDeliveryToSheet(delivery._id, 'update').catch(console.error);

    res.json({ success: true, message: `Status updated to ${finalStatus}`, trackingId, status: finalStatus });
  } catch (error) {
    console.error("Update Status Error:", error);
    res.status(400).json({ success: false, message: error.message });
  }
});

// 9.3. Complete Delivery (PRD Compliant)
app.post('/delivery/complete', auth(['delivery', 'admin', 'manager']), async (req, res) => {
  try {
    const { trackingId, otp, paymentType } = req.body; // paymentType: 'cash' | 'online'

    if (!trackingId) return res.status(400).json({ success: false, message: "trackingId required" });
    if (!otp) return res.status(400).json({ success: false, message: "OTP required" });

    // Find delivery
    const delivery = await Delivery.findOne({ trackingId });
    if (!delivery) return res.status(404).json({ success: false, message: "Delivery not found" });

    // Security: Only assigned delivery boy can complete, unless admin/manager
    if (req.user.role === 'delivery' && delivery.assignedTo?.toString() !== req.user.userId) {
      return res.status(403).json({ success: false, message: "You are not authorized to complete this delivery" });
    }

    if (delivery.currentStatus === 'Delivered') {
      return res.status(400).json({ success: false, message: "Already delivered" });
    }

    if (delivery.otp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    // COD Validations
    if (delivery.paymentMethod === 'COD') {
      if (!paymentType) {
        return res.status(400).json({ success: false, message: "paymentType required for COD delivery (cash/online)" });
      }

      if (paymentType === 'online') {
        // Must already be paid from webhook or verified
        if (delivery.codPaymentStatus !== "Paid - Online") {
          return res.status(400).json({ success: false, message: "Online payment not verified yet. Please ensure payment is successful." });
        }
      } else if (paymentType === 'cash') {
        delivery.codPaymentStatus = "Paid - Cash";
      } else {
        return res.status(400).json({ success: false, message: "Invalid paymentType. Use 'cash' or 'online'." });
      }
    } else {
      // For Prepaid
      delivery.codPaymentStatus = "Not Applicable";
    }

    // Update Status
    delivery.statusUpdates.push({ status: "Delivered", timestamp: new Date() });
    delivery.completedAt = new Date();
    await delivery.save();

    // --- AUTO-SYNC (UPDATE) ---
    syncSingleDeliveryToSheet(delivery._id, 'update').catch(console.error);

    // 🔔 FCM PUSH → Admins/Managers
    const staff = await User.find({ role: { $in: ['admin', 'manager'] }, isActive: true });
    for (const s of staff) {
      if (s?.fcmTokens?.length) {
        for (const token of s.fcmTokens) {
          await sendNotification(
            token,
            "✅ Delivery Completed",
            `Order ${delivery.trackingId} successfully deliver ho gaya hai.\nTime: ${getISTTime()}`,
            s._id,
            { tag: `staff-delivery-${delivery.trackingId}` }
          );
        }
      }
    }

    res.json({ success: true, message: "Delivery completed successfully", trackingId: delivery.trackingId });
  } catch (error) {
    console.error("Complete Delivery Error:", error);
    res.status(400).json({ success: false, message: error.message });
  }
});

// --- 10. Public API Routes --- (No changes)
// 10.1. Track
app.get('/track/:trackingId', async (req, res) => {
  try {
    const inputTid = req.params.trackingId;

    // 1️⃣ Try exact match first (NEW IDs: SAHYOG123456)
    let delivery = await Delivery.findOne({ trackingId: inputTid }).populate('assignedTo', 'name phone');

    // 2️⃣ If not found, try OLD format (SAHYOG-123456)
    if (!delivery && inputTid.startsWith('SAHYOG') && !inputTid.includes('-')) {
      const oldTid = inputTid.replace('SAHYOG', 'SAHYOG-');
      delivery = await Delivery.findOne({ trackingId: oldTid }).populate('assignedTo', 'name phone');
    }

    if (!delivery) {
      return res.status(404).json({ message: 'Tracking ID not found' });
    }

    res.json(delivery);
  } catch (err) {
    console.error("Track Error:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 10.2. Get VAPID Key
app.get('/vapid-public-key', (req, res) => res.send(VAPID_PUBLIC_KEY));
// --- (NEW) 10.3. Get Public Business Settings (Accessible by anyone or specific roles) ---
app.get('/public/settings', async (req, res) => {
  try {
    // Hum yahan auth middleware use nahi kar rahe, ya aap auth(['delivery', 'manager', 'admin']) laga sakte hain
    let settings = await BusinessSettings.findOne({}, 'businessName businessAddress businessPhone logoUrl upiId upiName'); // Only send necessary fields
    if (!settings) {
      // Agar settings nahi hain, toh ek default empty object bhej sakte hain ya create kar sakte hain
      settings = await BusinessSettings.create({}); // Create if not exists
    }
    res.json(settings);
  } catch (error) {
    console.error('Error fetching public settings:', error);
    res.status(500).json({ message: 'Error fetching public settings' });
  }
});

// --- 11. Business Settings Management (Admin Only) ---
// Get business settings (FIXED: Removed 'delivery' role)
app.get('/admin/settings', auth(['admin']), async (req, res) => {
  try {
    let settings = await BusinessSettings.findOne(); if (!settings) { settings = await BusinessSettings.create({}); } res.json(settings);
  } catch (error) { console.error('Error fetching settings:', error); res.status(500).json({ message: 'Error fetching settings' }); }
});
// Update business settings (No changes)
app.put('/admin/settings', auth(['admin']), async (req, res) => {
  try {
    const { businessName, businessAddress, businessPhone, logoUrl, upiId, upiName } = req.body;
    const updatedSettings = await BusinessSettings.findOneAndUpdate({}, { businessName, businessAddress, businessPhone, logoUrl, upiId, upiName }, { new: true, upsert: true, setDefaultsOnInsert: true });
    res.json({ message: 'Settings updated!', settings: updatedSettings });
  } catch (error) { console.error('Error updating settings:', error); res.status(500).json({ message: 'Error updating settings' }); }
});

// --- 11.1. Clear all FCM tokens (Admin Only) ---
app.post('/clear-fcm-tokens', auth(['admin']), async (req, res) => {
  await User.updateMany({}, { $set: { fcmTokens: [] } });
  res.json({ message: "All tokens cleared." });
});

// --- 11.2. Cashfree Webhook Route (Deprecated /api/payment-success in favor of /api/cashfree-webhook) ---
app.post("/api/payment-success", (req, res) => res.redirect(307, "/api/cashfree-webhook"));
app.get("/api/payment-success", (req, res) => res.send("Cashfree webhook route working. Use /api/cashfree-webhook for POST."));

// --- 11.5 NEW Cashfree COD QR Support (PRD FIX) ---
// ===== Cashfree COD Online Payment =====

// 1. Payment Order Creation API (PRD Compliant)
app.post("/api/create-payment-order", auth(['delivery', 'admin', 'manager']), async (req, res) => {
  try {
    const { amount, trackingId } = req.body;

    if (!trackingId) {
      return res.status(400).json({ success: false, message: "trackingId is required" });
    }

    const delivery = await Delivery.findOne({ trackingId });
    if (!delivery) {
      return res.status(404).json({ success: false, message: "Delivery not found" });
    }

    const finalAmount = amount || delivery.billAmount;
    if (!finalAmount || finalAmount <= 0) {
      return res.status(400).json({ success: false, message: "Amount is required and must be greater than zero" });
    }

    // Validations (PRD Requirement)
    if (delivery.paymentMethod !== 'COD') {
      return res.status(400).json({ success: false, message: "Only COD orders can create online payment sessions" });
    }

    if (delivery.codPaymentStatus !== "Pending") {
      return res.status(400).json({ success: false, message: `Payment already ${delivery.codPaymentStatus}` });
    }

    if (delivery.currentStatus === 'Delivered') {
      return res.status(400).json({ success: false, message: "Delivery already completed" });
    }

    // Unique order_id format: COD_<trackingId>_<timestamp>
    const orderId = `COD_${trackingId}_${Date.now()}`;

    const response = await fetch(`${CASHFREE_BASE_URL}/orders`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-client-id": process.env.CASHFREE_APP_ID,
        "x-client-secret": process.env.CASHFREE_SECRET_KEY,
        "x-api-version": "2023-08-01"
      },
      body: JSON.stringify({
        order_id: orderId,
        order_amount: Number(finalAmount),
        order_currency: "INR",
        order_note: `Sahyog Delivery: ${trackingId}`,
        customer_details: {
          customer_id: trackingId,
          customer_name: delivery.customerName || "Customer",
          customer_phone: delivery.customerPhone || "9999999999"
        },
        order_meta: {
          return_url: `https://sahyogdelivery.vercel.app/delivery.html?trackingId=${trackingId}`,
          notify_url: "https://sahyogdeliverybackend.onrender.com/api/cashfree-webhook"
        }
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("Cashfree API Error:", data);
      return res.status(400).json({ success: false, message: data.message || "Cashfree order creation failed", error: data });
    }

    res.json({
      success: true,
      payment_session_id: data.payment_session_id,
      order_id: orderId
    });

  } catch (err) {
    console.error("Payment Order Error:", err);
    res.status(400).json({ success: false, message: err.message });
  }
});


app.get("/api/payment-status/:trackingId", auth(['delivery', 'admin', 'manager']), async (req, res) => {
  const delivery = await Delivery.findOne({ trackingId: req.params.trackingId });

  if (!delivery) return res.json({ paid: false });

  res.json({ paid: delivery.codPaymentStatus === "Paid - Online" });
});

//webhook 
import crypto from "crypto";

app.post("/api/cashfree-webhook", async (req, res) => {
    try {
      const signature =
        req.headers["x-webhook-signature"] ||
        req.headers["x-cf-signature"];

      if (!signature) {
        console.log("❌ No signature header");
        return res.sendStatus(400);
      }

      if (!Buffer.isBuffer(req.body)) {
        console.log("❌ Invalid webhook body format");
        return res.sendStatus(400);
      }

      const expectedSignature = crypto
        .createHmac("sha256", process.env.CASHFREE_SECRET_KEY)
        .update(req.body)
        .digest("base64");

      if (signature !== expectedSignature) {
        console.log("❌ Invalid webhook signature");
        console.log("Received:", signature);
        console.log("Expected:", expectedSignature);
        return res.sendStatus(400);
      }

      // Convert buffer to JSON AFTER signature verify
      const event = JSON.parse(req.body.toString());

      if (event.type !== "PAYMENT_SUCCESS_WEBHOOK") {
        return res.sendStatus(200);
      }

      const orderId = event?.data?.order?.order_id || "";
      const match = orderId.match(/^COD_(.+)_\d+$/);
      const trackingId = match?.[1] || event?.data?.order?.customer_details?.customer_id || null;

      if (!trackingId) return res.sendStatus(200);

      const delivery = await Delivery.findOne({ trackingId });
      if (!delivery) return res.sendStatus(200);

      delivery.codPaymentStatus = "Paid - Online";
      await delivery.save();

      console.log("✅ Payment marked Paid - Online:", trackingId);

      return res.sendStatus(200);

    } catch (err) {
      console.error("Webhook error:", err);
      return res.sendStatus(500);
    }
});
// --- (NEW) Start Server ---



// --- 12. Start Server ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// --- 13. Create Admin User & Default Settings (one-time) ---
async function initialSetup() {
  // Admin User
  try {
    const adminEmail = 'sahyogmns', adminPass = 'passsahyogmns';
    let admin = await User.findOne({ email: adminEmail });
    if (!admin) {
      const hp = await bcrypt.hash(adminPass, 12);
      admin = new User({ name: 'Sahyog Admin', email: adminEmail, password: hp, role: 'admin', isActive: true });
      await admin.save();
      console.log(`--- ADMIN CREATED --- User: ${adminEmail}, Pass: ${adminPass}`);
    } else {
      if (!admin.isActive) {
        admin.isActive = true;
        await admin.save();
        console.log(`Admin ${adminEmail} reactivated.`);
      } else {
        console.log('Admin exists & active.');
      }
    }
  } catch (e) { console.error('Admin setup error:', e); }

  // Default Settings
  try {
    const defaultSettings = await BusinessSettings.findOne();
    if (!defaultSettings) {
      await BusinessSettings.create({});
      console.log('Default business settings created.');
    }
  } catch (e) { console.error('Default settings check/create error:', e); }
}
setTimeout(initialSetup, 5000);
