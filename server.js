// --- Sahyog Medical Delivery Backend (server.js) - v6.4 (Auto-Sync Enabled) ---

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
import crypto from 'crypto';
import fetch from 'node-fetch';

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
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));
app.options("*", cors());

import admin from 'firebase-admin';
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n')
    })
  });
}

const sendNotification = async (token, title, body, userId = null, options = {}) => {
  if (!token) return;
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
      fcmOptions: { link: options.link || "https://sahyogdelivery.vercel.app" }
    }
  };
  try {
    await admin.messaging().send(message);
  } catch (err) {
    if (userId && (err.code === 'messaging/invalid-registration-token' || err.code === 'messaging/registration-token-not-registered')) {
      await User.findByIdAndUpdate(userId, { $pull: { fcmTokens: token } });
    }
  }
};

function getISTTime() {
  return new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit' });
}

// --- Databases & Models ---

const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const CASHFREE_APP_ID = process.env.CASHFREE_APP_ID;
const CASHFREE_SECRET_KEY = process.env.CASHFREE_SECRET_KEY;
const CASHFREE_BASE_URL = process.env.CASHFREE_BASE_URL || 'https://sandbox.cashfree.com/pg';

mongoose.connect(MONGO_URI).then(() => console.log('MongoDB Connected')).catch(console.error);

const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String },
  role: { type: String, enum: ['admin', 'manager', 'delivery'], required: true },
  isActive: { type: Boolean, default: true },
  fcmTokens: { type: [String], default: [] },
  createdByManager: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }
}, { timestamps: true }));

const deliverySchema = new mongoose.Schema({
  customerName: String, customerAddress: String, customerPhone: String,
  trackingId: { type: String, unique: true, required: true }, otp: String,
  paymentMethod: { type: String, enum: ['COD', 'Prepaid'], default: 'Prepaid' }, billAmount: { type: Number, default: 0 },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  assignedByManager: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  assignedBoyDetails: { name: String, phone: String },
  statusUpdates: [{ status: String, timestamp: { type: Date, default: Date.now }, remarks: String }],
  codPaymentStatus: { type: String, enum: ['Pending', 'Paid - Cash', 'Paid - Online', 'Not Applicable'], default: 'Pending' },
  cashReceivedByAdmin: { type: Boolean, default: false }, cashReceivedAt: { type: Date, default: null },
  completedAt: { type: Date, default: null }, assignedAt: { type: Date, default: null },
  cancellationOtp: String, cancellationReason: String
}, { timestamps: true });

deliverySchema.virtual('currentStatus').get(function () {
  if (this.statusUpdates.length === 0) return 'Pending';
  return this.statusUpdates[this.statusUpdates.length - 1].status;
});
deliverySchema.set('toJSON', { virtuals: true });
const Delivery = mongoose.model('Delivery', deliverySchema);

const BusinessSettings = mongoose.model('BusinessSettings', new mongoose.Schema({
  businessName: { type: String, default: 'Sahyog Medical' },
  businessAddress: { type: String, default: 'Address Here' },
  businessPhone: { type: String, default: '+91' },
  logoUrl: { type: String, default: '' }, upiId: { type: String, default: '' }, upiName: { type: String, default: '' }
}, { timestamps: true }));

const DraftOrder = mongoose.model('DraftOrder', new mongoose.Schema({
  orderNumber: { type: String, unique: true }, customerName: String, phone: String, address: String, amount: Number,
  status: { type: String, enum: ['DRAFT', 'CONVERTED'], default: 'DRAFT' }
}, { timestamps: true }));

// --- Google Sheets Sync ---
const sheets = process.env.GOOGLE_SHEET_ID ? google.sheets({ version: 'v4', auth: new google.auth.GoogleAuth({ credentials: { client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL, private_key: process.env.GOOGLE_PRIVATE_KEY?.replace(/\\n/g, '\n') }, scopes: ['https://www.googleapis.com/auth/spreadsheets'] }) }) : null;

async function syncSingleDeliveryToSheet(id, action) {
  if (!sheets) return;
  const d = await Delivery.findById(id).populate('assignedByManager', 'name').populate('assignedTo', 'name');
  if (!d) return;
  const row = [d.trackingId, d.customerName, d.currentStatus, d.paymentMethod === 'COD' ? `₹${d.billAmount}` : 'Prepaid', d.codPaymentStatus, d.assignedByManager?.name || 'N/A', d.assignedTo?.name || 'N/A', d.otp || 'N/A', new Date().toLocaleDateString('en-IN')];
  try {
    const res = await sheets.spreadsheets.values.get({ spreadsheetId: process.env.GOOGLE_SHEET_ID, range: 'Sheet1!A:A' });
    const rows = res.data.values || [];
    let idx = rows.findIndex(r => r[0] === d.trackingId);
    if (idx !== -1) {
      await sheets.spreadsheets.values.update({ spreadsheetId: process.env.GOOGLE_SHEET_ID, range: `Sheet1!A${idx+1}`, valueInputOption: 'USER_ENTERED', resource: { values: [row] } });
    } else {
      await sheets.spreadsheets.values.append({ spreadsheetId: process.env.GOOGLE_SHEET_ID, range: 'Sheet1!A1', valueInputOption: 'USER_ENTERED', resource: { values: [row] } });
    }
  } catch (e) { console.error("Sync error", e.message); }
}

// --- Middleware & Auth ---

const auth = (roles = []) => (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET); req.user = decoded;
    if (roles.length && !roles.includes(decoded.role)) return res.status(403).json({ message: 'Forbidden' });
    next();
  } catch (e) { res.status(401).json({ message: 'Invalid token' }); }
};

// --- Routes ---

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const u = await User.findOne({ email: email.toLowerCase() });
  if (!u || !u.isActive || !(await bcrypt.compare(password, u.password))) return res.status(401).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ userId: u._id, role: u.role, name: u.name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, name: u.name, role: u.role });
});

app.post('/api/save-fcm-token', auth(), async (req, res) => {
  await User.findByIdAndUpdate(req.user.userId, { $addToSet: { fcmTokens: req.body.token } });
  res.sendStatus(200);
});

app.post('/api/change-password', auth(), async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const u = await User.findById(req.user.userId);
  if (!u || !(await bcrypt.compare(oldPassword, u.password))) return res.status(401).json({ message: 'Incorrect old password' });
  u.password = await bcrypt.hash(newPassword, 10);
  await u.save();
  res.json({ message: 'Password changed successfully' });
});

app.use(express.static(path.join(__dirname)));
app.get('/firebase-messaging-sw.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.sendFile(path.join(__dirname, 'firebase-messaging-sw.js'));
});

app.patch('/manager/assign-delivery/:id', auth(['manager']), async (req, res) => {
  const boy = await User.findById(req.body.assignedBoyId);
  if (!boy) return res.status(404).json({ message: 'Boy not found' });
  const d = await Delivery.findOneAndUpdate({ _id: req.params.id, assignedByManager: req.user.userId }, { $set: { assignedTo: boy._id, assignedBoyDetails: { name: boy.name, phone: boy.phone }, assignedAt: new Date() }, $push: { statusUpdates: { status: 'Boy Assigned' } } }, { new: true });
  if (boy.fcmTokens?.length) boy.fcmTokens.forEach(t => sendNotification(t, "Naya Parcel!", `Tracking ID: ${d.trackingId}`, boy._id));
  res.sendStatus(200);
});

// --- Admin APIs ---

app.get('/admin/deliveries', auth(['admin']), async (req, res) => {
  const q = req.query.managerId ? { assignedByManager: req.query.managerId } : {};
  res.json(await Delivery.find(q).populate('assignedByManager', 'name').populate('assignedTo', 'name').sort({ createdAt: -1 }));
});

app.get('/admin/users', auth(['admin']), async (req, res) => {
  res.json(await User.find({}, '-password').populate('createdByManager', 'name'));
});

app.get('/admin/managers', auth(['admin']), async (req, res) => {
  res.json(await User.find({ role: 'manager', isActive: true }, 'name _id'));
});

app.post('/admin/create-user', auth(['admin']), async (req, res) => {
  const { name, email, password, phone, role, managerId } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await new User({ name, email: email.toLowerCase(), password: hash, phone, role, createdByManager: role === 'delivery' ? managerId : null }).save();
  res.sendStatus(201);
});

app.patch('/admin/user/:id', auth(['admin']), async (req, res) => {
  const { password, ...update } = req.body;
  if (password) update.password = await bcrypt.hash(password, 10);
  await User.findByIdAndUpdate(req.params.id, update);
  res.sendStatus(200);
});

app.delete('/admin/user/:id', auth(['admin']), async (req, res) => {
  await User.findByIdAndDelete(req.params.id); res.sendStatus(200);
});

app.patch('/admin/user/:id/toggle-active', auth(['admin']), async (req, res) => {
  const u = await User.findById(req.params.id); u.isActive = !u.isActive; await u.save();
  res.json({ isActive: u.isActive });
});

app.post('/book', auth(['admin']), async (req, res) => {
  const { name, address, phone, paymentMethod, billAmount, managerId, draftId } = req.body;
  const tid = 'SAHYOG' + Date.now().toString().slice(-6);
  const d = new Delivery({ customerName: name, customerAddress: address, customerPhone: phone, trackingId: tid, otp: Math.floor(1000 + Math.random() * 9000).toString(), paymentMethod, billAmount, assignedByManager: managerId, statusUpdates: [{ status: 'Booked' }], codPaymentStatus: paymentMethod === 'Prepaid' ? 'Not Applicable' : 'Pending' });
  await d.save();
  if (draftId) await DraftOrder.findByIdAndUpdate(draftId, { status: 'CONVERTED' });
  syncSingleDeliveryToSheet(d._id, 'create').catch(console.error);
  res.status(201).json({ trackingId: tid, otp: d.otp });
});

app.post('/admin/dispatch-bulk', auth(['admin']), async (req, res) => {
  await Delivery.updateMany({ trackingId: { $in: req.body.trackingIds } }, { $push: { statusUpdates: { status: 'Dispatched from Head Office' } } });
  res.sendStatus(200);
});

app.post('/admin/receive-bulk', auth(['admin']), async (req, res) => {
  await Delivery.updateMany({ trackingId: { $in: req.body.trackingIds } }, { $push: { statusUpdates: { status: 'Received by Admin' } } });
  res.sendStatus(200);
});

app.get('/admin/pending-cash-orders', auth(['admin']), async (req, res) => {
  res.json(await Delivery.find({ paymentMethod: 'COD', codPaymentStatus: 'Paid - Cash', cashReceivedByAdmin: false, statusUpdates: { $elemMatch: { status: 'Delivered' } } }).populate('assignedTo', 'name'));
});

app.post('/admin/confirm-cash/:id', auth(['admin']), async (req, res) => {
  await Delivery.findByIdAndUpdate(req.params.id, { cashReceivedByAdmin: true, cashReceivedAt: new Date() });
  res.sendStatus(200);
});

app.get('/admin/completed-deliveries', auth(['admin']), async (req, res) => {
  res.json(await Delivery.find({ 'statusUpdates.status': 'Delivered' }).sort({ completedAt: -1 }).limit(100));
});

app.post('/admin/deliveries/bulk-cancel', auth(['admin']), async (req, res) => {
  await Delivery.updateMany({ _id: { $in: req.body.deliveryIds } }, { $push: { statusUpdates: { status: 'Cancelled' } } });
  res.sendStatus(200);
});

app.post('/admin/deliveries/bulk-delete', auth(['admin']), async (req, res) => {
  await Delivery.deleteMany({ _id: { $in: req.body.deliveryIds } }); res.sendStatus(200);
});

app.get('/api/drafts', auth(['admin']), async (req, res) => {
  res.json(await DraftOrder.find({ status: 'DRAFT' }).sort({ createdAt: -1 }));
});

app.delete('/api/drafts/:id', auth(['admin']), async (req, res) => {
  await DraftOrder.findByIdAndDelete(req.params.id); res.sendStatus(200);
});

// --- Manager APIs ---

app.get('/manager/summary', auth(['manager']), async (req, res) => {
  const deliveries = await Delivery.find({ assignedByManager: req.user.userId });
  let s = { totalReceived: deliveries.length, pendingAssignment: 0, outForDelivery: 0, deliveredToday: 0, cancelledToday: 0, cashInHand: 0 };
  const today = new Date(); today.setHours(0,0,0,0);
  deliveries.forEach(d => {
    if (d.currentStatus === 'Booked') s.pendingAssignment++;
    else if (d.currentStatus === 'Picked Up' || d.currentStatus === 'Out for Delivery') s.outForDelivery++;
    if (d.currentStatus === 'Delivered' && d.completedAt >= today) {
      s.deliveredToday++; if (d.paymentMethod === 'COD' && d.codPaymentStatus === 'Paid - Cash') s.cashInHand += d.billAmount;
    }
  });
  res.json(s);
});

app.get('/manager/my-boys', auth(['manager']), async (req, res) => {
  res.json(await User.find({ createdByManager: req.user.userId, role: 'delivery' }, '-password'));
});

app.post('/manager/create-delivery-boy', auth(['manager']), async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  await new User({ name: req.body.name, email: req.body.email.toLowerCase(), password: hash, phone: req.body.phone, role: 'delivery', createdByManager: req.user.userId }).save();
  res.sendStatus(201);
});

app.get('/manager/assigned-pickups', auth(['manager']), async (req, res) => {
    const list = await Delivery.find({ assignedByManager: req.user.userId, assignedTo: null }).sort({ createdAt: -1 });
    res.json(list.filter(d => ['Received at Branch'].includes(d.currentStatus)));
});

app.get('/manager/expected-receive', auth(['manager']), async (req, res) => {
    const list = await Delivery.find({ 
        assignedByManager: req.user.userId, 
        assignedTo: null 
    }).sort({ createdAt: -1 });
    res.json(list.filter(d => !['Received at Branch', 'Delivered', 'Cancelled'].includes(d.currentStatus)));
});

app.get('/manager/all-pending-deliveries', auth(['manager']), async (req, res) => {
  res.json(await Delivery.find({ assignedByManager: req.user.userId, 'statusUpdates.status': { $ne: 'Delivered' } }).populate('assignedTo', 'name').sort({ createdAt: -1 }));
});

app.post('/manager/receive-bulk', auth(['manager']), async (req, res) => {
  await Delivery.updateMany({ trackingId: { $in: req.body.trackingIds } }, { $set: { assignedTo: null }, $push: { statusUpdates: { status: 'Received at Branch' } } });
  res.sendStatus(200);
});

app.post('/manager/bulk-assign-deliveries', auth(['manager']), async (req, res) => {
  const boy = await User.findById(req.body.assignedBoyId);
  await Delivery.updateMany({ _id: { $in: req.body.deliveryIds }, assignedByManager: req.user.userId }, { $set: { assignedTo: boy._id, assignedBoyDetails: { name: boy.name, phone: boy.phone } }, $push: { statusUpdates: { status: 'Boy Assigned' } } });
  if (boy.fcmTokens?.length) boy.fcmTokens.forEach(t => sendNotification(t, "Naye Parcels!", "Aapko naye parcels assign hue hain", boy._id));
  res.sendStatus(200);
});

app.post('/manager/reassign-delivery/:id', auth(['manager']), async (req, res) => {
  const boy = await User.findById(req.body.newDeliveryBoyId);
  await Delivery.findOneAndUpdate({ _id: req.params.id, assignedByManager: req.user.userId }, { $set: { assignedTo: boy._id, assignedBoyDetails: { name: boy.name, phone: boy.phone } }, $push: { statusUpdates: { status: 'Boy Assigned', remarks: 'Reassigned' } } });
  res.sendStatus(200);
});

app.get('/manager/completed-deliveries', auth(['manager']), async (req, res) => {
  res.json(await Delivery.find({ assignedByManager: req.user.userId, 'statusUpdates.status': 'Delivered' }).populate('assignedTo', 'name').sort({ completedAt: -1 }));
});

app.get('/manager/pending-cash-orders', auth(['manager']), async (req, res) => {
  res.json(await Delivery.find({ assignedByManager: req.user.userId, paymentMethod: 'COD', codPaymentStatus: 'Paid - Cash', cashReceivedByAdmin: false, 'statusUpdates.status': 'Delivered' }).populate('assignedTo', 'name'));
});

app.post('/manager/confirm-cash/:id', auth(['manager']), async (req, res) => {
  await Delivery.findOneAndUpdate({ _id: req.params.id, assignedByManager: req.user.userId }, { cashReceivedByAdmin: true, cashReceivedAt: new Date() });
  res.sendStatus(200);
});

// --- Delivery Boy APIs ---

app.get('/delivery/my-deliveries', auth(['delivery']), async (req, res) => {
  const q = { assignedTo: req.user.userId, 'statusUpdates.status': { $nin: ['Delivered', 'Cancelled'] } };
  const deliveries = await Delivery.find(q).sort({ createdAt: -1 });
  const totalDeliveries = await Delivery.countDocuments(q);
  res.json({ deliveries, totalDeliveries });
});

app.get('/delivery/completed', auth(['delivery']), async (req, res) => {
  res.json(await Delivery.find({ assignedTo: req.user.userId, 'statusUpdates.status': 'Delivered' }).sort({ completedAt: -1 }).limit(100));
});

app.post('/delivery/update-status', auth(['delivery']), async (req, res) => {
    await Delivery.findOneAndUpdate({ trackingId: req.body.trackingId, assignedTo: req.user.userId }, { $push: { statusUpdates: { status: req.body.status } } });
    res.sendStatus(200);
});

app.post('/delivery/complete', auth(['delivery', 'admin', 'manager']), async (req, res) => {
  const { trackingId, otp, paymentType } = req.body;
  const d = await Delivery.findOne({ trackingId });
  if (!d || d.otp !== otp) return res.status(400).json({ message: 'Invalid OTP' });
  d.statusUpdates.push({ status: 'Delivered' }); d.completedAt = new Date();
  if (d.paymentMethod === 'COD') d.codPaymentStatus = paymentType === 'online' ? 'Paid - Online' : 'Paid - Cash';
  await d.save(); syncSingleDeliveryToSheet(d._id, 'update').catch(console.error);
  res.sendStatus(200);
});

app.post('/delivery/request-cancel-otp', auth(['delivery']), async (req, res) => {
  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  await Delivery.findOneAndUpdate({ trackingId: req.body.trackingId, assignedTo: req.user.userId }, { cancellationOtp: otp });
  res.json({ success: true });
});

app.post('/delivery/confirm-cancel', auth(['delivery']), async (req, res) => {
  const { trackingId, otp, reason } = req.body;
  const d = await Delivery.findOne({ trackingId, assignedTo: req.user.userId });
  if (!d || d.cancellationOtp !== otp) return res.status(400).json({ message: 'Invalid OTP' });
  const ns = reason === 'Request for reschedule' ? 'Rescheduled' : 'Cancelled';
  d.statusUpdates.push({ status: ns, remarks: reason }); d.cancellationOtp = null;
  if (ns === 'Rescheduled') { d.assignedTo = null; d.assignedBoyDetails = null; }
  await d.save(); res.json({ success: true });
});

// --- Public & Settings ---

app.get('/track/:id', async (req, res) => {
  const d = await Delivery.findOne({ trackingId: req.params.id }).populate('assignedTo', 'name phone');
  if (!d) return res.status(404).json({ message: 'Not found' });
  const { otp, cancellationOtp, ...safe } = d.toObject();
  res.json({ ...safe, currentStatus: d.currentStatus });
});

app.get('/vapid-public-key', (req, res) => res.send(VAPID_PUBLIC_KEY));

app.get('/public/settings', async (req, res) => {
  res.json(await BusinessSettings.findOne({}, 'businessName businessAddress businessPhone logoUrl upiId upiName') || {});
});

app.get('/admin/settings', auth(['admin']), async (req, res) => {
  res.json(await BusinessSettings.findOne() || {});
});

app.post('/admin/settings', auth(['admin']), async (req, res) => {
  const s = await BusinessSettings.findOneAndUpdate({}, req.body, { new: true, upsert: true });
  res.json(s);
});

app.post("/api/create-payment-order", auth(), async (req, res) => {
  try {
    const d = await Delivery.findOne({ trackingId: req.body.trackingId });
    const r = await fetch(`${CASHFREE_BASE_URL}/orders`, { method: "POST", headers: { "Content-Type": "application/json", "x-client-id": CASHFREE_APP_ID, "x-client-secret": CASHFREE_SECRET_KEY, "x-api-version": "2023-08-01" }, body: JSON.stringify({ order_id: `COD_${d.trackingId}_${Date.now()}`, order_amount: Number(req.body.amount || d.billAmount), order_currency: "INR", customer_details: { customer_id: d.trackingId, customer_name: d.customerName || "Customer", customer_phone: d.customerPhone || "9999999999" }, order_meta: { return_url: `https://sahyogdelivery.vercel.app/delivery.html?trackingId=${d.trackingId}`, notify_url: "https://sahyogdeliverybackend.onrender.com/api/cashfree-webhook" } }) });
    const dt = await r.json(); res.json({ payment_session_id: dt.payment_session_id });
  } catch (e) { res.status(500).json({ success: false }); }
});

app.post("/api/cashfree-webhook", async (req, res) => {
  const sig = req.headers["x-webhook-signature"] || req.headers["x-cf-signature"];
  const exp = crypto.createHmac("sha256", CASHFREE_SECRET_KEY).update(req.body).digest("base64");
  if (sig === exp) {
    const ev = JSON.parse(req.body.toString());
    if (ev.type === "PAYMENT_SUCCESS_WEBHOOK") {
      const tid = ev?.data?.order?.order_id.match(/^COD_(.+)_\d+$/)?.[1] || ev?.data?.order?.customer_details?.customer_id;
      if (tid) await Delivery.findOneAndUpdate({ trackingId: tid }, { codPaymentStatus: "Paid - Online" });
    }
  }
  res.sendStatus(200);
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

async function initialSetup() {
  if (!await User.findOne({ email: 'sahyogmns' })) await User.create({ name: 'Sahyog Admin', email: 'sahyogmns', password: await bcrypt.hash('passsahyogmns', 12), role: 'admin' });
  if (!await BusinessSettings.findOne()) await BusinessSettings.create({});
}
setTimeout(initialSetup, 5000);

// --- Margmart Email Logic ---
function extractPincode(addr) { const m = addr?.match(/\b\d{6}\b/); return m ? m[0] : null; }
function parseMargmartEmail(body) {
  return {
    orderNumber: body.match(/Order Number\s*:\s*(.+)/i)?.[1]?.trim(),
    customerName: body.match(/Customer's Name\s*:\s*(.+)/i)?.[1]?.trim(),
    phone: body.match(/Contact\s*:\s*(\d+)/i)?.[1]?.trim(),
    address: body.match(/Shipping Address\s*:\s*(.+)/i)?.[1]?.trim(),
    amount: Number(body.match(/Total Amount\s*:\s*([\d.]+)/i)?.[1]),
  };
}

async function fetchMargmartEmails() {
  try {
    const { google } = await import('googleapis');
    const auth = new google.auth.OAuth2(process.env.G_CLIENT_ID, process.env.G_CLIENT_SECRET);
    auth.setCredentials({ refresh_token: process.env.G_REFRESH_TOKEN });
    const gmail = google.gmail({ version: 'v1', auth });
    const res = await gmail.users.messages.list({ userId: 'me', q: 'from:margmart.com "Order Confirmation"', maxResults: 10 });
    if (!res.data.messages) return;
    for (const msg of res.data.messages) {
      const g = await gmail.users.messages.get({ userId: 'me', id: msg.id });
      const body = Buffer.from(g.data.payload.parts?.[0]?.body?.data || g.data.payload.body?.data || '', 'base64').toString();
      const d = parseMargmartEmail(body);
      if (d.orderNumber && !await DraftOrder.findOne({ orderNumber: d.orderNumber })) {
        await new DraftOrder({ ...d, pincode: extractPincode(d.address) }).save();
      }
    }
  } catch (e) { console.error("Email fetch failed", e.message); }
}

cron.schedule("*/5 * * * *", fetchMargmartEmails);
app.post('/api/fetch-margmart-orders', auth(['admin']), async (req, res) => {
  await fetchMargmartEmails(); res.json({ message: 'Fetched' });
});
