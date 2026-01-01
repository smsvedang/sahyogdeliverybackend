// --- Sahyog Medical Delivery Backend (server.js) - v6.2 (Auto-Sync Enabled) ---

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const webpush = require('web-push');
const { google } = require('googleapis');

const app = express();
app.use(cors());
app.use(express.json());

// --- 1. Environment Variables ---
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;

if (!MONGO_URI || !JWT_SECRET || !VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    console.error('FATAL ERROR: Environment Variables are not set.');
    process.exit(1);
}

// --- 2. MongoDB Connect ---
mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB से जुड़ गए!'))
    .catch(err => console.error('MongoDB से जुड़ने में गड़बड़ी:', err));

// --- 3. Web Push Setup ---
webpush.setVapidDetails('mailto:sonivedang7@gmail.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

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

// --- 4. Schemas ---

// 4.1. User Schema (No changes)
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true }, // Username
    password: { type: String, required: true },
    phone: { type: String },
    role: { type: String, enum: ['admin', 'manager', 'delivery'], required: true },
    isActive: { type: Boolean, default: true },
    pushSubscription: { type: Object },
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
    codPaymentStatus: { type: String, enum: ['Pending', 'Paid - Cash', 'Paid - Online', 'Not Applicable'], default: 'Pending' }
}, { timestamps: true });

deliverySchema.virtual('currentStatus').get(function() {
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
                resource: { requests: [{ "repeatCell": {
                    "range": { "sheetId": 0, "startRowIndex": rowNumber - 1, "endRowIndex": rowNumber, "startColumnIndex": 0, "endColumnIndex": GOOGLE_SHEET_HEADERS.length },
                    "cell": { "userEnteredFormat": { "backgroundColor": null } },
                    "fields": "userEnteredFormat.backgroundColor"
                }}] }
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

// 5.2. Auth Middleware
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
app.get('/service-worker.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.sendFile(path.join(__dirname, 'service-worker.js'));
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
        const trackingId = 'SAHYOG-' + Date.now().toString().slice(-6);

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
        
        // --- AUTO-SYNC (CREATE) ---
        syncSingleDeliveryToSheet(newDelivery._id, 'create').catch(console.error);

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
            .populate('assignedTo', 'name email isActive') 
            .sort({ createdAt: -1 });
        res.json(deliveries);
    } catch (error) {
         console.error("Fetch Deliveries Error:", error);
         res.status(500).json({ message: 'Error fetching deliveries' });
    }
});

// 7.3. Get All Users (Removed duplicate route)
app.get('/admin/users', auth(['admin']), async (req, res) => {
    try {
        const users = await User.find({}, '-password') 
                          .populate('createdByManager', 'name')
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
        const { name,email,password,phone,role,managerId } = req.body;

if(role==="delivery" && !managerId){
    return res.status(400).json({ message:"Manager required for delivery boy" });
}
    
const hashedPassword = await bcrypt.hash(password,10);

const newUser = new User({
    name,email:email.toLowerCase(),password:hashedPassword,
    phone,role,
    createdByManager: role==="delivery" ? managerId : null
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

app.get('/manager/pending', auth(['manager']), async(req,res)=>{
    const deliveries = await Delivery.find({
        assignedByManager:req.user.userId,
        statusUpdates:{ $not:{ $elemMatch:{ status:'Delivered' }}}
    }).populate('assignedTo','name');
    res.json(deliveries);
});

app.get('/manager/completed', auth(['manager']), async(req,res)=>{
    const deliveries = await Delivery.find({
        assignedByManager:req.user.userId,
        statusUpdates:{ $elemMatch:{ status:'Delivered' }}
    }).populate('assignedTo','name');
    res.json(deliveries);
});

app.get('/manager/completed-deliveries', auth(['manager']), async(req,res)=>{
    const list = await Delivery.find({
        assignedByManager:req.user.userId,
        statusUpdates:{ $elemMatch:{status:'Delivered'} }
    }).populate('assignedTo','name');
    res.json(list);
});

app.get('/delivery/completed-deliveries', auth(['delivery']), async(req,res)=>{
    const list = await Delivery.find({
        assignedTo:req.user.userId,
        statusUpdates:{ $elemMatch:{status:'Delivered'} }
    });
    res.json(list);
});

app.get('/delivery/completed', auth(['delivery']), async(req,res)=>{
    const deliveries = await Delivery.find({
        assignedTo:req.user.userId,
        statusUpdates:{ $elemMatch:{ status:'Delivered'} }
    });
    res.json(deliveries);
});

// 7.5. Update User Details (No changes)
app.put('/admin/user/:userId', auth(['admin']), async (req, res) => {
    try {
        const { userId } = req.params;
        const { name, email, phone, role } = req.body;
        if (!name || !email || !role || !['admin', 'manager', 'delivery'].includes(role)) {
             return res.status(400).json({ message: 'Valid Name, Email, Role required' });
        }
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        user.name = name;
        user.email = email.toLowerCase();
        user.phone = phone;
        user.role = role;
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
                resetColorRequests.push({ "repeatCell": {
                    "range": { "sheetId": 0, "startRowIndex": existingEntry.row - 1, "endRowIndex": existingEntry.row, "startColumnIndex": 0, "endColumnIndex": headerRow.length },
                    "cell": { "userEnteredFormat": { "backgroundColor": null } },
                    "fields": "userEnteredFormat.backgroundColor"
                }});
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
    .populate('assignedTo', 'name')
    .sort({ createdAt: -1 });

    res.json(deliveries);
  } catch (err) {
    res.status(500).json({ message: 'Failed to load pending deliveries' });
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
app.get('/manager/my-boys', auth(['manager']), async (req,res)=>{
    const boys = await User.find({ 
        role:'delivery',
        createdByManager:req.user.userId 
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

// Manager can update ONLY delivery boys created under him
app.put('/manager/user/:userId', auth(['manager']), async (req, res) => {
    try {
        const { userId } = req.params;
        const { name, email, phone, password, isActive } = req.body;

        const boy = await User.findOne({ _id: userId, createdByManager: req.user.userId });

        if (!boy) return res.status(403).json({ message: "Not allowed. This delivery boy is not under you." });

        if (name) boy.name = name;
        if (email) boy.email = email.toLowerCase();
        if (phone) boy.phone = phone;
        if (typeof isActive !== "undefined") boy.isActive = isActive;

        if (password && password.trim() !== "") {
            boy.password = await bcrypt.hash(password, 10);
        }

        await boy.save();
        res.json({ message: "Delivery boy updated successfully!" });

    } catch (e) {
        res.status(500).json({ message: "Update Failed", error: e.message });
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
        delivery.statusUpdates.push({ status: 'Boy Assigned' });
        await delivery.save();
        
        // --- AUTO-SYNC (UPDATE) ---
        syncSingleDeliveryToSheet(delivery._id, 'update').catch(console.error);

        if (boy.pushSubscription) {
            const payload = JSON.stringify({ title: 'New Delivery Assigned!', body: `Order ${delivery.trackingId} for ${delivery.customerName}` });
            webpush.sendNotification(boy.pushSubscription, payload).catch(err => console.error("Push error during assignment:", err));
        }

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
        .populate('assignedTo', 'name') 
        .sort({ createdAt: -1 }); 

        res.json(deliveries);
    } catch (error) {
        console.error("Fetch All Pending Deliveries Error:", error);
        res.status(500).json({ message: 'Error fetching all pending deliveries' });
    }
});


// --- 9. Delivery Boy API Routes ---

// 9.1. Get Assigned Deliveries (No changes)
app.get('/delivery/my-deliveries', auth(['delivery']), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1; const limit = 5; const skip = (page - 1) * limit;
        const filter = { assignedTo: req.user.userId, 'statusUpdates.status': { $nin: ['Delivered', 'Cancelled'] } };
        const deliveries = await Delivery.find(filter).sort({ createdAt: 1 }).skip(skip).limit(limit);
        const totalDeliveries = await Delivery.countDocuments(filter);
        res.json({ deliveries, currentPage: page, totalPages: Math.ceil(totalDeliveries / limit), totalDeliveries });
    } catch (error) { console.error("Fetch Assigned Error:", error); res.status(500).json({ message: 'Error fetching assigned deliveries' }); }
});

// 9.2. Update Status (Scan/Manual)
app.post('/delivery/update-status', auth(['delivery']), async (req, res) => {
    try {
        const { trackingId } = req.body; const delivery = await Delivery.findOne({ trackingId: trackingId, assignedTo: req.user.userId }); if (!delivery) return res.status(404).json({ message: 'ID not found/assigned' });
        let nextStatus; switch (delivery.currentStatus) { case 'Boy Assigned': nextStatus = 'Picked Up'; break; case 'Booked': nextStatus = 'Picked Up'; break; case 'Picked Up': nextStatus = 'Out for Delivery'; break; default: return res.status(400).json({ message: `Already ${delivery.currentStatus}` }); }
        delivery.statusUpdates.push({ status: nextStatus }); 
        await delivery.save(); 
        
        // --- AUTO-SYNC (UPDATE) ---
        syncSingleDeliveryToSheet(delivery._id, 'update').catch(console.error);
        
        res.json({ trackingId: delivery.trackingId, status: nextStatus });
    } catch (error) { console.error("Update Status Error:", error); res.status(500).json({ message: 'Server error updating status', error: error.message }); }
});

// 9.3. Complete Delivery (OTP)
app.post('/delivery/complete', auth(['delivery']), async (req, res) => {
    try {
        const { trackingId, otp, paymentReceivedMethod } = req.body; const delivery = await Delivery.findOne({ trackingId: trackingId, assignedTo: req.user.userId });
        if (!delivery) return res.status(404).json({ message: 'ID not found/assigned' }); if (delivery.currentStatus !== 'Out for Delivery') return res.status(400).json({ message: `Status is ${delivery.currentStatus}.` }); if (delivery.otp !== otp) return res.status(400).json({ message: 'Invalid OTP!' });
        if (delivery.paymentMethod === 'COD') { if (!paymentReceivedMethod) return res.status(400).json({ message: 'Select payment method' }); delivery.codPaymentStatus = (paymentReceivedMethod === 'cash') ? 'Paid - Cash' : 'Paid - Online'; } else { delivery.codPaymentStatus = 'Not Applicable'; }
        delivery.statusUpdates.push({ status: 'Delivered' }); 
        await delivery.save(); 
        
        // --- AUTO-SYNC (UPDATE) ---
        syncSingleDeliveryToSheet(delivery._id, 'update').catch(console.error);
        
        res.json({ trackingId: delivery.trackingId, status: 'Delivered' });
    } catch (error) { console.error("Complete Error:", error); res.status(500).json({ message: 'Server error completing delivery', error: error.message }); }
});

// 9.4. Subscribe to Push (No changes)
app.post('/subscribe', auth(['delivery']), async (req, res) => {
    try { await User.findByIdAndUpdate(req.user.userId, { pushSubscription: req.body }); res.status(201).json({ message: 'Subscribed' }); }
    catch (error) { console.error("Subscribe Error:", error); res.status(500).json({ message: 'Failed to save subscription' }); }
});

// --- 10. Public API Routes --- (No changes)
// 10.1. Track
app.get('/track/:trackingId', async (req, res) => {
    try { const delivery = await Delivery.findOne({ trackingId: req.params.trackingId }).populate('assignedTo', 'name phone'); if (!delivery) return res.status(404).json({ message: 'ID not found' });
        let boyDetails = delivery.assignedBoyDetails; if (delivery.assignedTo && delivery.assignedTo.name) { boyDetails = { name: delivery.assignedTo.name, phone: delivery.assignedTo.phone }; }
        res.json({ trackingId: delivery.trackingId, customerName: delivery.customerName, statusUpdates: delivery.statusUpdates, paymentMethod: delivery.paymentMethod, billAmount: delivery.billAmount, currentStatus: delivery.currentStatus, assignedBoyDetails: boyDetails });
    } catch (error) { console.error("Track Error:", error); res.status(500).json({ message: 'Tracking lookup failed' }); }
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

// --- 12. Start Server --- (No changes)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`सर्वर ${PORT} पर चल रहा है`));

// --- 13. Create Admin User & Default Settings (one-time) --- (No changes)
async function initialSetup() {
    // Admin User
    try { const adminEmail = 'sahyogmns', adminPass = 'passsahyogmns'; let admin = await User.findOne({ email: adminEmail });
        if (!admin) { const hp = await bcrypt.hash(adminPass, 12); admin = new User({ name: 'Sahyog Admin', email: adminEmail, password: hp, role: 'admin', isActive: true }); await admin.save(); console.log(`--- ADMIN CREATED --- User: ${adminEmail}, Pass: ${adminPass}`); }
        else { if (!admin.isActive) { admin.isActive = true; await admin.save(); console.log(`Admin ${adminEmail} reactivated.`); } else { console.log('Admin exists & active.'); } }
    } catch (e) { console.error('Admin setup error:', e); }

    // Default Settings
    try { const defaultSettings = await BusinessSettings.findOne(); if (!defaultSettings) { await BusinessSettings.create({}); console.log('Default business settings created.'); } }
    catch (e) { console.error('Default settings check/create error:', e); }
}
setTimeout(initialSetup, 5000);
