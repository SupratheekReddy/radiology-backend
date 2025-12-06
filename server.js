// ================================================================
// SERVER.JS — Final Version (Original Structure + Render Fixes)
// ================================================================

require("dotenv").config();
const http = require("http");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const session = require("express-session");
const multer = require("multer");
const axios = require("axios");
const streamifier = require("streamifier");
const { Server } = require("socket.io");
const cloudinary = require("cloudinary").v2;
const nodemailer = require("nodemailer"); // NEW: Email
const PDFDocument = require("pdfkit");    // NEW: PDF
const { GoogleGenerativeAI } = require("@google/generative-ai");

// --- 1. ENVIRONMENT CHECK ---
const requiredEnv = ['MONGO_URI', 'CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET', 'GEMINI_API_KEY'];
if (requiredEnv.some(key => !process.env[key])) {
    console.error(`❌ CRITICAL: Missing .env keys: ${requiredEnv.filter(k => !process.env[k]).join(', ')}`);
    // process.exit(1); // Uncomment to enforce strict check
}

// =========================
// APP & SERVER INITIALIZATION
// =========================

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 10000; // Render usually uses 10000

// --- 2. ROBUST CORS (Fixed for Netlify) ---
// ✅ FIX: Explicitly allowed your Netlify URL
const corsOptions = {
    origin: "https://radiology-system.netlify.app", 
    credentials: true, // Required for cookies/session
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
};

// ✅ FIX: Trust Proxy (Required for Render to handle cookies correctly)
app.set("trust proxy", 1);

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ FIX: Session Settings for Cross-Site (Netlify -> Render)
app.use(session({
    secret: process.env.SESSION_SECRET || "radai_secret_999",
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,        // REQUIRED: Must be true for Render (HTTPS)
        sameSite: 'none',    // REQUIRED: Allows cookie flow from Netlify -> Render
        maxAge: 24 * 60 * 60 * 1000 // 1 Day
    },
}));

const io = new Server(server, { cors: corsOptions });

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);
});

// =========================
// DATABASE & MODELS (Updated for New Features)
// =========================

// Updated User Schema
const UserSchema = new mongoose.Schema({
    name: String, 
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'doctor', 'technician', 'radiologist', 'patient'], required: true },
    email: String,
    basePriority: String
});
const User = mongoose.models.Account || mongoose.model("Account", UserSchema);

// Updated Case Schema (With AI Data, Chat, Timeline Support)
const CaseSchema = new mongoose.Schema({
    caseId: String,
    patient: { type: mongoose.Schema.Types.ObjectId, ref: 'Account' },
    doctor: { type: mongoose.Schema.Types.ObjectId, ref: 'Account' },
    technician: { type: mongoose.Schema.Types.ObjectId, ref: 'Account' },
    
    images: { type: [String], default: [] },
    scanType: String,
    symptoms: String,
    
    // Auto-Triage Field
    priority: { type: String, enum: ['Safe', 'Medium', 'Critical'], default: 'Medium' },
    status: { type: String, default: 'Pending' },
    date: { type: Date, default: Date.now },
    
    // Structured Data & Reports
    aiData: { 
        findings: String, 
        diagnosis: String, 
        confidence: String, 
        bodyPart: String 
    },
    radiologistNotes: String, 
    prescription: String,
    
    // Chat History
    chatHistory: { type: [{ role: String, message: String }], default: [] }
});
const Case = mongoose.models.Case || mongoose.model("Case", CaseSchema);

// Connect DB
// ✅ FIX: Removed deprecated options (useNewUrlParser) to clean up logs
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected"))
    .catch((err) => console.error("❌ MongoDB Error:", err));

// --- ADMIN RESET (Your Original Logic) ---
(async () => {
  try {
    const adminExists = await User.findOne({ role: "admin" });
    if (!adminExists) {
        console.log("⚠ Creating default admin account...");
        await User.create({
            name: "System Admin", email: "admin@system.com",
            username: "admin", password: "123", role: "admin"
        });
        // Create other default roles for testing
        await User.create({ name: "Dr. House", username: "doctor", password: "123", role: "doctor", email: "doc@rad.ai" });
        await User.create({ name: "Tech Sarah", username: "tech", password: "123", role: "technician", email: "tech@rad.ai" });
        await User.create({ name: "Rad. Jones", username: "radiologist", password: "123", role: "radiologist", email: "rad@rad.ai" });
        await User.create({ name: "John Doe", username: "patient", password: "123", role: "patient", email: "pat@rad.ai" });
        console.log("🟢 Defaults created (Login: admin/123)");
    }
  } catch (err) { console.error("Admin check failed:", err.message); }
})();

// =========================
// CONFIGURATIONS
// =========================

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// --- NEW: EMAIL HELPER ---
async function sendEmail(to, subject, html) {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        console.log("⚠️ Email skipped (Missing Credentials)");
        return;
    }
    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
        });
        await transporter.sendMail({ from: '"Rad AI Platform" <no-reply@radai.com>', to, subject, html });
    } catch (e) { console.error("❌ Email Failed:", e.message); }
}

// Middleware
const requireLogin = (req, res, next) => {
  if (req.session && req.session.user) next();
  else res.status(401).json({ success: false, message: "Unauthorized" });
};

const requireRole = (role) => (req, res, next) => {
    // Enhanced to allow arrays or single string
    const roles = Array.isArray(role) ? role : [role];
    if (req.session.user && (roles.includes(req.session.user.role) || req.session.user.role === 'admin')) {
      next();
    } else {
      res.status(403).json({ success: false, message: "Forbidden" });
    }
};

// =========================
// ROUTES: AUTH
// =========================
app.post("/auth/login", async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const user = await User.findOne({ username, role });
    if (!user || user.password !== password) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }
    req.session.user = { id: user._id, username: user.username, role: user.role, email: user.email };
    
    // ✅ FIX: Explicit save to ensure cookie is set before response
    req.session.save((err) => {
        if(err) return res.status(500).json({success: false, message: "Session Error"});
        res.json({ success: true, user: req.session.user });
    });

  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.post("/auth/logout", (req, res) => {
    req.session.destroy(() => {
        res.clearCookie("connect.sid", { path: '/' });
        res.json({ success: true });
    });
});

app.get("/auth/me", (req, res) => {
    if(req.session.user) {
        res.json({ success: true, user: req.session.user });
    } else {
        res.status(401).json({ success: false, message: "Not logged in" });
    }
});

// =========================
// ROUTES: ADMIN (Your Original Logic Preserved)
// =========================

app.post("/admin/doctor", requireRole('admin'), async (req, res) => {
  try {
    await User.create({ ...req.body, role: "doctor" });
    res.json({ success: true });
  } catch (err) { res.status(400).json({ message: err.message }); }
});

app.post("/admin/technician", requireRole('admin'), async (req, res) => {
  try {
    await User.create({ ...req.body, role: "technician" });
    res.json({ success: true });
  } catch (err) { res.status(400).json({ message: err.message }); }
});

app.post("/admin/radiologist", requireRole('admin'), async (req, res) => {
  try {
    await User.create({ ...req.body, role: "radiologist" });
    res.json({ success: true });
  } catch (err) { res.status(400).json({ message: err.message }); }
});

app.post("/admin/patient", requireRole('admin'), async (req, res) => {
  try {
    await User.create({ ...req.body, role: "patient" });
    res.json({ success: true });
  } catch (err) { res.status(400).json({ message: err.message }); }
});

app.get("/admin/lists", requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const patients = await User.find({ role: "patient" });
    const doctors = await User.find({ role: "doctor" });
    const technicians = await User.find({ role: "technician" });
    res.json({ patients, doctors, technicians });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// Helper for users
app.get("/admin/users/:role", requireRole(['admin', 'doctor']), async (req, res) => {
    try {
        const users = await User.find({ role: req.params.role }).select("name _id");
        res.json({ users });
    } catch(e) { res.status(500).json({error: e.message}); }
});

app.post("/admin/case", requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    await Case.create(req.body);
    io.emit("update-dashboard");
    res.json({ success: true });
  } catch (err) { res.status(400).json({ message: err.message }); }
});

app.get("/admin/cases", requireRole(['admin', 'radiologist', 'technician']), async (req, res) => {
  try {
    const cases = await Case.find().populate("patient doctor technician").sort({ date: -1 });
    res.json({ cases });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.delete("/admin/case/:id", requireRole(['admin', 'radiologist']), async (req, res) => {
    try {
        await Case.findByIdAndDelete(req.params.id);
        io.emit("update-dashboard");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

// =========================
// ROUTES: DOCTOR (Enhanced)
// =========================

// 1. Create Case Route
app.post("/doctor/create-case", requireRole('doctor'), async (req, res) => {
    try {
        const { patientId, scanType, symptoms } = req.body;
        const newCase = new Case({
            caseId: "CASE-" + Math.floor(1000 + Math.random() * 9000),
            patient: patientId,
            doctor: req.session.user.id,
            scanType, symptoms, status: "Pending"
        });
        await newCase.save();
        io.emit("update-dashboard");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 2. Prescribe & Email (New Feature)
app.post("/doctor/prescribe/:caseId", requireRole('doctor'), async (req, res) => {
    try {
        const c = await Case.findById(req.params.caseId).populate('patient');
        c.prescription = req.body.prescription;
        c.status = "Completed";
        await c.save();
        
        // Send Email
        if(c.patient?.email) sendEmail(c.patient.email, "New Prescription - Rad AI", `Doctor has added a prescription: ${c.prescription}`);
        
        io.emit("update-dashboard");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.get("/doctor/cases/:doctorId", requireRole('doctor'), async (req, res) => {
  try {
    const cases = await Case.find({ doctor: req.params.doctorId })
      .populate("patient").populate("technician").sort({date:-1});
    res.json({ cases });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// =========================
// ROUTES: TECHNICIAN
// =========================

app.get("/technician/cases", requireRole("technician"), async (req, res) => {
  try {
    const cases = await Case.find().populate("patient doctor").sort({date:-1});
    res.json({ cases });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post("/tech/upload-cloud/:caseId", requireRole("technician"), upload.array("images", 5), async (req, res) => {
    try {
      if (!req.files || req.files.length === 0) return res.status(400).json({ message: "No files" });
      const c = await Case.findById(req.params.caseId);
      if (!c) return res.status(404).json({ message: "Not found" });

      const urls = [];
      for (const file of req.files) {
        try {
            const result = await new Promise((resolve, reject) => {
              const stream = cloudinary.uploader.upload_stream({ folder: "radiology" }, (e, r) => e ? reject(e) : resolve(r));
              streamifier.createReadStream(file.buffer).pipe(stream);
            });
            if(result?.secure_url) urls.push(result.secure_url);
        } catch(e) { console.error("Upload error", e); }
      }

      c.images = [...(c.images || []), ...urls];
      c.status = "Scanned"; 
      await c.save();
      io.emit("update-dashboard");
      return res.json({ success: true });
    } catch (err) { return res.status(500).json({ message: "Upload failed" }); }
});

// =========================
// ROUTES: RADIOLOGIST (AI + Auto-Triage)
// =========================

// 1. Manual Notes
app.post("/radio/notes/:caseId", requireRole("radiologist"), async (req, res) => {
  try {
    const c = await Case.findById(req.params.caseId);
    c.radiologistNotes = req.body.radiologistNotes || "";
    await c.save();
    io.emit("update-dashboard");
    res.json({ success: true });
  } catch (err) { res.status(500).json({ message: "Error" }); }
});

// 2. AI Analysis (Enhanced: Auto-Triage + JSON)
app.post("/radio/ai-analyze/:caseId", requireRole(['radiologist', 'admin']), async (req, res) => {
  try {
    const c = await Case.findById(req.params.caseId);
    if (!c?.images?.length) return res.status(400).json({ message: "No images" });

    const imageResp = await axios.get(c.images[0], { responseType: "arraybuffer" });
    const imagePart = { inlineData: { data: Buffer.from(imageResp.data).toString("base64"), mimeType: "image/jpeg" } };

    // Use Gemini 1.5 Flash (Fast + Accurate)
    const model = genAI.getGenerativeModel({ 
        model: "gemini-1.5-flash",
        generationConfig: { responseMimeType: "application/json" } // STRICT JSON
    });

    const prompt = `Analyze this scan. 
    1. Check for Fractures, Tumors, Hemorrhage.
    2. Set 'severity' to 'Critical' if life-threatening (Hemorrhage/Displaced Fracture), otherwise 'Medium' or 'Safe'.
    Return JSON: { "findings": "string", "diagnosis": "string", "severity": "Safe|Medium|Critical", "confidence": "string", "bodyPart": "string", "report": "string" }`;

    const result = await model.generateContent({
        contents: [{ role: "user", parts: [{ text: prompt }, imagePart] }]
    });

    const rawText = result.response.text();
    // Safety Regex to extract JSON block
    const jsonMatch = rawText.match(/\{[\s\S]*\}/);
    let aiData;
    if (jsonMatch) {
        try { aiData = JSON.parse(jsonMatch[0]); } catch(e) { throw new Error("JSON Parse Failed"); }
    } else {
        aiData = { findings: "Error parsing AI", diagnosis: "Manual Review", severity: "Medium", report: rawText };
    }

    // UPDATE DB (Auto-Triage)
    c.priority = aiData.severity || "Medium";
    c.aiData = aiData;
    c.radiologistNotes = aiData.report;
    c.status = "Analyzed";
    await c.save();

    io.emit("update-dashboard");
    return res.json({ success: true, aiData });
  } catch (err) { 
    console.error("AI Error:", err);
    return res.status(500).json({ message: "AI Analysis Failed" });
  }
});

// --- NEW: CHAT WITH SCAN ---
app.post("/ai/chat/:caseId", requireRole(['radiologist', 'doctor']), async (req, res) => {
    try {
        const { question } = req.body;
        const c = await Case.findById(req.params.caseId);
        if (!c?.images?.length) return res.status(400).json({message:"No image"});

        const imageResp = await axios.get(c.images[0], { responseType: "arraybuffer" });
        const imagePart = { inlineData: { data: Buffer.from(imageResp.data).toString("base64"), mimeType: "image/jpeg" } };
        
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        const result = await model.generateContent({
            contents: [{ role: "user", parts: [{ text: `Question: ${question}. Be clinical.` }, imagePart] }]
        });
        
        const answer = result.response.text();
        c.chatHistory.push({ role: "user", message: question });
        c.chatHistory.push({ role: "ai", message: answer });
        if(c.chatHistory.length > 20) c.chatHistory.shift(); // Limit history
        await c.save();
        return res.json({ success: true, answer });
    } catch (e) { return res.status(500).json({ message: e.message }); }
});

// =========================
// ROUTES: PATIENT (Enhanced)
// =========================

app.get("/patient/cases/:patientId", requireRole('patient'), async (req, res) => {
  try {
    const cases = await Case.find({ patient: req.params.patientId })
      .populate("doctor").populate("technician").sort({date:-1});
    res.json({ cases });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// New: Medical Timeline
app.get("/patient/history/:id", requireRole(['doctor', 'patient']), async (req, res) => {
    try {
        const cases = await Case.find({ patient: req.params.id }).select("date scanType priority").sort({date:-1});
        return res.json({ history: cases });
    } catch (e) { return res.status(500).json({ error: e.message }); }
});

// New: PDF Report Download
app.get("/patient/pdf/:caseId", requireRole(['patient', 'doctor', 'radiologist']), async (req, res) => {
    try {
        const c = await Case.findById(req.params.caseId).populate('patient doctor');
        if(!c) return res.status(404).send("Not Found");

        const doc = new PDFDocument();
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=Report-${c.caseId}.pdf`);
        doc.pipe(res);
        
        doc.fontSize(20).text("Rad AI Medical Report", { align: 'center' });
        doc.moveDown();
        doc.fontSize(12).text(`Patient: ${c.patient?.name || 'N/A'}`);
        doc.text(`Doctor: ${c.doctor?.name || 'N/A'}`);
        doc.text(`Date: ${new Date(c.date).toDateString()}`);
        doc.moveDown();
        doc.fontSize(14).text("AI Findings:", { underline: true });
        doc.fontSize(12).text(c.radiologistNotes || "Pending Analysis");
        
        if (c.images.length > 0) {
            try {
                const img = await axios.get(c.images[0], { responseType: 'arraybuffer' });
                doc.image(Buffer.from(img.data), { width: 300, align: 'center' });
            } catch(e) {}
        }
        
        if(c.prescription) {
            doc.moveDown();
            doc.fontSize(14).text("Prescription:", { underline: true });
            doc.text(c.prescription);
        }
        doc.end();
    } catch (e) { res.status(500).send("PDF Error"); }
});

// Generic
app.get("/case/:id", async (req, res) => {
  try {
    const singleCase = await Case.findById(req.params.id).populate("patient doctor technician");
    res.json({ case: singleCase });
  } catch (err) { res.status(404).json({ message: "Case not found" }); }
});

// =========================
// START SERVER
// =========================

app.get("/health", (_req, res) => res.json({ ok: true, now: new Date().toISOString() }));

app.use((req, res) => {
  res.status(404).json({ success: false, message: "Route not found" });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});