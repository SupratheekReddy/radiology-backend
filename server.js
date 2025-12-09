// ================================================================
// SERVER.JS — Final Version (Groq Llama 3.2 Vision Edition)
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
const nodemailer = require("nodemailer"); 
const PDFDocument = require("pdfkit");    
// ✅ CHANGED: Import Groq instead of GoogleGenerativeAI
const Groq = require("groq-sdk");

// --- 1. ENVIRONMENT CHECK ---
// ✅ CHANGED: Check for GROQ_API_KEY instead of GEMINI
const requiredEnv = ['MONGO_URI', 'CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET', 'GROQ_API_KEY'];
if (requiredEnv.some(key => !process.env[key])) {
    console.error(`❌ CRITICAL: Missing .env keys: ${requiredEnv.filter(k => !process.env[k]).join(', ')}`);
}

// =========================
// APP & SERVER INITIALIZATION
// =========================

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 10000; 

// --- 2. ROBUST CORS ---
const ALLOWED_ORIGINS = [
    "https://radiology-system.netlify.app", 
    "http://localhost:5500",                
    "http://127.0.0.1:5500"
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || ALLOWED_ORIGINS.includes(origin) || origin.endsWith(".netlify.app")) {
            callback(null, true);
        } else {
            console.log("Blocked CORS origin:", origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, 
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
};

// Trust Proxy for Render
app.set("trust proxy", 1);

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session Settings
app.use(session({
    secret: process.env.SESSION_SECRET || "radai_secret_999",
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,        // Required for Render (HTTPS)
        sameSite: 'none',    // Required for Netlify -> Render
        maxAge: 24 * 60 * 60 * 1000 
    },
}));

const io = new Server(server, { cors: corsOptions });

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);
});

// =========================
// DATABASE & MODELS
// =========================

const UserSchema = new mongoose.Schema({
    name: String, 
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'doctor', 'technician', 'radiologist', 'patient'], required: true },
    email: String,
    basePriority: String
});
const User = mongoose.models.Account || mongoose.model("Account", UserSchema);

const CaseSchema = new mongoose.Schema({
    caseId: String,
    patient: { type: mongoose.Schema.Types.ObjectId, ref: 'Account' },
    doctor: { type: mongoose.Schema.Types.ObjectId, ref: 'Account' },
    technician: { type: mongoose.Schema.Types.ObjectId, ref: 'Account' },
    
    images: { type: [String], default: [] },
    scanType: String,
    symptoms: String,
    priority: { type: String, enum: ['Safe', 'Medium', 'Critical'], default: 'Medium' },
    status: { type: String, default: 'Pending' },
    date: { type: Date, default: Date.now },
    
    // AI Data (Updated with Treatment)
    aiData: { 
        isMedical: { type: Boolean, default: true },
        findings: String, 
        diagnosis: String, 
        confidence: String, 
        bodyPart: String,
        treatment: String 
    },
    
    // Notes & Prescriptions
    radiologistNotes: String, // Radiologist's Analysis/Note
    prescription: String,     // Doctor's Final Prescription
    
    chatHistory: { type: [{ role: String, message: String }], default: [] }
});
const Case = mongoose.models.Case || mongoose.model("Case", CaseSchema);

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected"))
    .catch((err) => console.error("❌ MongoDB Error:", err));

// --- ADMIN RESET ---
(async () => {
  try {
    const adminExists = await User.findOne({ role: "admin" });
    if (!adminExists) {
        console.log("⚠ Creating default admin account...");
        await User.create({
            name: "System Admin", email: "admin@system.com",
            username: "admin", password: "123", role: "admin"
        });
        // Create defaults
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

// ✅ CHANGED: Initialize Groq
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// --- EMAIL HELPER ---
async function sendEmail(to, subject, html) {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) return;
    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
        });
        await transporter.sendMail({ from: '"Rad AI Platform" <no-reply@radai.com>', to, subject, html });
    } catch (e) { console.error("❌ Email Failed:", e.message); }
}

// Middleware
const requireRole = (role) => (req, res, next) => {
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
    req.session.save((err) => {
        if(err) return res.status(500).json({success: false});
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
    if(req.session.user) res.json({ success: true, user: req.session.user });
    else res.status(401).json({ success: false, message: "Not logged in" });
});

// =========================
// ROUTES: SHARED / GENERIC
// =========================

app.get("/case/:id", async (req, res) => {
    try {
        const singleCase = await Case.findById(req.params.id).populate("patient doctor technician");
        if(!singleCase) return res.status(404).json({ success: false, message: "Case not found" });
        res.json({ success: true, case: singleCase });
    } catch (err) { res.status(500).json({ message: "Server Error" }); }
});

// =========================
// ROUTES: ADMIN
// =========================

app.get("/admin/users/:role", requireRole(['admin', 'doctor']), async (req, res) => {
    try {
        const users = await User.find({ role: req.params.role }).select("name _id");
        res.json({ users });
    } catch(e) { res.status(500).json({error: e.message}); }
});

app.post("/admin/case", requireRole(['admin', 'doctor']), async (req, res) => {
  try { await Case.create(req.body); io.emit("update-dashboard"); res.json({ success: true }); } catch (err) { res.status(400).json({ message: err.message }); }
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
        res.json({ success: true, message: "Case Deleted" }); 
    } catch (e) { res.status(500).json({ success: false }); }
});

app.post("/admin/doctor", requireRole('admin'), async (req, res) => { try { await User.create({ ...req.body, role: "doctor" }); res.json({ success: true }); } catch (e) { res.status(400).json({ message: e.message }); } });
app.post("/admin/technician", requireRole('admin'), async (req, res) => { try { await User.create({ ...req.body, role: "technician" }); res.json({ success: true }); } catch (e) { res.status(400).json({ message: e.message }); } });
app.post("/admin/radiologist", requireRole('admin'), async (req, res) => { try { await User.create({ ...req.body, role: "radiologist" }); res.json({ success: true }); } catch (e) { res.status(400).json({ message: e.message }); } });
app.post("/admin/patient", requireRole('admin'), async (req, res) => { try { await User.create({ ...req.body, role: "patient" }); res.json({ success: true }); } catch (e) { res.status(400).json({ message: e.message }); } });
app.get("/admin/lists", requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const patients = await User.find({ role: "patient" });
    const doctors = await User.find({ role: "doctor" });
    res.json({ patients, doctors });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// =========================
// ROUTES: DOCTOR & TECH
// =========================

app.post("/doctor/create-case", requireRole('doctor'), async (req, res) => {
    try {
        const { patientId, scanType, symptoms } = req.body;
        const newCase = new Case({
            caseId: "CASE-" + Math.floor(1000 + Math.random() * 9000),
            patient: patientId, doctor: req.session.user.id, scanType, symptoms, status: "Pending"
        });
        await newCase.save(); io.emit("update-dashboard"); res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post("/doctor/prescribe/:caseId", requireRole('doctor'), async (req, res) => {
    try {
        const c = await Case.findById(req.params.caseId).populate('patient');
        c.prescription = req.body.prescription;
        c.status = "Completed";
        await c.save();
        if(c.patient?.email) sendEmail(c.patient.email, "New Prescription - Rad AI", `Doctor has added a prescription: ${c.prescription}`);
        io.emit("update-dashboard"); res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.get("/doctor/cases/:doctorId", requireRole('doctor'), async (req, res) => {
  try {
    const cases = await Case.find({ doctor: req.params.doctorId }).populate("patient").populate("technician").sort({date:-1});
    res.json({ cases });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

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
      await c.save(); io.emit("update-dashboard");
      return res.json({ success: true });
    } catch (err) { return res.status(500).json({ message: "Upload failed" }); }
});

// =========================
// ROUTES: RADIOLOGIST (AI + NOTES)
// =========================

app.post("/radio/notes/:caseId", requireRole("radiologist"), async (req, res) => {
  try {
    const c = await Case.findById(req.params.caseId);
    
    const newNote = req.body.radiologistNotes;
    const timestamp = new Date().toLocaleString();
    
    c.radiologistNotes = c.radiologistNotes 
        ? `${c.radiologistNotes}\n\n[Note - ${timestamp}]: ${newNote}`
        : `[Note - ${timestamp}]: ${newNote}`;

    await c.save(); 
    io.emit("update-dashboard"); 
    res.json({ success: true });
  } catch (err) { res.status(500).json({ message: "Error" }); }
});

// ✅ CHANGED: Logic Updated to use GROQ (Llama 3.2 Vision)
app.post("/radio/ai-analyze/:caseId", requireRole(['radiologist', 'admin']), async (req, res) => {
  try {
    const c = await Case.findById(req.params.caseId);
    if (!c?.images?.length) return res.status(400).json({ message: "No images found." });

    let imageResp;
    try {
        imageResp = await axios.get(c.images[0], { responseType: "arraybuffer", timeout: 10000 });
    } catch (axiosErr) {
        return res.status(400).json({ message: "Failed to download image." });
    }

    // ✅ Groq requires Data URI string
    const base64Image = Buffer.from(imageResp.data).toString("base64");
    const dataUrl = `data:image/jpeg;base64,${base64Image}`;

    const prompt = `
    Role: Expert Radiologist.
    Task: Analyze this image.

    STEP 1: IDENTITY CHECK
    Is this a medical scan (X-Ray, MRI, CT, Ultrasound)?
    - If NO (e.g., person, landscape, object): Return JSON with "isMedical": false.
    - If YES: Proceed to Step 2.

    STEP 2: DETAILED ANALYSIS
    Provide a COMPREHENSIVE report.
    1. Anatomical Region.
    2. Detailed Findings (Bone integrity, soft tissue, spacing, anomalies).
    3. Diagnosis (Specific condition or "Normal").
    4. TREATMENT: Suggest immediate next steps and possible medical treatments.
    5. Severity (Safe / Medium / Critical).

    Return ONLY VALID JSON format (no markdown):
    {
      "isMedical": true,
      "bodyPart": "String",
      "findings": "String (Very detailed medical observation, at least 4 sentences)",
      "diagnosis": "String",
      "treatment": "String (Recommended next steps and treatments)",
      "severity": "Safe" | "Medium" | "Critical",
      "confidence": "String (e.g. 98%)",
      "report": "String (Full formatted report)"
    }
    `;

    // ✅ CHANGED: Groq Chat Completion Call
    const chatCompletion = await groq.chat.completions.create({
        messages: [
            {
                role: "user",
                content: [
                    { type: "text", text: prompt },
                    { type: "image_url", image_url: { url: dataUrl } }
                ],
            },
        ],
        model: "llama-3.2-90b-vision-preview",
        temperature: 0.1,
        response_format: { type: "json_object" } // Force JSON Mode
    });

    const rawText = chatCompletion.choices[0].message.content;
    
    let aiData;
    try { 
        aiData = JSON.parse(rawText); 
    } catch(e) { 
        // Fallback cleanup if Llama adds markdown blocks despite response_format
        const jsonMatch = rawText.match(/\{[\s\S]*\}/);
        if(jsonMatch) aiData = JSON.parse(jsonMatch[0]);
        else aiData = { isMedical: true, findings: rawText, diagnosis: "Manual Review", severity: "Medium" }; 
    }

    if (aiData.isMedical === false) {
        aiData.findings = "Image is NOT related to medical radiology. Analysis aborted.";
        aiData.diagnosis = "Invalid Image";
        aiData.treatment = "N/A";
        aiData.severity = "Safe";
        c.radiologistNotes = "⚠️ Invalid Image Uploaded (Non-Medical detected).";
    } else {
        const detailedNote = `AI FINDINGS:\n${aiData.findings}\n\nSUGGESTED TREATMENT:\n${aiData.treatment || 'Consult Specialist'}`;
        c.radiologistNotes = detailedNote;
    }

    c.priority = aiData.severity || "Medium";
    c.aiData = aiData;
    c.status = "Analyzed";
    await c.save();

    io.emit("update-dashboard");
    return res.json({ success: true, aiData });

  } catch (err) { 
    console.error("AI Error:", err);
    return res.status(500).json({ message: `AI Failed: ${err.message}` });
  }
});

// --- CHAT WITH SCAN (Updated to Groq) ---
app.post("/ai/chat/:caseId", requireRole(['radiologist', 'doctor']), async (req, res) => {
    try {
        const { question } = req.body;
        const c = await Case.findById(req.params.caseId);
        if (!c?.images?.length) return res.status(400).json({message:"No image"});

        const imageResp = await axios.get(c.images[0], { responseType: "arraybuffer" });
        const base64Image = Buffer.from(imageResp.data).toString("base64");
        const dataUrl = `data:image/jpeg;base64,${base64Image}`;
        
        // ✅ CHANGED: Groq Chat Call
        const chatCompletion = await groq.chat.completions.create({
            messages: [
                {
                    role: "user",
                    content: [
                        { type: "text", text: `Question: ${question}. Be clinical. Think step by step.` },
                        { type: "image_url", image_url: { url: dataUrl } }
                    ],
                },
            ],
            model: "llama-3.2-90b-vision-preview",
        });
        
        const answer = chatCompletion.choices[0].message.content;

        c.chatHistory.push({ role: "user", message: question });
        c.chatHistory.push({ role: "ai", message: answer });
        if(c.chatHistory.length > 20) c.chatHistory.shift(); 
        await c.save();
        return res.json({ success: true, answer });
    } catch (e) { return res.status(500).json({ message: e.message }); }
});

// =========================
// ROUTES: PATIENT
// =========================

app.get("/patient/cases/:patientId", requireRole('patient'), async (req, res) => {
  try {
    const cases = await Case.find({ patient: req.params.patientId }).populate("doctor").populate("technician").sort({date:-1});
    res.json({ cases });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.get("/patient/history/:id", requireRole(['doctor', 'patient']), async (req, res) => {
    try {
        const cases = await Case.find({ patient: req.params.id }).select("date scanType priority").sort({date:-1});
        return res.json({ history: cases });
    } catch (e) { return res.status(500).json({ error: e.message }); }
});

app.get("/patient/pdf/:caseId", requireRole(['patient', 'doctor', 'radiologist']), async (req, res) => {
    try {
        const c = await Case.findById(req.params.caseId).populate('patient doctor');
        if(!c) return res.status(404).send("Not Found");
        const doc = new PDFDocument();
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=Report-${c.caseId}.pdf`);
        doc.pipe(res);
        doc.fontSize(20).text("Rad AI Medical Report", { align: 'center' }); doc.moveDown();
        doc.fontSize(12).text(`Patient: ${c.patient?.name || 'N/A'}`); doc.text(`Doctor: ${c.doctor?.name || 'N/A'}`);
        doc.text(`Date: ${new Date(c.date).toDateString()}`);
        
        if(c.radiologistNotes) {
            doc.moveDown();
            doc.fontSize(14).text("Radiology Findings:", { underline: true });
            doc.fontSize(12).text(c.radiologistNotes);
        }

        if(c.prescription) { 
            doc.moveDown(); doc.fontSize(14).text("Prescription:", { underline: true }); doc.text(c.prescription); 
        }
        doc.end();
    } catch (e) { res.status(500).send("PDF Error"); }
});

// =========================
// START SERVER
// =========================

app.get("/health", (_req, res) => res.json({ ok: true, now: new Date().toISOString() }));

app.use((req, res) => { res.status(404).json({ success: false, message: "Route not found" }); });

server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});