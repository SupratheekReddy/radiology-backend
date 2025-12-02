// =========================
// PART 1 — IMPORTS + SETUP
// =========================

require("dotenv").config();
const path = require("path");
const fs = require("fs");
const http = require("http");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const axios = require("axios");
const streamifier = require("streamifier");
const { Server } = require("socket.io");
const cloudinary = require("cloudinary").v2;

// Models
const User = require("./models/Account"); 
const Case = require("./models/Case");

// =========================
// APP & SERVER INITIALIZATION
// =========================

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 5000;
const FRONTEND_ORIGINS = [
  "https://radiology-system.netlify.app",
  "https://*.netlify.app",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:3000"
];

// Socket.io Setup
const io = new Server(server, {
  cors: {
    origin: FRONTEND_ORIGINS,
    methods: ["GET", "POST"],
    credentials: true
  }
});

app.set("io", io);

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);
  socket.on("disconnect", () => {
    console.log("Socket disconnected:", socket.id);
  });
});

// =========================
// DATABASE CONNECTION
// =========================
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log("✅ MongoDB Connected"))
.catch((err) => console.error("❌ MongoDB Error:", err));

// =========================
// RESET ADMIN (OPTIONAL)
// =========================
(async () => {
  try {
    const adminExists = await User.findOne({ role: "admin" });
    if (!adminExists) {
        console.log("⚠ Creating default admin account...");
        await User.create({
            name: "System Admin",
            email: "admin@system.com",
            username: "admin",
            password: "admin",
            role: "admin"
        });
        console.log("🟢 Admin created (admin/admin)");
    }
  } catch (err) {
    console.error("Admin check failed:", err.message);
  }
})();

// =========================
// MIDDLEWARE
// =========================

app.set("trust proxy", 1);
app.use(cors({ origin: FRONTEND_ORIGINS, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

// --- Custom Auth Middleware ---
const requireLogin = (req, res, next) => {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ success: false, message: "Unauthorized: Please login" });
  }
};

const requireRole = (role) => {
  return (req, res, next) => {
    if (req.session.user && req.session.user.role === role) {
      next();
    } else {
      res.status(403).json({ success: false, message: "Forbidden: Insufficient permissions" });
    }
  };
};

// =========================
// CLOUDINARY CONFIG
// =========================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// =========================
// GOOGLE GEMINI — AI HELPER (FIXED)
// =========================
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

async function analyzeImageURL(imageUrl) {
  try {
    // 1. Download the image from Cloudinary (or any URL)
    const imageResp = await axios.get(imageUrl, { responseType: "arraybuffer" });
    
    // 2. Convert to Base64
    const base64Image = Buffer.from(imageResp.data).toString("base64");
    
    // 3. Simple MIME detection
    const mimeType = imageUrl.endsWith(".png") ? "image/png" : "image/jpeg";

    // 4. Send to Gemini using inlineData
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`,
      {
        contents: [
          {
            parts: [
              { text: "Analyze this medical scan and provide a detailed radiology report. Include findings, likely diagnosis, and severity." },
              {
                inlineData: {
                  mimeType: mimeType,
                  data: base64Image
                }
              }
            ]
          }
        ]
      }
    );

    return (
      response.data?.candidates?.[0]?.content?.parts?.[0]?.text ||
      "AI could not generate a report."
    );

  } catch (err) {
    console.error("Gemini error details:", err.response?.data || err.message);
    return "Gemini analysis failed. Please check server logs.";
  }
}

// =========================
// ROUTES: AUTH
// =========================
app.post("/auth/login", async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    const user = await User.findOne({ username, role });
    
    // Simple password check (Hash in production!)
    if (!user || user.password !== password) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    req.session.user = {
      id: user._id,
      username: user.username,
      role: user.role,
    };

    res.json({ success: true, user: req.session.user });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get("/auth/me", (req, res) => {
    if(req.session.user) {
        res.json({ success: true, user: req.session.user });
    } else {
        res.json({ success: false, user: null });
    }
});

// =========================
// ROUTES: ADMIN
// =========================

app.post("/admin/doctor", async (req, res) => {
  const { name, email, username, password } = req.body; // Added password extraction
  try {
    const doc = new User({
      name, email, username,
      password: password || "doctor123",
      role: "doctor",
    });
    await doc.save();
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.post("/admin/technician", async (req, res) => {
  const { name, email, username, password } = req.body;
  try {
    const tech = new User({
      name, email, username, password,
      role: "technician",
    });
    await tech.save();
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.post("/admin/radiologist", async (req, res) => {
  const { name, email, username, password } = req.body;
  try {
    const radio = new User({
      name, email, username, password,
      role: "radiologist"
    });
    await radio.save();
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.post("/admin/patient", async (req, res) => {
  const { name, email, username, password, basePriority } = req.body;
  try {
    const patient = new User({
      name, email, username, password,
      role: "patient",
      basePriority,
    });
    await patient.save();
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.get("/admin/lists", async (req, res) => {
  try {
    const patients = await User.find({ role: "patient" });
    const doctors = await User.find({ role: "doctor" });
    const technicians = await User.find({ role: "technician" });
    res.json({ patients, doctors, technicians });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/admin/case", async (req, res) => {
  try {
    const newCase = new Case(req.body);
    await newCase.save();
    io.emit("case-created");
    res.json({ success: true });
  } catch (err) {
    console.error("Schedule error:", err);
    res.status(400).json({ success: false, message: err.message });
  }
});

app.get("/admin/cases", async (req, res) => {
  try {
    const cases = await Case.find()
      .populate("patient", "name")
      .populate("doctor", "name")
      .populate("technician", "name");
    res.json({ cases });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// =========================
// ROUTES: TECHNICIAN
// =========================

// Get All Cases for Technician
app.get("/technician/cases", requireLogin, requireRole("technician"), async (req, res) => {
  try {
    const cases = await Case.find()
      .populate("patient", "name")
      .populate("doctor", "name");
    res.json({ cases });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Upload to Cloudinary
app.post(
  "/tech/upload-cloud/:caseId",
  requireLogin,
  requireRole("technician"),
  upload.array("images", 10),
  async (req, res) => {
    try {
      // Find case by custom caseId OR _id
      let c = await Case.findOne({ caseId: req.params.caseId });
      if (!c) {
         try { c = await Case.findById(req.params.caseId); } catch(e){}
      }
      
      if (!c) return res.status(404).json({ success: false, message: "Case not found" });

      if (!req.files || req.files.length === 0)
        return res.status(400).json({ success: false, message: "No files uploaded" });

      // Upload to Cloudinary
      const uploadPromises = req.files.map((file) => {
        return new Promise((resolve, reject) => {
          const uploadStream = cloudinary.uploader.upload_stream(
            { folder: "radiology_cases" },
            (err, result) => {
              if (err) return reject(err);
              resolve(result.secure_url);
            }
          );
          streamifier.createReadStream(file.buffer).pipe(uploadStream);
        });
      });

      const uploadedUrls = await Promise.all(uploadPromises);

      // Append images
      c.images = [...(c.images || []), ...uploadedUrls];
      c.status = "Scanned"; // Update status
      await c.save();

      io.emit("images-updated", { caseId: c._id });

      return res.json({ success: true, images: c.images });
    } catch (err) {
      console.error("Tech upload error:", err);
      return res.status(500).json({ success: false, message: "Upload failed" });
    }
  }
);

// =========================
// ROUTES: RADIOLOGIST (AI)
// =========================

app.post("/radio/notes/:caseId", requireLogin, requireRole("radiologist"), async (req, res) => {
  try {
    const c = await Case.findById(req.params.caseId);
    if (!c) return res.status(404).json({ success: false, message: "Case not found" });

    c.radiologistNotes = req.body.radiologistNotes || "";
    await c.save();

    io.emit("radiologist-updated", { caseId: c._id });
    res.json({ success: true });
  } catch (err) {
    console.error("Radio notes error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Trigger AI Analysis
app.post("/radio/ai-analyze/:caseId", requireLogin, requireRole("radiologist"), async (req, res) => {
  try {
    // 1. Find Case
    // Try by _id first, then by caseId if strictly needed, usually frontend sends _id for actions
    let c = await Case.findById(req.params.caseId);
    if (!c) c = await Case.findOne({ caseId: req.params.caseId });

    if (!c) return res.status(404).json({ success: false, message: "Case not found" });

    if (!c.images || c.images.length === 0)
      return res.status(400).json({ success: false, message: "No images to analyze" });

    // 2. Analyze First Image
    const imageUrl = c.images[0]; 
    console.log(`Analyzing image for Case ${c.caseId}: ${imageUrl}`);

    const aiReport = await analyzeImageURL(imageUrl);

    // 3. Save Report
    const separator = `\n\n--- AI ANALYSIS REPORT (${new Date().toLocaleDateString()}) ---\n`;
    c.radiologistNotes = (c.radiologistNotes || "") + separator + aiReport;
    
    await c.save();

    io.emit("ai-report-generated", { caseId: c._id });

    return res.json({ success: true, aiReport });
  } catch (err) {
    console.error("AI analyze error:", err);
    return res.status(500).json({ success: false, message: "AI analysis failed" });
  }
});

// =========================
// ROUTES: SHARED/GENERIC
// =========================

app.get("/doctor/cases/:doctorId", async (req, res) => {
  try {
    const cases = await Case.find({ doctor: req.params.doctorId })
      .populate("patient").populate("technician");
    res.json({ cases });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/patient/cases/:patientId", async (req, res) => {
  try {
    const cases = await Case.find({ patient: req.params.patientId })
      .populate("doctor").populate("technician");
    res.json({ cases });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/case/:id", async (req, res) => {
  try {
    const singleCase = await Case.findById(req.params.id)
      .populate("patient").populate("doctor").populate("technician");
    res.json({ case: singleCase });
  } catch (err) {
    res.status(404).json({ message: "Case not found" });
  }
});

// =========================
// START SERVER
// =========================

app.get("/health", (_req, res) => res.json({ ok: true, now: new Date().toISOString() }));

app.use((req, res) => {
  res.status(404).json({ success: false, message: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error("UNHANDLED ERROR:", err);
  res.status(500).json({ success: false, message: "Internal server error" });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log("🌍 Environment:", process.env.NODE_ENV || "development");
});