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
// Note: We import Account but assign it to 'User' variable because 
// the logic below uses 'User.findOne', etc.
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
  "http://localhost:3000" // Added common React port just in case
];

// Socket.io Setup
const io = new Server(server, {
  cors: {
    origin: FRONTEND_ORIGINS,
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Make io accessible globally or via req (optional, but good for separation)
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
  console.log("⚠ Resetting admin account...");

  await User.deleteMany({ role: "admin" });

  await User.create({
    name: "System Admin",
    email: "admin@system.com",
    username: "admin",
    password: "admin",
    role: "admin"
  });

  console.log("🟢 Admin reset complete! (admin/admin)");
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
      secure: process.env.NODE_ENV === "production", // true in production (https)
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

// Multer for Cloudinary (Memory Storage)
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// =========================
// GOOGLE GEMINI — AI HELPER
// =========================
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

async function analyzeImageURL(imageUrl) {
  try {
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`,
      {
        contents: [
          {
            parts: [
              { text: "Analyze this medical scan and provide a detailed radiology report. Include findings, likely diagnosis, and severity." },
              { fileData: { mimeType: "image/jpeg", fileUri: imageUrl } }
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
    console.error("Gemini error:", err.response?.data || err.message);
    return "Gemini analysis failed. Ensure API key is valid and image is accessible.";
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
    // In production, use bcrypt.compare here. 
    // Assuming plain text for now based on your 'admin/doctor' route logic.
    const user = await User.findOne({ username, role });
    
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

// ---- Add Doctor ----
app.post("/admin/doctor", async (req, res) => {
  const { name, email, username } = req.body;
  try {
    const doc = new User({
      name, email, username,
      password: "doctor123", // Ideally hash this
      role: "doctor",
    });
    await doc.save();
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// ---- Add Technician ----
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
// ---- Add Radiologist ----
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


// ---- Add Patient ----
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

// ---- Get Dropdown Lists ----
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

// ---- Schedule New Case ----
app.post("/admin/case", async (req, res) => {
  try {
    const newCase = new Case(req.body);
    await newCase.save();
    io.emit("case-created");
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// ---- Get All Cases (Admin) ----
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
// ROUTES: DOCTOR
// =========================

app.get("/doctor/cases/:doctorId", async (req, res) => {
  try {
    const cases = await Case.find({ doctor: req.params.doctorId })
      .populate("patient")
      .populate("technician");
    res.json({ cases });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/doctor/diagnosis/:caseId", async (req, res) => {
  const { diagnosis, severity } = req.body;
  try {
    const updated = await Case.findByIdAndUpdate(
      req.params.caseId,
      { diagnosis, severity, status: "diagnosed" },
      { new: true }
    );
    io.emit("case-updated");
    res.json({ success: true, case: updated });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// =========================
// ROUTES: PATIENT
// =========================

app.get("/patient/cases/:patientId", async (req, res) => {
  try {
    const cases = await Case.find({ patient: req.params.patientId })
      .populate("doctor")
      .populate("technician");
    res.json({ cases });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// =========================
// ROUTES: SHARED / GENERIC
// =========================

app.get("/case/:id", async (req, res) => {
  try {
    const singleCase = await Case.findById(req.params.id)
      .populate("patient")
      .populate("doctor")
      .populate("technician");
    res.json({ case: singleCase });
  } catch (err) {
    res.status(404).json({ message: "Case not found" });
  }
});

app.post("/case/status/:id", async (req, res) => {
  const { status } = req.body;
  try {
    const updated = await Case.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    io.emit("case-updated");
    res.json({ success: true, case: updated });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// =========================
// ADD THIS TO server.js (Under ROUTES: TECHNICIAN)
// =========================

// ---- Get All Cases for Technician ----
app.get("/technician/cases", requireLogin, requireRole("technician"), async (req, res) => {
  try {
    // Return all cases so tech can see what needs scanning
    // Optionally filter by { status: "pending" } if you only want pending ones
    const cases = await Case.find()
      .populate("patient", "name")
      .populate("doctor", "name");
    
    res.json({ cases });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Upload to Cloudinary via Memory Stream
app.post(
  "/tech/upload-cloud/:caseId",
  requireLogin,
  requireRole("technician"),
  upload.array("images", 10),
  async (req, res) => {
    try {
      // Find case by _id or custom caseId field. Assuming _id for Mongoose safety, 
      // but logic below attempts custom caseId first.
      let c = await Case.findOne({ caseId: req.params.caseId });
      if (!c) {
         // Fallback: try finding by MongoDB _id
         try { c = await Case.findById(req.params.caseId); } catch(e){}
      }
      
      if (!c) return res.status(404).json({ success: false, message: "Case not found" });

      if (!req.files || req.files.length === 0)
        return res.status(400).json({ success: false, message: "No files uploaded" });

      // Process uploads
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
// ROUTES: RADIOLOGIST (Notes + AI)
// =========================

// Save Radiologist Notes
app.post("/radio/notes/:caseId", requireLogin, requireRole("radiologist"), async (req, res) => {
  try {
    const c = await Case.findById(req.params.caseId);
    if (!c) return res.status(404).json({ success: false, message: "Case not found" });

    c.radiologistNotes = req.body.radiologistNotes || "";
    await c.save();

    io.emit("radiologist-updated", { caseId: c._id });

    return res.json({ success: true });
  } catch (err) {
    console.error("Radio notes error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// AI Analysis with Gemini
app.post("/radio/ai-analyze/:caseId", requireLogin, requireRole("radiologist"), async (req, res) => {
  try {
    const c = await Case.findById(req.params.caseId);
    if (!c) return res.status(404).json({ success: false, message: "Case not found" });

    if (!c.images || c.images.length === 0)
      return res.status(400).json({ success: false, message: "No images to analyze" });

    const imageUrl = c.images[0]; // Analyzing the first image

    const aiReport = await analyzeImageURL(imageUrl);

    // Append AI report to existing notes
    c.radiologistNotes = `${c.radiologistNotes || ""}\n\n--- AI ANALYSIS REPORT (${new Date().toLocaleDateString()}) ---\n${aiReport}`;
    await c.save();

    io.emit("ai-report-generated", { caseId: c._id });

    return res.json({ success: true, aiReport });
  } catch (err) {
    console.error("AI analyze error:", err);
    return res.status(500).json({ success: false, message: "AI analysis failed" });
  }
});

// =========================
// ERROR HANDLING & START
// =========================

app.get("/health", (_req, res) => res.json({ ok: true, now: new Date().toISOString() }));

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: "Route not found" });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error("UNHANDLED ERROR:", err);
  res.status(500).json({ success: false, message: "Internal server error" });
});

// Start Server
server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log("🌍 Environment:", process.env.NODE_ENV || "development");
});