require("dotenv").config();
const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const session = require("express-session");
const RedisStore = require("connect-redis").default;
const { createClient } = require("redis");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const logger = require("./logger");
const Account = require("./models/Account");
const Case = require("./models/Case");

// HTTP + SOCKET.IO
const http = require("http");
const { Server } = require("socket.io");

// socket.io instance (assigned later)


// ---------- Setup ----------
const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/radiology";
const SESSION_SECRET = process.env.SESSION_SECRET || "supersecretbaby";
const REDIS_URL = "redis://127.0.0.1:6380";


// ---------- FRONTEND ORIGINS (LAN + local) ----------
const FRONTEND_ORIGINS = [
  "http://10.137.53.11:5500",  // your hotspot IP + frontend port
  "http://localhost:5500",
  "http://127.0.0.1:5500"
];

// ---------- CORS ----------
app.use(cors({
  origin: FRONTEND_ORIGINS,
  credentials: true
}));

app.use(express.json());

// ---------- Redis + Session ----------
const redisClient = createClient({ url: REDIS_URL });
redisClient.connect().catch(console.error);

const redisStore = new RedisStore({
  client: redisClient,
  prefix: "radiology_sess:"
});

app.use(
  session({
    store: redisStore,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 8
    }
  })
);

// ---------- Mongo ----------
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB error", err));
// ---------- Seed Default Accounts ----------
async function seedDefaults() {
  const admin = await Account.findOne({ role: "admin", username: "admin" });
  if (!admin) {
    const hash = await bcrypt.hash("admin", 10);
    await Account.create({
      role: "admin",
      username: "admin",
      password: hash,
      name: "Administrator",
      email: "admin@example.com"
    });
    console.log("Seeded admin/admin");
  }

  const radio = await Account.findOne({ role: "radiologist", username: "radiologist" });
  if (!radio) {
    const hash = await bcrypt.hash("radiologist", 10);
    await Account.create({
      role: "radiologist",
      username: "radiologist",
      password: hash,
      name: "Radiologist",
      email: "radiologist@example.com"
    });
    console.log("Seeded radiologist/radiologist");
  }
}
seedDefaults();

// ---------- Multer (image uploads) ----------
const uploadDir = path.join(__dirname, "uploads");
const storage = multer.diskStorage({
  destination: function (_req, _file, cb) {
    cb(null, uploadDir);
  },
  filename: function (_req, file, cb) {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const cleaned = file.originalname.replace(/\s+/g, "_");
    cb(null, unique + "-" + cleaned);
  }
});
const upload = multer({ storage });

app.use("/uploads", express.static(uploadDir));

// ---------- Middleware ----------
function requireLogin(req, res, next) {
  if (!req.session.user)
    return res.status(401).json({ success: false, message: "Not logged in" });
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.role !== role)
      return res.status(403).json({ success: false, message: "Forbidden" });
    next();
  };
}
// ---------- AUTH ROUTES ----------
app.post("/auth/login", async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password || !role)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const user = await Account.findOne({
      role,
      $or: [{ username }, { email: username }]
    });

    if (!user)
      return res.status(200).json({ success: false, message: "Invalid username or role." });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(200).json({ success: false, message: "Wrong password." });

    req.session.user = {
      username: user.username,
      role: user.role
    };

    return res.json({
      success: true,
      user: {
        username: user.username,
        role: user.role,
        name: user.name,
        email: user.email
      }
    });
  } catch (err) {
    console.error("Login error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err)
      return res.status(500).json({ success: false, message: "Logout failed" });

    res.clearCookie("connect.sid");
    return res.json({ success: true });
  });
});

// ---------- ADMIN: ADD DOCTOR ----------
app.post("/admin/doctor", requireLogin, requireRole("admin"), async (req, res) => {
  try {
    const { name, email, username } = req.body;
    if (!name || !email || !username)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const exists = await Account.findOne({ username });
    if (exists)
      return res.status(200).json({ success: false, message: "Username already taken" });

    const hashed = await bcrypt.hash("doctor", 10);
    await Account.create({
      role: "doctor",
      name,
      email,
      username,
      password: hashed
    });

    io.emit("doctor-updated");
    return res.json({ success: true });
  } catch (err) {
    console.error("Add doctor error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- ADMIN: ADD TECHNICIAN ----------
app.post("/admin/technician", requireLogin, requireRole("admin"), async (req, res) => {
  try {
    const { name, email, username, password } = req.body;

    if (!name || !email || !username || !password)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const exists = await Account.findOne({ username });
    if (exists)
      return res.status(200).json({ success: false, message: "Username already taken" });

    const hashed = await bcrypt.hash(password, 10);

    await Account.create({
      role: "technician",
      name,
      email,
      username,
      password: hashed
    });

    io.emit("tech-updated");
    return res.json({ success: true });
  } catch (err) {
    console.error("Add technician error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- ADMIN: ADD PATIENT ----------
app.post("/admin/patient", requireLogin, requireRole("admin"), async (req, res) => {
  try {
    const { name, email, username, password, basePriority } = req.body;

    if (!name || !email || !username || !password)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const exists = await Account.findOne({ username });
    if (exists)
      return res.status(200).json({ success: false, message: "Username already taken" });

    const hashed = await bcrypt.hash(password, 10);

    await Account.create({
      role: "patient",
      name,
      email,
      username,
      password: hashed,
      basePriority: basePriority || "Medium"
    });

    io.emit("patient-updated");
    return res.json({ success: true });
  } catch (err) {
    console.error("Add patient error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});
// ---------- ADMIN LISTS ----------
app.get("/admin/lists", requireLogin, requireRole("admin"), async (_req, res) => {
  try {
    const doctors = await Account.find({ role: "doctor" }).sort({ name: 1 });
    const patients = await Account.find({ role: "patient" }).sort({ name: 1 });

    return res.json({
      doctors: doctors.map(d => ({
        username: d.username,
        name: d.name,
        email: d.email
      })),
      patients: patients.map(p => ({
        username: p.username,
        name: p.name,
        email: p.email,
        basePriority: p.basePriority
      }))
    });
  } catch (err) {
    console.error("Admin lists error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- CREATE CASE ----------
app.post("/admin/case", requireLogin, requireRole("admin"), async (req, res) => {
  try {
    const {
      patientUsername,
      doctorUsername,
      date,
      timeSlot,
      scanType,
      priority,
      refDoctor,
      symptoms
    } = req.body;

    if (!patientUsername || !doctorUsername || !date || !timeSlot || !scanType)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const caseId = "CASE-" + Date.now();

    const newCase = await Case.create({
      caseId,
      patientUsername,
      doctorUsername,
      date,
      timeSlot,
      scanType,
      priority: priority || "Medium",
      refDoctor: refDoctor || "",
      symptoms: symptoms || "",
      images: [],
      doctorNotes: "",
      prescription: "",
      radiologistNotes: ""
    });

    io.emit("case-created");

    return res.json({ success: true, case: { id: newCase.caseId } });
  } catch (err) {
    console.error("Schedule case error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- LIST ALL CASES ----------
app.get("/admin/cases", requireLogin, requireRole("admin"), async (_req, res) => {
  try {
    const cases = await Case.find().sort({ createdAt: -1 });

    const doctorUsernames = [...new Set(cases.map(c => c.doctorUsername))];
    const patientUsernames = [...new Set(cases.map(c => c.patientUsername))];

    const doctors = await Account.find({ username: { $in: doctorUsernames } });
    const patients = await Account.find({ username: { $in: patientUsernames } });

    const docMap = new Map(doctors.map(d => [d.username, d]));
    const patMap = new Map(patients.map(p => [p.username, p]));

    const out = cases.map(c => ({
      id: c.caseId,
      patientUsername: c.patientUsername,
      doctorUsername: c.doctorUsername,
      date: c.date,
      timeSlot: c.timeSlot,
      scanType: c.scanType,
      priority: c.priority,
      refDoctor: c.refDoctor,
      symptoms: c.symptoms,
      images: c.images,
      doctorNotes: c.doctorNotes,
      prescription: c.prescription,
      radiologistNotes: c.radiologistNotes,
      patientName: patMap.get(c.patientUsername)?.name || null,
      doctorName: docMap.get(c.doctorUsername)?.name || null
    }));

    return res.json({ success: true, cases: out });
  } catch (err) {
    console.error("Admin cases error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- DOCTOR ROUTES ----------
app.get("/doctor/cases/:username", requireLogin, requireRole("doctor"), async (req, res) => {
  try {
    if (req.session.user.username !== req.params.username)
      return res.status(403).json({ success: false, message: "Forbidden" });

    const cases = await Case.find({ doctorUsername: req.params.username })
      .sort({ date: 1, timeSlot: 1 });

    const patientUsernames = [...new Set(cases.map(c => c.patientUsername))];
    const patients = await Account.find({ username: { $in: patientUsernames } });
    const patMap = new Map(patients.map(p => [p.username, p]));

    const out = cases.map(c => ({
      id: c.caseId,
      patientUsername: c.patientUsername,
      doctorUsername: c.doctorUsername,
      date: c.date,
      timeSlot: c.timeSlot,
      scanType: c.scanType,
      priority: c.priority,
      refDoctor: c.refDoctor,
      symptoms: c.symptoms,
      images: c.images,
      doctorNotes: c.doctorNotes,
      prescription: c.prescription,
      radiologistNotes: c.radiologistNotes,
      patientName: patMap.get(c.patientUsername)?.name || null
    }));

    return res.json({ success: true, cases: out });
  } catch (err) {
    console.error("Doctor cases error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/doctor/notes/:caseId", requireLogin, requireRole("doctor"), async (req, res) => {
  try {
    const c = await Case.findOne({ caseId: req.params.caseId });
    if (!c)
      return res.status(404).json({ success: false, message: "Case not found" });

    if (c.doctorUsername !== req.session.user.username)
      return res.status(403).json({ success: false, message: "Forbidden" });

    c.doctorNotes = req.body.doctorNotes || "";
    await c.save();

    io.emit("case-updated");

    return res.json({ success: true });
  } catch (err) {
    console.error("Doctor notes error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/doctor/prescription/:caseId", requireLogin, requireRole("doctor"), async (req, res) => {
  try {
    const c = await Case.findOne({ caseId: req.params.caseId });
    if (!c)
      return res.status(404).json({ success: false, message: "Case not found" });

    if (c.doctorUsername !== req.session.user.username)
      return res.status(403).json({ success: false, message: "Forbidden" });

    c.prescription = req.body.prescription || "";
    await c.save();

    io.emit("case-updated");
    return res.json({ success: true });
  } catch (err) {
    console.error("Doctor prescription error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});
// ---------- TECHNICIAN ROUTES ----------
app.get("/tech/cases", requireLogin, requireRole("technician"), async (_req, res) => {
  try {
    const cases = await Case.find().sort({ date: 1, timeSlot: 1 });

    const doctorUsernames = [...new Set(cases.map(c => c.doctorUsername))];
    const patientUsernames = [...new Set(cases.map(c => c.patientUsername))];

    const doctors = await Account.find({ username: { $in: doctorUsernames } });
    const patients = await Account.find({ username: { $in: patientUsernames } });

    const docMap = new Map(doctors.map(d => [d.username, d]));
    const patMap = new Map(patients.map(p => [p.username, p]));

    const out = cases.map(c => ({
      id: c.caseId,
      patientUsername: c.patientUsername,
      doctorUsername: c.doctorUsername,
      date: c.date,
      timeSlot: c.timeSlot,
      scanType: c.scanType,
      priority: c.priority,
      refDoctor: c.refDoctor,
      symptoms: c.symptoms,
      images: c.images,
      doctorNotes: c.doctorNotes,
      prescription: c.prescription,
      radiologistNotes: c.radiologistNotes,
      patientName: patMap.get(c.patientUsername)?.name || null,
      doctorName: docMap.get(c.doctorUsername)?.name || null
    }));

    return res.json({ success: true, cases: out });
  } catch (err) {
    console.error("Tech cases error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- TECH: UPLOAD IMAGES ----------
app.post(
  "/tech/upload/:caseId",
  requireLogin,
  requireRole("technician"),
  upload.array("images", 10),
  async (req, res) => {
    try {
      const c = await Case.findOne({ caseId: req.params.caseId });
      if (!c)
        return res.status(404).json({ success: false, message: "Case not found" });

      const files = req.files || [];
      if (!files.length)
        return res.status(400).json({ success: false, message: "No files uploaded" });

      const filenames = files.map(f => f.filename);
      c.images = [...c.images, ...filenames];
      await c.save();

      io.emit("images-updated");   // <-- realtime event

      return res.json({ success: true, images: c.images });
    } catch (err) {
      console.error("Tech upload error", err);
      return res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// ---------- RADIOLOGIST ROUTES ----------
app.get("/radio/cases", requireLogin, requireRole("radiologist"), async (_req, res) => {
  try {
    const cases = await Case.find({
      images: { $exists: true, $not: { $size: 0 } }
    }).sort({ createdAt: -1 });

    const doctorUsernames = [...new Set(cases.map(c => c.doctorUsername))];
    const patientUsernames = [...new Set(cases.map(c => c.patientUsername))];

    const doctors = await Account.find({ username: { $in: doctorUsernames } });
    const patients = await Account.find({ username: { $in: patientUsernames } });

    const docMap = new Map(doctors.map(d => [d.username, d]));
    const patMap = new Map(patients.map(p => [p.username, p]));

    const out = cases.map(c => ({
      id: c.caseId,
      patientUsername: c.patientUsername,
      doctorUsername: c.doctorUsername,
      date: c.date,
      timeSlot: c.timeSlot,
      scanType: c.scanType,
      priority: c.priority,
      refDoctor: c.refDoctor,
      symptoms: c.symptoms,
      images: c.images,
      doctorNotes: c.doctorNotes,
      prescription: c.prescription,
      radiologistNotes: c.radiologistNotes,
      patientName: patMap.get(c.patientUsername)?.name || null,
      doctorName: docMap.get(c.doctorUsername)?.name || null
    }));

    return res.json({ success: true, cases: out });
  } catch (err) {
    console.error("Radio cases error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/radio/notes/:caseId", requireLogin, requireRole("radiologist"), async (req, res) => {
  try {
    const c = await Case.findOne({ caseId: req.params.caseId });
    if (!c)
      return res.status(404).json({ success: false, message: "Case not found" });

    c.radiologistNotes = req.body.radiologistNotes || "";
    await c.save();

    io.emit("radiologist-updated");  // realtime

    return res.json({ success: true });
  } catch (err) {
    console.error("Radio notes error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- PATIENT ROUTES ----------
app.get("/patient/cases/:username", requireLogin, requireRole("patient"), async (req, res) => {
  try {
    if (req.session.user.username !== req.params.username)
      return res.status(403).json({ success: false, message: "Forbidden" });

    const cases = await Case.find({ patientUsername: req.params.username })
      .sort({ date: 1, timeSlot: 1 });

    const doctorUsernames = [...new Set(cases.map(c => c.doctorUsername))];
    const doctors = await Account.find({ username: { $in: doctorUsernames } });
    const docMap = new Map(doctors.map(d => [d.username, d]));

    const out = cases.map(c => ({
      id: c.caseId,
      patientUsername: c.patientUsername,
      doctorUsername: c.doctorUsername,
      date: c.date,
      timeSlot: c.timeSlot,
      scanType: c.scanType,
      priority: c.priority,
      refDoctor: c.refDoctor,
      symptoms: c.symptoms,
      images: c.images,
      doctorNotes: c.doctorNotes,
      prescription: c.prescription,
      radiologistNotes: c.radiologistNotes,
      doctorName: docMap.get(c.doctorUsername)?.name || null
    }));

    return res.json({ success: true, cases: out });
  } catch (err) {
    console.error("Patient cases error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- SOCKET.IO SERVER ----------
const httpServer = http.createServer(app);   // use http from above

io = new Server(httpServer, {
  cors: {
    origin: "*",
    credentials: false
  }
});

io.on("connection", (socket) => {
  console.log("🔥 User connected:", socket.id);

  socket.on("register", (data) => {
    console.log("User registered:", data);
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

// ---------- START SERVER ----------
httpServer.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Radiology backend running on http://10.137.53.11:${PORT}`);
});

