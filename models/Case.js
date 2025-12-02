const mongoose = require("mongoose");

const caseSchema = new mongoose.Schema(
  {
    // ============================================
    // 1. RELATIONAL FIELDS (Required for .populate to work)
    // ============================================
    patient: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: "User", // This links to the Account/User model
      required: false 
    },
    doctor: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: "User", 
      required: false 
    },
    technician: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: "User", 
      required: false 
    },

    // ============================================
    // 2. DATA FIELDS
    // ============================================
    caseId: { type: String, required: true, unique: true },
    
    // We keep these strings as backups, but the ObjectIds above are the main links
    patientUsername: { type: String, required: false },
    doctorUsername: { type: String, required: false },

    date: { type: String, required: true },
    timeSlot: { type: String, required: true },
    scanType: { type: String, required: true },
    priority: { type: String, enum: ["Critical", "Medium", "Safe"], default: "Medium" },
    
    symptoms: { type: String },
    refDoctor: { type: String },
    
    // Workflow Status
    status: { type: String, default: "Pending" }, // Pending -> Scanned -> Diagnosed

    // ============================================
    // 3. RESULTS & REPORTS
    // ============================================
    images: [{ type: String }], // Cloudinary URLs
    radiologistNotes: { type: String }, // AI Report stores here
    doctorNotes: { type: String },
    diagnosis: { type: String },
    severity: { type: String },
    prescription: { type: String }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Case", caseSchema);