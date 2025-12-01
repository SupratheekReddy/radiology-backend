const mongoose = require("mongoose");

const caseSchema = new mongoose.Schema(
  {
    caseId: { type: String, required: true, unique: true }, // e.g., "CASE-17123456789"
    patientUsername: { type: String, required: true },
    doctorUsername: { type: String, required: true },
    date: { type: String, required: true },        // yyyy-mm-dd
    timeSlot: { type: String, required: true },    // e.g. "09:00-10:00"
    scanType: { type: String, required: true },    // CT, MRI, X-Ray, etc.
    priority: { type: String, enum: ["Critical", "Medium", "Safe"], default: "Medium" },
    symptoms: { type: String },
    refDoctor: { type: String },
    images: [{ type: String }],                   // filenames in /uploads
    doctorNotes: { type: String },
    prescription: { type: String },
    radiologistNotes: { type: String }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Case", caseSchema);
