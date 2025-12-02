const mongoose = require("mongoose");

const accountSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // In production, hash this!
  
  role: { 
    type: String, 
    enum: ["admin", "doctor", "patient", "technician", "radiologist"], 
    required: true 
  },
  
  // Specific to patients
  basePriority: { type: String, enum: ["Critical", "Medium", "Safe"], default: "Safe" }
});

// IMPORTANT: This name "User" must match the 'ref' in Case.js
module.exports = mongoose.model("User", accountSchema);