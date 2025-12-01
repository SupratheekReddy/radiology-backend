const mongoose = require("mongoose");

const accountSchema = new mongoose.Schema(
  {
    role: {
      type: String,
      enum: ["admin", "doctor", "technician", "radiologist", "patient"],
      required: true
    },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }, // hashed
    name: { type: String },
    email: { type: String },
    basePriority: { type: String, enum: ["Critical", "Medium", "Safe"], default: "Medium" }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Account", accountSchema);
