const mongoose = require('mongoose');

const userProfileSchema = new mongoose.Schema({
    robloxUserId: { type: String, required: true, unique: true },
    username: { type: String, required: true },
    lastHwid: { type: String },
    hwidHistory: [{ type: String }],
    adminNotes: { type: String, default: "" },
    updatedAt: { type: Date, default: Date.now }
});

userProfileSchema.index({ username: "text", robloxUserId: "text" });

module.exports = mongoose.model('UserProfile', userProfileSchema);