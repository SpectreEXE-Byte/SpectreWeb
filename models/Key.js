const mongoose = require('mongoose');

const keySchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    isBlacklisted: { type: Boolean, default: false },
    blacklistReason: { type: String, default: "" },
    assignedUser: { type: String, default: "" },
    assignedUserId: { type: String, default: "" }, 
    assignedHWID: { type: String, default: "" },
    assignedExecutor: { type: String, default: "" },
    activatedAt: { type: Date },
    expiresAt: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now }
});

// Compound optimized search arrays
keySchema.index({ assignedUserId: 1, isBlacklisted: 1 });
keySchema.index({ key: 1 }, { unique: true });

module.exports = mongoose.model('Key', keySchema);