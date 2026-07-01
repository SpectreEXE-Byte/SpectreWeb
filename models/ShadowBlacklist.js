const mongoose = require('mongoose');

const shadowBlacklistSchema = new mongoose.Schema({
    robloxUserId: { type: String, required: true, unique: true },
    hwid: { type: String, required: true },
    reason: { type: String, default: "Enforced Cluster Evasion Containment" },
    flaggedAt: { type: Date, default: Date.now }
});

shadowBlacklistSchema.index({ robloxUserId: 1, hwid: 1 });

module.exports = mongoose.model('ShadowBlacklist', shadowBlacklistSchema);