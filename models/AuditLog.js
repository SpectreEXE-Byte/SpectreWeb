const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
    event: { type: String, required: true }, // INITIALIZATION, HANDSHAKE, SHADOW_EVADE_BLOCK
    key: { type: String, required: true },
    username: { type: String, required: true },
    hwid: { type: String, required: true },
    status: { type: String, required: true }, // SUCCESS, INVALID, DENIED
    timestamp: { type: Date, default: Date.now }
});

logSchema.index({ timestamp: -1, event: 1 });

module.exports = mongoose.model('AuditLog', logSchema);