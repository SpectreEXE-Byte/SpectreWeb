const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

// Force dotenv to find your configuration variables inside the absolute application container runtime directory
require('dotenv').config({ path: path.join(__dirname, '.env') });

const app = express();
const PORT = process.env.PORT || 3000;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;
const mongoURI = process.env.MONGO_URI;

app.use(express.json());
app.use(cors());

// Diagnostic configuration check before firing up the connection pipeline
if (!mongoURI) {
    console.error('\n!!! CRITICAL CONFIGURATION FAULT: process.env.MONGO_URI is entirely missing or undefined inside your runtime layout.');
} else {
    console.log('\n⏳ Initializing cluster secure authorization handshake pipeline...');
    
    // Connect securely to your persistent MongoDB infrastructure
    mongoose.connect(mongoURI)
        .then(() => console.log('\n>>> SUCCESS: Spectre Advanced Central Matrix Cluster Connected Smoothly.'))
        .catch(err => {
            console.error('\n!!! CRITICAL ERROR: Database Cluster Connection Failure Detected!');
            console.error('Explicit Node Driver Details Context:\n', err);
        });
}

// Active connection session monitoring listeners
mongoose.connection.on('error', err => console.error('!!! ACTIVE NETWORK LOOP ERROR:', err));
mongoose.connection.on('disconnected', () => console.warn('⚠️ WARNING: Matrix Data Cluster connection dropped from target system.'));

// ============================================================================
// DATABASE DATA SCHEMAS (MONGODB DATA STRUCTURES)
// ============================================================================

const keySchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    isBlacklisted: { type: Boolean, default: false },
    blacklistReason: { type: String, default: "" },
    assignedUser: { type: String, default: "" },
    assignedUserId: { type: String, default: "" }, // Roblox Target ID Record
    assignedHWID: { type: String, default: "" },
    assignedExecutor: { type: String, default: "" },
    activatedAt: { type: Date },
    expiresAt: { type: Date, required: true }
});
keySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // Automates pruning if needed
const Key = mongoose.model('Key', keySchema);

const hwidBanSchema = new mongoose.Schema({
    hwid: { type: String, required: true, unique: true },
    reason: { type: String, default: "Violation of usage security protocols." },
    bannedAt: { type: Date, default: Date.now }
});
const HWIDBan = mongoose.model('HWIDBan', hwidBanSchema);

const shadowBlacklistSchema = new mongoose.Schema({
    robloxUserId: { type: String, required: true, unique: true },
    robloxUsername: { type: String },
    reason: { type: String, default: "Security Enforcement Flagged." },
    flaggedAt: { type: Date, default: Date.now }
});
const ShadowBlacklist = mongoose.model('ShadowBlacklist', shadowBlacklistSchema);

const auditLogSchema = new mongoose.Schema({
    key: { type: String },
    robloxUser: { type: String },
    robloxUserId: { type: String },
    executor: { type: String },
    action: { type: String, required: true },
    status: { type: String, required: true },
    details: { type: String },
    timestamp: { type: Date, default: Date.now }
});
const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// Helper function to securely dispatch telemetry payloads over Discord pipelines
async function sendDiscordWebhook(title, description, color = 0x00FF00, fields = []) {
    if (!DISCORD_WEBHOOK_URL) return;
    try {
        await axios.post(DISCORD_WEBHOOK_URL, {
            embeds: [{
                title: title,
                description: description,
                color: color,
                fields: fields,
                footer: { text: "Spectre Matrix Intelligence Engine v43.0" },
                timestamp: new Date()
            }]
        });
    } catch (err) {
        console.error("Failed to forward telemetry context bundle to Webhook pipeline:", err.message);
    }
}

// Helper to calculate expiration matrices
function getExpirationDate(durationStr) {
    const amount = parseInt(durationStr);
    const unit = durationStr.replace(/[0-9]/g, '').trim().toLowerCase();
    const now = new Date();

    if (unit === 'm' || unit === 'min' || unit === 'minute' || unit === 'minutes') return new Date(now.getTime() + amount * 60000);
    if (unit === 'h' || unit === 'hr' || unit === 'hour' || unit === 'hours') return new Date(now.getTime() + amount * 3600000);
    if (unit === 'd' || unit === 'day' || unit === 'days') return new Date(now.getTime() + amount * 86400000);
    if (unit === 'w' || unit === 'week' || unit === 'weeks') return new Date(now.getTime() + amount * 7 * 86400000);
    
    return new Date(now.getTime() + 86400000); // Standard fallback parameters (24 Hours)
}

// ============================================================================
// ENDPOINT INFRASTRUCTURE & ROUTING MANAGEMENT
// ============================================================================

app.post('/api/keys/validate', async (req, res) => {
    const { key, hwid, robloxUser, robloxUserId, executor } = req.body;

    if (!key || !hwid) {
        return res.status(400).json({ success: false, message: "Missing essential validation handshake components." });
    }

    try {
        const isBanned = await HWIDBan.findOne({ hwid: String(hwid) });
        if (isBanned) {
            await new AuditLog({ key, robloxUser, robloxUserId, executor, action: "VALIDATION_ATTEMPT", status: "BLOCKED", details: `Hardware Blacklist Encountered. Reason: ${isBanned.reason}` }).save();
            return res.status(403).json({ success: false, message: `Access Denied: This workstation hardware hash has been banned. Reason: ${isBanned.reason}` });
        }

        if (robloxUserId) {
            const isShadowed = await ShadowBlacklist.findOne({ robloxUserId: String(robloxUserId) });
            if (isShadowed) {
                await new AuditLog({ key, robloxUser, robloxUserId, executor, action: "VALIDATION_ATTEMPT", status: "SHADOW_BLOCKED", details: "Profile tracking parameters activated." }).save();
                return res.status(403).json({ success: false, message: "Access Denied: Operational clearance has been administrative revoked." });
            }
        }

        const keyData = await Key.findOne({ key: String(key) });
        if (!keyData) {
            return res.status(404).json({ success: false, message: "The cryptographic authorization sequence provided is invalid." });
        }

        if (keyData.isBlacklisted) {
            return res.status(403).json({ success: false, message: `Access Revoked: Key blacklisted. Reason: ${keyData.blacklistReason}` });
        }

        const currentTime = new Date();
        if (currentTime > keyData.expiresAt) {
            return res.status(403).json({ success: false, message: "Access Expired: This allocation cycle has already terminated." });
        }

        if (!keyData.assignedHWID) {
            keyData.assignedHWID = String(hwid);
            keyData.assignedUser = robloxUser || "Unknown Native";
            keyData.assignedUserId = robloxUserId ? String(robloxUserId) : "0";
            keyData.assignedExecutor = executor || "Generic Shell";
            keyData.activatedAt = currentTime;
            await keyData.save();

            await new AuditLog({ key, robloxUser, robloxUserId, executor, action: "KEY_ACTIVATION", status: "SUCCESS", details: `Successfully provisioned hardware locks to target workstation.` }).save();

            await sendDiscordWebhook("🔐 Operational Allocation Lock Set", `Cryptographic sequence successfully verified and localized down.`, 0x00FF00, [
                { name: "Key", value: `\`\`\`${key}\`\`\`` },
                { name: "User Identity", value: `${robloxUser} (${robloxUserId})`, inline: true },
                { name: "Executor Shell", value: executor || "N/A", inline: true },
                { name: "Hardware Reference (HWID)", value: `\`\`\`${hwid}\`\`\`` }
            ]);

            return res.status(200).json({ success: true, message: "Authorization parameters synchronized successfully.", expiresAt: keyData.expiresAt });
        }

        if (keyData.assignedHWID !== String(hwid)) {
            await new AuditLog({ key, robloxUser, robloxUserId, executor, action: "VALIDATION_ATTEMPT", status: "HARDWARE_MISMATCH", details: `Expected: ${keyData.assignedHWID} | Provided: ${hwid}` }).save();
            return res.status(403).json({ success: false, message: "Security Integrity Failure: Hardware blueprint configuration mismatch." });
        }

        return res.status(200).json({ success: true, message: "Clearance accepted.", expiresAt: keyData.expiresAt });

    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// ============================================================================
// ADMINISTRATIVE UTILITIES PANEL ROUTING
// ============================================================================

app.post('/api/admin/keys/generate', async (req, res) => {
    const { prefix, duration, notes } = req.body;
    if (!duration) return res.status(400).json({ success: false, error: "Allocation cycle metrics must be declared explicitly." });

    try {
        const generatedKey = `${prefix || 'NX'}-${Math.random().toString(36).substring(2, 10).toUpperCase()}-${Math.random().toString(36).substring(2, 10).toUpperCase()}`;
        const expirationTimestamp = getExpirationDate(duration);

        const newKeyEntry = new Key({
            key: generatedKey,
            expiresAt: expirationTimestamp
        });
        await newKeyEntry.save();

        return res.status(201).json({ success: true, key: generatedKey, expiresAt: expirationTimestamp });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.get('/api/admin/keys', async (req, res) => {
    try {
        const allKeys = await Key.find({}).lean();
        return res.status(200).json({ success: true, keys: allKeys });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/keys/delete/:id', async (req, res) => {
    try {
        const targetId = req.params.id;
        await Key.deleteOne({ _id: targetId });
        return res.status(200).json({ success: true, message: "Purge execution array complete." });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/keys/blacklist', async (req, res) => {
    const { key, reason } = req.body;
    try {
        const updated = await Key.findOneAndUpdate({ key: String(key) }, { isBlacklisted: true, blacklistReason: reason || "Unspecified policy violation." }, { new: true });
        if (!updated) return res.status(404).json({ success: false, message: "Target token array footprint missing." });
        return res.status(200).json({ success: true, message: "Token tracking state marked blacklisted." });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/bans/hwid', async (req, res) => {
    const { hwid, reason } = req.body;
    try {
        await new HWIDBan({ hwid: String(hwid), reason: reason || "Administrative Hardware Purge Action" }).save();
        return res.status(201).json({ success: true, message: "Workstation terminal parameters locked out successfully." });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/admin/bans/hwid', async (req, res) => {
    try {
        const structuralBans = await HWIDBan.find({}).lean();
        return res.status(200).json({ success: true, bans: structuralBans });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/bans/hwid/remove/:id', async (req, res) => {
    try {
        const targetId = req.params.id;
        await HWIDBan.deleteOne({ _id: targetId });
        return res.status(200).json({ success: true, message: "Hardware authorization parameters updated." });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/admin/logs', async (req, res) => {
    try {
        const traceLogs = await AuditLog.find({}).sort({ timestamp: -1 }).limit(150).lean();
        return res.status(200).json({ success: true, logs: traceLogs });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/blacklist/shadow', async (req, res) => {
    const { robloxUserId, robloxUsername, reason } = req.body;
    try {
        await new ShadowBlacklist({ robloxUserId: String(robloxUserId), robloxUsername, reason: reason || "Profile target flag set." }).save();
        return res.status(201).json({ success: true, message: "Profiles metrics targeted." });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/admin/blacklist/shadow', async (req, res) => {
    try {
        const bannedProfiles = await ShadowBlacklist.find().sort({ flaggedAt: -1 }).lean();
        return res.status(200).json({ success: true, blacklist: bannedProfiles });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/blacklist/remove/:id', async (req, res) => {
    try {
        const targetId = req.params.id;
        await ShadowBlacklist.deleteOne({ robloxUserId: String(targetId) });
        return res.status(200).json({ success: true, message: "Enforcement parameters purged successfully." });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/keys/purge-expired', async (req, res) => {
    try {
        await Key.deleteMany({ expiresAt: { $lt: new Date() } });
        return res.status(200).json({ success: true });
    } catch (err) { return res.status(500).json({ success: false }); }
});

app.post('/api/admin/logs/clear', async (req, res) => {
    try {
        await AuditLog.deleteMany({});
        return res.status(200).json({ success: true });
    } catch (err) { return res.status(500).json({ success: false }); }
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/trial-portal', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`🛰️  Spectre Core Matrix Engine initialized on port ${PORT}`);
    console.log(`=======================================================`);
});
