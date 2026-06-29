require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;

// ============================================================================
// 1. GLOBAL MIDDLEWARE
// ============================================================================
app.use(express.json());
app.use(cors());

// ============================================================================
// 2. DATABASE CONFIGURATION & CONNECTIVITY
// ============================================================================
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('>>> Spectre Matrix Engine Connected to MongoDB Atlas Cluster.'))
    .catch(err => console.error('!!! Database Connection Fault Vector:', err));

// Database Key Model Setup (Includes Hardware Locks & Auto-Expiring Indexes)
const keySchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    isBlacklisted: { type: Boolean, default: false },
    blacklistReason: { type: String, default: "" },
    assignedUser: { type: String, default: "" },
    assignedHWID: { type: String, default: "" },
    assignedExecutor: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true }
});

// Automated DB Engine Rule: Purge data document automatically when current time passes expiresAt
keySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const Key = mongoose.model('Key', keySchema);

// Security Log Stream Model
const logSchema = new mongoose.Schema({
    event: String,
    key: String,
    username: String,
    hwid: String,
    executor: String,
    status: String,
    timestamp: { type: Date, default: Date.now }
});
const AuditLog = mongoose.model('AuditLog', logSchema);

// Embedded Webhook Dispatch System
async function dispatchSecurityAlert(title, description, color = 10027263) {
    if (!DISCORD_WEBHOOK_URL) return;
    try {
        await axios.post(DISCORD_WEBHOOK_URL, {
            embeds: [{
                title: `🛡️ SPECTRE SECURITY HUB // ${title}`,
                description: description,
                color: color,
                timestamp: new Date(),
                footer: { text: "SPECTRE TELEMETRY CORE v2.0" }
            }]
        });
    } catch (err) {
        console.error("Webhook Dispatch Failure:", err.message);
    }
}

// ============================================================================
// 3. CORE TELEMETRY GATEWAY ROUTE (Called by Roblox Clients)
// ============================================================================
app.post('/api/verify', async (req, res) => {
    const { key, username, hwid, executor } = req.body;

    if (!key) return res.status(400).json({ success: false, message: "Missing license validation key." });

    try {
        const targetKey = await Key.findOne({ key });

        if (!targetKey) {
            return res.status(404).json({ success: false, message: "Token unrecognized in global cluster." });
        }

        if (targetKey.isBlacklisted) {
            return res.status(403).json({ success: false, message: `ACCESS REVOKED: ${targetKey.blacklistReason}` });
        }

        // --- FIRST TIME ACTIVATION BOUNDARY LOCKING ---
        if (!targetKey.assignedUser && !targetKey.assignedHWID) {
            targetKey.assignedUser = username;
            targetKey.assignedHWID = hwid;
            targetKey.assignedExecutor = executor;
            await targetKey.save();

            await AuditLog.create({ event: "INITIALIZATION", key, username, hwid, executor, status: "SUCCESS" });
            await dispatchSecurityAlert(
                "LICENSE KEY ACTIVATED & LOCKED",
                `**Token:** \`${key}\`\n**Claimed By:** \`${username}\`\n**Machine HWID:** \`${hwid}\`\n**Client Layer:** ${executor}`,
                5177087
            );

            return res.status(200).json({ success: true, message: "Hardware mapping registered cleanly." });
        }

        // --- ENFORCED RE-AUTHENTICATION & SECURITY POLICIES ---
        let infractions = [];
        if (targetKey.assignedUser !== username) infractions.push(`User Mismatch (Bound: ${targetKey.assignedUser}, Claiming: ${username})`);
        if (targetKey.assignedHWID !== hwid) infractions.push("Hardware Profile Spoof Verification Failure");

        if (infractions.length > 0) {
            const compositeReason = infractions.join(" | ");
            targetKey.isBlacklisted = true;
            targetKey.blacklistReason = `Identity Hijack Attempt: ${compositeReason}`;
            await targetKey.save();

            await AuditLog.create({ event: "BLACKLIST_AUTO", key, username, hwid, executor, status: "TERMINATED" });
            await dispatchSecurityAlert(
                "CRITICAL SECURITY COMPLIANCE VIOLATION",
                `**Token Suspended:** \`${key}\`\n**Violator Username:** \`${username}\`\n**Violator HWID:** \`${hwid}\`\n**Breach Vectors:** ${compositeReason}`,
                16711680
            );

            return res.status(403).json({ success: false, message: "HARDWARE LOCK BREACH ERROR. ACCOUNT PERMANENTLY SUSPENDED." });
        }

        // Successful Verification Pass
        await AuditLog.create({ event: "HANDSHAKE", key, username, hwid, executor, status: "PASS" });
        return res.status(200).json({ success: true, message: "Verification clear." });

    } catch (err) {
        return res.status(500).json({ success: false, message: "Internal verification processing crash." });
    }
});

// ============================================================================
// 4. CENTRAL DASHBOARD API CONTROL LAYERS
// ============================================================================
app.get('/api/admin/metrics', async (req, res) => {
    try {
        const totalKeys = await Key.countDocuments();
        const activeKeys = await Key.countDocuments({ isBlacklisted: false });
        const blacklistedKeys = await Key.countDocuments({ isBlacklisted: true });
        const recentLogs = await AuditLog.find().sort({ timestamp: -1 }).limit(10);
        const keysList = await Key.find().sort({ createdAt: -1 });

        res.json({ totalKeys, activeKeys, blacklistedKeys, recentLogs, keysList });
    } catch (err) {
        res.status(500).json({ error: "Metrics pipeline failure." });
    }
});

app.post('/api/admin/keys/create', async (req, res) => {
    const { customKey, durationHours } = req.body;
    try {
        const generatedKey = customKey || "SPECTRE-" + Math.random().toString(36).substring(2, 10).toUpperCase() + "-" + Math.random().toString(36).substring(2, 6).toUpperCase();
        const expirationTime = new Date(Date.now() + (Number(durationHours || 24) * 60 * 60 * 1000));

        const newKey = await Key.create({ key: generatedKey, expiresAt: expirationTime });
        await dispatchSecurityAlert("NEW SYSTEM KEY GENERATED", `**Key Token:** \`${generatedKey}\`\n**Lifespan Allocation:** ${durationHours} Hour(s)\n**Expires On:** ${expirationTime.toUTCString()}`, 10027263);
        res.json({ success: true, key: newKey });
    } catch (err) {
        res.status(500).json({ success: false, error: "Token minting allocation failure." });
    }
});

app.post('/api/admin/keys/blacklist', async (req, res) => {
    const { key, reason } = req.body;
    try {
        const target = await Key.findOneAndUpdate({ key }, { isBlacklisted: true, blacklistReason: reason || "Manual Administrator Revocation" }, { new: true });
        if (!target) return res.status(404).json({ success: false, message: "Target token key not discovered." });
        await dispatchSecurityAlert("MANUAL OPERATOR BLOCK ENFORCED", `**Target Token:** \`${key}\`\n**Operator Reason:** ${reason}`, 16738320);
        res.json({ success: true, message: "Token flagged and blocked." });
    } catch (err) {
        res.status(500).json({ success: false, error: "Blacklist command modification error." });
    }
});

// ============================================================================
// 5. STATIC ASSET HOSTING & ROUTE FALLBACKS
// ============================================================================
// This must remain below the API endpoints to stop it from intercepting API calls
app.use(express.static(path.join(__dirname, 'public')));

// Fallback catch-all to route to the dashboard interface home page if an unmapped URL is hit
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================================
// 6. ENGINE STARTUP
// ============================================================================
app.listen(PORT, () => console.log(`>>> Spectre Framework Processing Node Running Online on Port ${PORT}`));