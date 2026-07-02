const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = 3000;

// ============================================================================
// HARDCODED SECURE INITIALIZATION PARAMETERS (Bypasses Electron .env issues)
// ============================================================================
const MONGO_URI = "mongodb+srv://Spectre:Morlol93$@cluster0.fcnlgtq.mongodb.net/?appName=Cluster0"; 
const DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1521844457115357304/eaNaiXv6ZLXhdRHSmIvXRIqQkR44fE2fSwRo-SIBHpVNStzq-fGS5Xf9TlZtxicbQiGq";

app.use(express.json());
app.use(cors());

// Diagnostic setup checker
if (MONGO_URI === "YOUR_MONGO_URI_HERE" || !MONGO_URI) {
    console.error('\n!!! CONFIGURATION ERROR: Please paste your real connection string directly into the MONGO_URI variable inside server.js.');
} else {
    console.log('\n⏳ Initializing cluster secure authorization handshake pipeline...');
    mongoose.connect(MONGO_URI)
        .then(() => console.log('\n>>> SUCCESS: Spectre Advanced Central Matrix Cluster Connected Smoothly.'))
        .catch(err => {
            console.error('\n!!! CRITICAL ERROR: Database Cluster Connection Failure Detected!');
            console.error(err);
        });
}

// ============================================================================
// DATABASE DATA SCHEMAS
// ============================================================================
const keySchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    isBlacklisted: { type: Boolean, default: false },
    blacklistReason: { type: String, default: "" },
    assignedUser: { type: String, default: "" },
    assignedUserId: { type: String, default: "" }, 
    assignedHWID: { type: String, default: "" },
    assignedExecutor: { type: String, default: "" },
    activatedAt: { type: Date },
    expiresAt: { type: Date, required: true }
});
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

// Webhook Dispatcher
async function sendDiscordWebhook(title, description, color = 0x00FF00, fields = []) {
    if (!DISCORD_WEBHOOK_URL || DISCORD_WEBHOOK_URL.includes("YOUR_DISCORD")) return;
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

// ============================================================================
// CORE ENDPOINTS & ROADWAYS (All administrative routes deleted)
// ============================================================================

// The active validation link your Lua script checks
app.post('/api/keys/validate', async (req, res) => {
    const { key, hwid, robloxUser, robloxUserId, executor } = req.body;

    if (!key || !hwid) {
        return res.status(400).json({ success: false, message: "Missing essential validation handshake components." });
    }

    try {
        const isBanned = await HWIDBan.findOne({ hwid: String(hwid) });
        if (isBanned) {
            await new AuditLog({ key, robloxUser, robloxUserId, executor, action: "VALIDATION_ATTEMPT", status: "BLOCKED", details: `Hardware Blacklist Encountered. Reason: ${isBanned.reason}` }).save();
            return res.status(403).json({ success: false, message: `Access Denied: This workstation hardware hash has been banned.` });
        }

        if (robloxUserId) {
            const isShadowed = await ShadowBlacklist.findOne({ robloxUserId: String(robloxUserId) });
            if (isShadowed) {
                return res.status(403).json({ success: false, message: "Access Denied: Operational clearance has been administrative revoked." });
            }
        }

        const keyData = await Key.findOne({ key: String(key) });
        if (!keyData) {
            return res.status(404).json({ success: false, message: "The cryptographic authorization sequence provided is invalid." });
        }

        if (keyData.isBlacklisted) {
            return res.status(403).json({ success: false, message: `Access Revoked: Key blacklisted.` });
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

            await new AuditLog({ key, robloxUser, robloxUserId, executor, action: "KEY_ACTIVATION", status: "SUCCESS" }).save();

            await sendDiscordWebhook("🔐 Operational Allocation Lock Set", `Cryptographic sequence successfully verified and localized down.`, 0x00FF00, [
                { name: "Key", value: `\`\`\`${key}\`\`\`` },
                { name: "User Identity", value: `${robloxUser} (${robloxUserId})`, inline: true },
                { name: "Hardware Reference (HWID)", value: `\`\`\`${hwid}\`\`\`` }
            ]);

            return res.status(200).json({ success: true, message: "Authorization parameters synchronized successfully.", expiresAt: keyData.expiresAt });
        }

        if (keyData.assignedHWID !== String(hwid)) {
            return res.status(403).json({ success: false, message: "Security Integrity Failure: Hardware blueprint configuration mismatch." });
        }

        return res.status(200).json({ success: true, message: "Clearance accepted.", expiresAt: keyData.expiresAt });

    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// ============================================================================
// PUBLIC VISUAL PORTALS
// ============================================================================
app.use(express.static(path.join(__dirname, 'public')));

// KEEP THE DISCORD TRIAL PAGE ALIVE HERE
app.get('/trial-portal', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`🛰️  Spectre Core Matrix Engine initialized on port ${PORT}`);
    console.log(`=======================================================`);
});
