require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;

// 1. GLOBAL INITIALIZATION PIPELINE
app.use(express.json());
app.use(cors());

// 2. STABLE DATABASE MAPPING LAYER
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('>>> Spectre Matrix Engine Connected to MongoDB Atlas Cluster.'))
    .catch(err => console.error('!!! Database Connection Fault Vector:', err));

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

keySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const Key = mongoose.model('Key', keySchema);

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

// 3. EXPLICIT API ROUTE BOUNDARIES
app.post('/api/verify', async (req, res) => {
    const { key, username, hwid, executor } = req.body;
    if (!key) return res.status(400).json({ success: false, message: "Missing license validation key." });

    try {
        const targetKey = await Key.findOne({ key });
        if (!targetKey) return res.status(404).json({ success: false, message: "Token unrecognized." });
        if (targetKey.isBlacklisted) return res.status(403).json({ success: false, message: `ACCESS REVOKED: ${targetKey.blacklistReason}` });

        if (!targetKey.assignedUser && !targetKey.assignedHWID) {
            targetKey.assignedUser = username;
            targetKey.assignedHWID = hwid;
            targetKey.assignedExecutor = executor;
            await targetKey.save();

            await AuditLog.create({ event: "INITIALIZATION", key, username, hwid, executor, status: "SUCCESS" });
            await dispatchSecurityAlert("LICENSE KEY ACTIVATED & LOCKED", `**Token:** \`${key}\`\n**Claimed By:** \`${username}\``, 5177087);
            return res.status(200).json({ success: true, message: "Hardware mapping registered cleanly." });
        }

        let infractions = [];
        if (targetKey.assignedUser !== username) infractions.push(`User Mismatch`);
        if (targetKey.assignedHWID !== hwid) infractions.push("HWID Mismatch");

        if (infractions.length > 0) {
            const compositeReason = infractions.join(" | ");
            targetKey.isBlacklisted = true;
            targetKey.blacklistReason = `Identity Hijack: ${compositeReason}`;
            await targetKey.save();

            await AuditLog.create({ event: "BLACKLIST_AUTO", key, username, hwid, executor, status: "TERMINATED" });
            return res.status(403).json({ success: false, message: "HARDWARE LOCK BREACH ERROR." });
        }

        await AuditLog.create({ event: "HANDSHAKE", key, username, hwid, executor, status: "PASS" });
        return res.status(200).json({ success: true, message: "Verification clear." });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Crash error internal." });
    }
});

app.get('/api/admin/metrics', async (req, res) => {
    try {
        const totalKeys = await Key.countDocuments();
        const activeKeys = await Key.countDocuments({ isBlacklisted: false });
        const blacklistedKeys = await Key.countDocuments({ isBlacklisted: true });
        const recentLogs = await AuditLog.find().sort({ timestamp: -1 }).limit(10);
        const keysList = await Key.find().sort({ createdAt: -1 });

        return res.status(200).json({ totalKeys, activeKeys, blacklistedKeys, recentLogs, keysList });
    } catch (err) {
        return res.status(500).json({ success: false, error: "Metrics database pipeline failure." });
    }
});

app.post('/api/admin/keys/create', async (req, res) => {
    try {
        const { customKey, durationHours } = req.body;
        const hours = Number(durationHours || 24);
        const generatedKey = customKey || "SPECTRE-" + Math.random().toString(36).substring(2, 10).toUpperCase();
        const expirationTime = new Date(Date.now() + (hours * 60 * 60 * 1000));

        const newKey = await Key.create({ key: generatedKey, expiresAt: expirationTime });
        return res.status(200).json({ success: true, key: newKey });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/keys/blacklist', async (req, res) => {
    try {
        const { key, reason } = req.body;
        const target = await Key.findOneAndUpdate({ key }, { isBlacklisted: true, blacklistReason: reason || "Manual Operation" }, { new: true });
        if (!target) return res.status(404).json({ success: false, error: "Key missing." });
        return res.status(200).json({ success: true, message: "Token flagged." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// 4. STATIC ASSET DEPLOYMENT (Strictly at the bottom)
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => console.log(`>>> Spectre Core Base Online on Port ${PORT}`));