require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;

app.use(express.json());
app.use(cors());

// DATABASE CONNECTION HOOK
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('>>> Spectre Core Framework Engine Active.'))
    .catch(err => console.error('!!! Cluster Connection Error:', err));

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
                title: `🛡️ SPECTRE HUB // ${title}`,
                description: description,
                color: color,
                timestamp: new Date(),
                footer: { text: "TELEMETRY OVERFLOW CONTROL" }
            }]
        });
    } catch (err) {
        console.error("Webhook Fault:", err.message);
    }
}

// CLIENT GATEWAY VERIFICATION CHANNEL
app.post('/api/verify', async (req, res) => {
    const { key, username, hwid, executor } = req.body;
    if (!key) return res.status(400).json({ success: false, message: "License authorization validation token missing." });

    try {
        const targetKey = await Key.findOne({ key });
        if (!targetKey) return res.status(404).json({ success: false, message: "License record untracked in main matrix." });
        if (targetKey.isBlacklisted) return res.status(403).json({ success: false, message: `SUSPENDED: ${targetKey.blacklistReason}` });

        if (!targetKey.assignedUser && !targetKey.assignedHWID) {
            targetKey.assignedUser = username;
            targetKey.assignedHWID = hwid;
            targetKey.assignedExecutor = executor;
            await targetKey.save();

            await AuditLog.create({ event: "INITIALIZATION", key, username, hwid, executor, status: "SUCCESS" });
            await dispatchSecurityAlert("IDENTITY BOUND", `**Token:** \`${key}\`\n**User:** \`${username}\`\n**HWID:** \`${hwid}\``, 5177087);
            return res.status(200).json({ success: true, message: "Hardware boundary lock applied successfully." });
        }

        let infractions = [];
        if (targetKey.assignedUser !== username) infractions.push(`User Change Attack Vector`);
        if (targetKey.assignedHWID !== hwid) infractions.push("HWID Mismatch Signature");

        if (infractions.length > 0) {
            const reason = infractions.join(" | ");
            targetKey.isBlacklisted = true;
            targetKey.blacklistReason = `Automated Lockdown Vector: ${reason}`;
            await targetKey.save();

            await AuditLog.create({ event: "BLACKLIST_AUTO", key, username, hwid, executor, status: "TERMINATED" });
            await dispatchSecurityAlert("AUTOMATED SYSTEM TAMPER LOCKDOWN", `**Token Blacklisted:** \`${key}\`\n**User:** \`${username}\`\n**Breach Check:** ${reason}`, 16711680);
            return res.status(403).json({ success: false, message: "HARDWARE ACCOUNT TAMPER DETECTED. CHANNELS RECONCILED TERMINATED." });
        }

        await AuditLog.create({ event: "HANDSHAKE", key, username, hwid, executor, status: "PASS" });
        return res.status(200).json({ success: true, message: "Handshake clear." });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Verification subsystem pipeline anomaly." });
    }
});

// CORE MANAGEMENT & METRICS ENDPOINTS
app.get('/api/admin/metrics', async (req, res) => {
    try {
        const totalKeys = await Key.countDocuments();
        const activeKeys = await Key.countDocuments({ isBlacklisted: false });
        const blacklistedKeys = await Key.countDocuments({ isBlacklisted: true });
        const recentLogs = await AuditLog.find().sort({ timestamp: -1 }).limit(18);
        const keysList = await Key.find().sort({ createdAt: -1 });

        return res.status(200).json({ totalKeys, activeKeys, blacklistedKeys, recentLogs, keysList });
    } catch (err) {
        return res.status(500).json({ success: false, error: "Database mapping aggregation fault." });
    }
});

app.post('/api/admin/keys/create', async (req, res) => {
    try {
        const { customKey, durationHours } = req.body;
        const hours = Number(durationHours || 24);
        const generatedKey = customKey ? customKey.toUpperCase() : "SPECTRE-" + Math.random().toString(36).substring(2, 10).toUpperCase() + "-" + Math.random().toString(36).substring(2, 6).toUpperCase();
        const expirationTime = new Date(Date.now() + (hours * 60 * 60 * 1000));

        const newKey = await Key.create({ key: generatedKey, expiresAt: expirationTime });
        await dispatchSecurityAlert("TOKEN ALLOCATION GENERATED", `**Key:** \`${generatedKey}\`\n**Duration Status:** ${hours} Hours`, 10027263);
        return res.status(200).json({ success: true, key: newKey });
    } catch (err) {
        return res.status(500).json({ success: false, error: "Allocation engine failure." });
    }
});

app.post('/api/admin/keys/blacklist', async (req, res) => {
    try {
        const { key, reason } = req.body;
        const target = await Key.findOneAndUpdate({ key }, { isBlacklisted: true, blacklistReason: reason || "Manual Administrator Revocation Check" }, { new: true });
        if (!target) return res.status(404).json({ success: false, error: "Key query target untracked." });
        await dispatchSecurityAlert("ADMIN REVOCATION OVERRIDE ENFORCED", `**Key:** \`${key}\`\n**Reason Context:** ${reason}`, 16738320);
        return res.status(200).json({ success: true, message: "Hardware scope suspended." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// ADVANCED COMPLIANCE DIRECTIVES (NEW EXTENSIONS)
app.post('/api/admin/keys/restore', async (req, res) => {
    try {
        const { key } = req.body;
        const target = await Key.findOneAndUpdate({ key }, { isBlacklisted: false, blacklistReason: "", assignedUser: "", assignedHWID: "", assignedExecutor: "" }, { new: true });
        if (!target) return res.status(404).json({ success: false, error: "Target license not found." });
        await dispatchSecurityAlert("TOKEN COMPLIANCE RESTORED / RESET", `**Key:** \`${key}\`\n*Hardware mapping profiles have been decoupled.*`, 5177087);
        return res.status(200).json({ success: true, message: "Token execution bounds reset smoothly." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/keys/purge-expired', async (req, res) => {
    try {
        const now = new Date();
        const output = await Key.deleteMany({ expiresAt: { $lt: now } });
        return res.status(200).json({ success: true, message: `Purged ${output.deletedCount} old expired tokens.` });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/logs/clear', async (req, res) => {
    try {
        await AuditLog.deleteMany({});require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;

app.use(express.json());
app.use(cors());

// DATABASE CONNECTION HOOK
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('>>> Spectre Core Framework Engine Active.'))
    .catch(err => console.error('!!! Cluster Connection Error:', err));

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
                title: `🛡️ SPECTRE HUB // ${title}`,
                description: description,
                color: color,
                timestamp: new Date(),
                footer: { text: "TELEMETRY OVERFLOW CONTROL" }
            }]
        });
    } catch (err) {
        console.error("Webhook Fault:", err.message);
    }
}

// CLIENT GATEWAY VERIFICATION CHANNEL
app.post('/api/verify', async (req, res) => {
    const { key, username, hwid, executor } = req.body;
    if (!key) return res.status(400).json({ success: false, message: "License authorization validation token missing." });

    try {
        const targetKey = await Key.findOne({ key });
        if (!targetKey) return res.status(404).json({ success: false, message: "License record untracked in main matrix." });
        if (targetKey.isBlacklisted) return res.status(403).json({ success: false, message: `SUSPENDED: ${targetKey.blacklistReason}` });

        if (!targetKey.assignedUser && !targetKey.assignedHWID) {
            targetKey.assignedUser = username;
            targetKey.assignedHWID = hwid;
            targetKey.assignedExecutor = executor;
            await targetKey.save();

            await AuditLog.create({ event: "INITIALIZATION", key, username, hwid, executor, status: "SUCCESS" });
            await dispatchSecurityAlert("IDENTITY BOUND", `**Token:** \`${key}\`\n**User:** \`${username}\`\n**HWID:** \`${hwid}\``, 5177087);
            return res.status(200).json({ success: true, message: "Hardware boundary lock applied successfully." });
        }

        let infractions = [];
        if (targetKey.assignedUser !== username) infractions.push(`User Change Attack Vector`);
        if (targetKey.assignedHWID !== hwid) infractions.push("HWID Mismatch Signature");

        if (infractions.length > 0) {
            const reason = infractions.join(" | ");
            targetKey.isBlacklisted = true;
            targetKey.blacklistReason = `Automated Lockdown Vector: ${reason}`;
            await targetKey.save();

            await AuditLog.create({ event: "BLACKLIST_AUTO", key, username, hwid, executor, status: "TERMINATED" });
            await dispatchSecurityAlert("AUTOMATED SYSTEM TAMPER LOCKDOWN", `**Token Blacklisted:** \`${key}\`\n**User:** \`${username}\`\n**Breach Check:** ${reason}`, 16711680);
            return res.status(403).json({ success: false, message: "HARDWARE ACCOUNT TAMPER DETECTED. CHANNELS RECONCILED TERMINATED." });
        }

        await AuditLog.create({ event: "HANDSHAKE", key, username, hwid, executor, status: "PASS" });
        return res.status(200).json({ success: true, message: "Handshake clear." });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Verification subsystem pipeline anomaly." });
    }
});

// CORE MANAGEMENT & METRICS ENDPOINTS
app.get('/api/admin/metrics', async (req, res) => {
    try {
        const totalKeys = await Key.countDocuments();
        const activeKeys = await Key.countDocuments({ isBlacklisted: false });
        const blacklistedKeys = await Key.countDocuments({ isBlacklisted: true });
        const recentLogs = await AuditLog.find().sort({ timestamp: -1 }).limit(18);
        const keysList = await Key.find().sort({ createdAt: -1 });

        return res.status(200).json({ totalKeys, activeKeys, blacklistedKeys, recentLogs, keysList });
    } catch (err) {
        return res.status(500).json({ success: false, error: "Database mapping aggregation fault." });
    }
});

app.post('/api/admin/keys/create', async (req, res) => {
    try {
        const { customKey, durationHours } = req.body;
        const hours = Number(durationHours || 24);
        const generatedKey = customKey ? customKey.toUpperCase() : "SPECTRE-" + Math.random().toString(36).substring(2, 10).toUpperCase() + "-" + Math.random().toString(36).substring(2, 6).toUpperCase();
        const expirationTime = new Date(Date.now() + (hours * 60 * 60 * 1000));

        const newKey = await Key.create({ key: generatedKey, expiresAt: expirationTime });
        await dispatchSecurityAlert("TOKEN ALLOCATION GENERATED", `**Key:** \`${generatedKey}\`\n**Duration Status:** ${hours} Hours`, 10027263);
        return res.status(200).json({ success: true, key: newKey });
    } catch (err) {
        return res.status(500).json({ success: false, error: "Allocation engine failure." });
    }
});

app.post('/api/admin/keys/blacklist', async (req, res) => {
    try {
        const { key, reason } = req.body;
        const target = await Key.findOneAndUpdate({ key }, { isBlacklisted: true, blacklistReason: reason || "Manual Administrator Revocation Check" }, { new: true });
        if (!target) return res.status(404).json({ success: false, error: "Key query target untracked." });
        await dispatchSecurityAlert("ADMIN REVOCATION OVERRIDE ENFORCED", `**Key:** \`${key}\`\n**Reason Context:** ${reason}`, 16738320);
        return res.status(200).json({ success: true, message: "Hardware scope suspended." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/keys/restore', async (req, res) => {
    try {
        const { key } = req.body;
        const target = await Key.findOneAndUpdate({ key }, { isBlacklisted: false, blacklistReason: "", assignedUser: "", assignedHWID: "", assignedExecutor: "" }, { new: true });
        if (!target) return res.status(404).json({ success: false, error: "Target license not found." });
        await dispatchSecurityAlert("TOKEN COMPLIANCE RESTORED / RESET", `**Key:** \`${key}\`\n*Hardware mapping profiles have been decoupled.*`, 5177087);
        return res.status(200).json({ success: true, message: "Token execution bounds reset smoothly." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/keys/purge-expired', async (req, res) => {
    try {
        const now = new Date();
        const output = await Key.deleteMany({ expiresAt: { $lt: now } });
        return res.status(200).json({ success: true, message: `Purged ${output.deletedCount} old expired tokens.` });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/logs/clear', async (req, res) => {
    try {
        await AuditLog.deleteMany({});
        return res.status(200).json({ success: true, message: "Log telemetry buffer cleared." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// STATIC RESOURCE HOSTING
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => console.log(`>>> Spectre Framework Processing Node Running Online on Port ${PORT}`));
        return res.status(200).json({ success: true, message: "Log telemetry buffer cleared." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// STATIC RESOURCE HOSTING
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => console.log(`>>> Spectre Framework Processing Node Running Online on Port ${PORT}`));