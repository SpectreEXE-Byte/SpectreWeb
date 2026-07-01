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

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('>>> Spectre Advanced Profile & Enforcement Matrix Connected.'))
    .catch(err => console.error('!!! Database Connection Fault:', err));

// ============================================================================
// DATA LAYOUT DATA SCHEMAS
// ============================================================================
const keySchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    isBlacklisted: { type: Boolean, default: false },
    blacklistReason: { type: String, default: "" },
    assignedUser: { type: String, default: "" },
    assignedUserId: { type: String, default: "" }, // Roblox Target Identifier
    assignedHWID: { type: String, default: "" },
    assignedExecutor: { type: String, default: "" },
    activatedAt: { type: Date },
    expiresAt: { type: Date, required: true }
});
keySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const Key = mongoose.model('Key', keySchema);

const userProfileSchema = new mongoose.Schema({
    username: { type: String, required: true },
    robloxUserId: { type: String, required: true, unique: true },
    adminNotes: { type: String, default: "" },
    lastSeenHWID: { type: String, default: "" },
    lastSeenExecutor: { type: String, default: "" },
    updatedAt: { type: Date, default: Date.now }
});
const UserProfile = mongoose.model('UserProfile', userProfileSchema);

const shadowBlacklistSchema = new mongoose.Schema({
    robloxUserId: { type: String, required: true, unique: true },
    hwid: { type: String, required: true },
    reason: { type: String, default: "Evulsion Control Isolation Trigger" },
    flaggedAt: { type: Date, default: Date.now }
});
const ShadowBlacklist = mongoose.model('ShadowBlacklist', shadowBlacklistSchema);

const logSchema = new mongoose.Schema({
    event: String,
    key: String,
    username: String,
    hwid: String,
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
                description,
                color,
                timestamp: new Date(),
                footer: { text: "ENFORCEMENT LAYER" }
            }]
        });
    } catch (err) {
        console.error("Webhook Fault:", err.message);
    }
}

// Helper function resolving stable fallback avatars via Roblox content deliver web endpoints
function fetchRobloxAvatarUrl(userId) {
    if (!userId || userId === "0" || userId === "—") return "https://www.roblox.com/headshot-thumbnail/image?userId=1&width=150&height=150&format=png";
    return `https://www.roblox.com/headshot-thumbnail/image?userId=${userId}&width=150&height=150&format=png`;
}

// ============================================================================
// CLIENT GATEWAY VERIFICATION CHANNEL WITH SHADOW AUTO-LOCK
// ============================================================================
app.post('/api/verify', async (req, res) => {
    const { key, username, robloxUserId, hwid, executor } = req.body;
    if (!key || !robloxUserId) return res.status(400).json({ success: false, message: "Required payload markers absent." });

    try {
        // SECURITY SHIELD: Check shadow block registry for evasion attempts
        const shadowMatch = await ShadowBlacklist.findOne({
            $or: [{ robloxUserId: String(robloxUserId) }, { hwid: hwid }]
        });

        if (shadowMatch) {
            // Instantly destroy the clean key they attempted to burn
            await Key.findOneAndUpdate({ key }, { isBlacklisted: true, blacklistReason: `EVASION SHIELD: Profile tied to ban registry (${shadowMatch.reason})` });
            await AuditLog.create({ event: "SHADOW_EVADE", key, username, hwid, status: "SHUTDOWN" });
            await dispatchSecurityAlert("SHADOW BAN EVASION TERMINATED", `**User:** \`${username}\` (${robloxUserId})\n**Key Attempted:** \`${key}\` *(Burned)*\n**Reason:** Hardlocked identification footprint profile match.`, 16711680);
            return res.status(403).json({ success: false, message: "HARDWARE ACCESS SUSPENDED. TERMINATION CODES PERSISTENT." });
        }

        const targetKey = await Key.findOne({ key });
        if (!targetKey) return res.status(404).json({ success: false, message: "License record untracked." });
        if (targetKey.isBlacklisted) return res.status(403).json({ success: false, message: `SUSPENDED: ${targetKey.blacklistReason}` });

        // PERSISTENCE SYNC: Keep profile or record telemetry updated
        await UserProfile.findOneAndUpdate(
            { robloxUserId: String(robloxUserId) },
            { username, lastSeenHWID: hwid, lastSeenExecutor: executor, updatedAt: new Date() },
            { upsert: true, new: true }
        );

        // INITIAL KEY REGISTRATION BIND
        if (!targetKey.assignedUser && !targetKey.assignedHWID) {
            targetKey.assignedUser = username;
            targetKey.assignedUserId = String(robloxUserId);
            targetKey.assignedHWID = hwid;
            targetKey.assignedExecutor = executor;
            targetKey.activatedAt = new Date();
            await targetKey.save();

            await AuditLog.create({ event: "INITIALIZATION", key, username, hwid, status: "SUCCESS" });
            return res.status(200).json({ success: true, message: "License successfully registered and bound to profile." });
        }

        // TAMPER ENFORCEMENT RULES
        let infractions = [];
        if (targetKey.assignedUserId !== String(robloxUserId)) infractions.push(`Profile mismatch (${targetKey.assignedUser} vs ${username})`);
        if (targetKey.assignedHWID !== hwid) infractions.push("Hardware variance block");

        if (infractions.length > 0) {
            const reason = infractions.join(" | ");
            targetKey.isBlacklisted = true;
            targetKey.blacklistReason = `Automated Lockdown: ${reason}`;
            await targetKey.save();

            // Permanent lock: Lock down their user account and hardware signature across future allocations
            await ShadowBlacklist.findOneAndUpdate(
                { robloxUserId: String(robloxUserId) },
                { robloxUserId: String(robloxUserId), hwid, reason: `Compromised token signature usage: ${reason}` },
                { upsert: true }
            );

            await AuditLog.create({ event: "BLACKLIST_AUTO", key, username, hwid, status: "TERMINATED" });
            return res.status(403).json({ success: false, message: "TAMPER ATTACK HARDBOUND PIN DISCOVERED. ACCOUNT BLACKLISTED." });
        }

        await AuditLog.create({ event: "HANDSHAKE", key, username, hwid, status: "PASS" });
        return res.status(200).json({ success: true, message: "Handshake verified." });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Verification pipeline fault." });
    }
});

// ============================================================================
// ADMINISTRATION ADMINISTRATIVE INTERACTION DECK
// ============================================================================
app.get('/api/admin/metrics', async (req, res) => {
    try {
        const keys = await Key.find().sort({ createdAt: -1 }).lean();
        const profiles = await UserProfile.find().lean();
        const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(18).lean();

        // Stitch rich user metadata into the token list response stream
        const extendedKeysList = keys.map(k => {
            const profile = profiles.find(p => p.robloxUserId === k.assignedUserId);
            return {
                ...k,
                avatarUrl: fetchRobloxAvatarUrl(k.assignedUserId),
                adminNotes: profile ? profile.adminNotes : "",
                lastSeen: profile ? profile.updatedAt : null
            };
        });

        return res.status(200).json({
            totalKeys: keys.length,
            activeKeys: keys.filter(k => !k.isBlacklisted).length,
            blacklistedKeys: keys.filter(k => k.isBlacklisted).length,
            recentLogs: logs,
            keysList: extendedKeysList
        });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/keys/create', async (req, res) => {
    try {
        const { customKey, durationHours } = req.body;
        const hours = Number(durationHours || 24);
        const generatedKey = customKey ? customKey.toUpperCase() : "SPECTRE-" + Math.random().toString(36).substring(2, 10).toUpperCase();
        const expirationTime = new Date(Date.now() + (hours * 60 * 60 * 1000));

        const newKey = await Key.create({ key: generatedKey, expiresAt: expirationTime });
        return res.status(200).json({ success: true, key: newKey });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/profile/notes', async (req, res) => {
    try {
        const { robloxUserId, notes } = req.body;
        await UserProfile.findOneAndUpdate(
            { robloxUserId: String(robloxUserId) },
            { adminNotes: notes },
            { upsert: true }
        );
        return res.status(200).json({ success: true, message: "CRM administration account metadata update clear." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/keys/blacklist', async (req, res) => {
    try {
        const { key, reason } = req.body;
        const target = await Key.findOneAndUpdate({ key }, { isBlacklisted: true, blacklistReason: reason }, { new: true });
        if (!target) return res.status(404).json({ success: false, error: "Token not found." });

        if (target.assignedUserId) {
            await ShadowBlacklist.findOneAndUpdate(
                { robloxUserId: target.assignedUserId },
                { robloxUserId: target.assignedUserId, hwid: target.assignedHWID, reason: reason || "Manual System Admin Hard-ban" },
                { upsert: true }
            );
        }
        return res.status(200).json({ success: true, message: "Target token suspended and identity profiles shadow-locked." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/keys/restore', async (req, res) => {
    try {
        const { key } = req.body;
        const target = await Key.findOneAndUpdate({ key }, { isBlacklisted: false, blacklistReason: "", assignedUser: "", assignedUserId: "", assignedHWID: "", assignedExecutor: "", activatedAt: null }, { new: true });
        if (target && target.assignedUserId) {
            await ShadowBlacklist.deleteOne({ robloxUserId: target.assignedUserId });
        }
        return res.status(200).json({ success: true, message: "Token and profile footprint cleared from blacklists." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/keys/purge-expired', async (req, res) => {
    try {
        const output = await Key.deleteMany({ expiresAt: { $lt: new Date() } });
        return res.status(200).json({ success: true, message: `Purged ${output.deletedCount} old entries.` });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/logs/clear', async (req, res) => {
    try {
        await AuditLog.deleteMany({});
        return res.status(200).json({ success: true, message: "Cleared logs stream." });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.use(express.static(path.join(__dirname, 'public')));
app.listen(PORT, () => console.log(`>>> Server executing operations on port ${PORT}`));