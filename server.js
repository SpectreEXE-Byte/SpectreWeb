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

// Connect securely to your persistent MongoDB infrastructure
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('>>> Spectre Advanced Central Matrix Cluster Connected.'))
    .catch(err => console.error('!!! Database Cluster Connection Failure:', err));

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

// ============================================================================
// SYSTEM UTILITIES / HELPER CHANNELS
// ============================================================================

async function dispatchSecurityAlert(title, description, color = 10027263) {
    if (!DISCORD_WEBHOOK_URL) return;
    try {
        await axios.post(DISCORD_WEBHOOK_URL, {
            embeds: [{
                title: `🛡️ SPECTRE HUB // ${title}`,
                description,
                color,
                timestamp: new Date(),
                footer: { text: "SPECTRE ENFORCEMENT ENGINE" }
            }]
        });
    } catch (err) {
        console.error("Discord Webhook Forwarding Fault:", err.message);
    }
}

function fetchRobloxAvatarUrl(userId) {
    if (!userId || userId === "0" || userId === "—") {
        return "https://www.roblox.com/headshot-thumbnail/image?userId=1&width=150&height=150&format=png";
    }
    return `https://www.roblox.com/headshot-thumbnail/image?userId=${userId}&width=150&height=150&format=png`;
}

// ============================================================================
// CLIENT ENDPOINT GATEWAY: RUNTIME TELEMETRY VERIFICATION OVERSEE
// ============================================================================

app.post('/api/verify', async (req, res) => {
    const { key, username, robloxUserId, hwid, executor } = req.body;
    if (!key || !robloxUserId) {
        return res.status(400).json({ success: false, message: "Required payload markers absent." });
    }

    try {
        const shadowMatch = await ShadowBlacklist.findOne({
            $or: [{ robloxUserId: String(robloxUserId) }, { hwid: hwid }]
        });

        if (shadowMatch) {
            await Key.findOneAndUpdate({ key }, { 
                isBlacklisted: true, 
                blacklistReason: `SHADOW EXCLUSION CODES TRIGGERED: Tied to ban register (${shadowMatch.reason})` 
            });
            await AuditLog.create({ event: "SHADOW_EVADE_BLOCK", key, username, hwid, status: "SHUTDOWN" });
            
            await dispatchSecurityAlert("SHADOW BAN EVASION TERMINATED", 
                `**User:** \`${username}\` (${robloxUserId})\n**Key Attempted:** \`${key}\` *(Burned)*\n**Reason:** Hardlocked user identity profile footprint match.`, 16711680);
            
            return res.status(403).json({ success: false, message: "HARDWARE ACCESS SUSPENDED. TERMINATION CODES PERSISTENT." });
        }

        const targetKey = await Key.findOne({ key });
        if (!targetKey) return res.status(404).json({ success: false, message: "License record untracked." });
        if (targetKey.isBlacklisted) return res.status(403).json({ success: false, message: `SUSPENDED: ${targetKey.blacklistReason}` });

        await UserProfile.findOneAndUpdate(
            { robloxUserId: String(robloxUserId) },
            { username, lastSeenHWID: hwid, lastSeenExecutor: executor, updatedAt: new Date() },
            { upsert: true, new: true }
        );

        if (!targetKey.assignedUser && !targetKey.assignedHWID) {
            targetKey.assignedUser = username;
            targetKey.assignedUserId = String(robloxUserId);
            targetKey.assignedHWID = hwid;
            targetKey.assignedExecutor = executor;
            targetKey.activatedAt = new Date();
            await targetKey.save();

            await AuditLog.create({ event: "INITIALIZATION", key, username, hwid, status: "SUCCESS" });
            return res.status(200).json({ success: true, message: "License successfully registered." });
        }

        let infractions = [];
        if (targetKey.assignedUserId !== String(robloxUserId)) infractions.push(`User account mismatch (${targetKey.assignedUser} vs ${username})`);
        if (targetKey.assignedHWID !== hwid) infractions.push("Hardware variance token split");

        if (infractions.length > 0) {
            const reason = infractions.join(" | ");
            targetKey.isBlacklisted = true;
            targetKey.blacklistReason = `Automated Security Lockdown: ${reason}`;
            await targetKey.save();

            await ShadowBlacklist.findOneAndUpdate(
                { robloxUserId: String(robloxUserId) },
                { robloxUserId: String(robloxUserId), hwid, reason: `Compromised footprint context usage: ${reason}` },
                { upsert: true }
            );

            await AuditLog.create({ event: "BLACKLIST_AUTO", key, username, hwid, status: "TERMINATED" });
            return res.status(403).json({ success: false, message: "TAMPER ATTACK HARDBOUND PIN DISCOVERED. ACCOUNT BLACKLISTED." });
        }

        await AuditLog.create({ event: "HANDSHAKE", key, username, hwid, status: "PASS" });
        return res.status(200).json({ success: true, message: "Handshake verified." });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Verification pipeline cluster fault." });
    }
});

// ============================================================================
// ADMINISTRATION CONTROL INTERACTION CHANNELS
// ============================================================================

app.get('/api/admin/metrics', async (req, res) => {
    try {
        const keys = await Key.find().sort({ createdAt: -1 }).lean();
        const profiles = await UserProfile.find().lean();
        const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(100).lean();

        const extendedKeysList = keys.map(k => {
            const profile = profiles.find(p => p.robloxUserId === k.assignedUserId);
            return {
                ...k,
                avatarUrl: fetchRobloxAvatarUrl(k.assignedUserId),
                adminNotes: profile ? profile.adminNotes : "",
                lastSeen: profile ? profile.updatedAt : null
            };
        });

        // Generate distribution rates over time dynamically for Analytics Chart
        const hourlyTimeline = {};
        logs.forEach(l => {
            if(l.timestamp) {
                const hourMarker = new Date(l.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                hourlyTimeline[hourMarker] = (hourlyTimeline[hourMarker] || 0) + 1;
            }
        });

        return res.status(200).json({
            totalKeys: keys.length,
            activeKeys: keys.filter(k => !k.isBlacklisted).length,
            blacklistedKeys: keys.filter(k => k.isBlacklisted).length,
            recentLogs: logs.slice(0, 20),
            keysList: extendedKeysList,
            chartTimeline: Object.keys(hourlyTimeline).slice(-7),
            chartData: Object.values(hourlyTimeline).slice(-7)
        });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// PROFILE DEEP DIVE: Fetch all details, metrics, logs, historical context, and bans on profile focus
app.get('/api/admin/profile/deep-dive/:robloxUserId', async (req, res) => {
    try {
        const targetId = String(req.params.robloxUserId);

        const [profile, activeKeys, shadowBan] = await Promise.all([
            UserProfile.findOne({ robloxUserId: targetId }).lean(),
            Key.find({ assignedUserId: targetId }).sort({ expiresAt: -1 }).lean(),
            ShadowBlacklist.findOne({ robloxUserId: targetId }).lean()
        ]);

        const associatedKeyStrings = activeKeys.map(k => k.key);
        const logSearchConditions = [{ key: { $in: associatedKeyStrings } }];
        if (profile && profile.username) {
            logSearchConditions.push({ username: profile.username });
        }

        const comprehensiveLogs = await AuditLog.find({ $or: logSearchConditions })
            .sort({ timestamp: -1 })
            .lean();

        const statistics = {
            totalHandshakes: comprehensiveLogs.filter(l => l.event === "HANDSHAKE" && l.status === "PASS").length,
            totalInitializations: comprehensiveLogs.filter(l => l.event === "INITIALIZATION").length,
            totalInfractions: comprehensiveLogs.filter(l => l.event === "BLACKLIST_AUTO" || l.event === "SHADOW_EVADE_BLOCK").length
        };

        return res.status(200).json({
            success: true,
            data: {
                identity: profile || { robloxUserId: targetId, username: "Unknown / Unsaved" },
                avatarUrl: fetchRobloxAvatarUrl(targetId),
                banStatus: shadowBan ? { active: true, reason: shadowBan.reason, flaggedAt: shadowBan.flaggedAt } : { active: false },
                associatedKeys: activeKeys,
                activityLogs: comprehensiveLogs,
                statistics
            }
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
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/profile/notes', async (req, res) => {
    try {
        const { robloxUserId, notes } = req.body;
        await UserProfile.findOneAndUpdate({ robloxUserId: String(robloxUserId) }, { adminNotes: notes }, { upsert: true });
        return res.status(200).json({ success: true, message: "Account note synchronized." });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/keys/blacklist', async (req, res) => {
    try {
        const { key, reason } = req.body;
        const target = await Key.findOneAndUpdate({ key }, { isBlacklisted: true, blacklistReason: reason }, { new: true });
        if (!target) return res.status(404).json({ success: false, error: "License key untracked." });

        if (target.assignedUserId) {
            await ShadowBlacklist.findOneAndUpdate(
                { robloxUserId: target.assignedUserId },
                { robloxUserId: target.assignedUserId, hwid: target.assignedHWID || "MANUAL_BAN", reason: reason || "Manual System Administrator Action Overrule" },
                { upsert: true }
            );
        }
        return res.status(200).json({ success: true, message: "Token suspended." });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/keys/restore', async (req, res) => {
    try {
        const { key } = req.body;
        const target = await Key.findOneAndUpdate({ key }, { 
            isBlacklisted: false, blacklistReason: "", assignedUser: "", assignedUserId: "", assignedHWID: "", assignedExecutor: "", activatedAt: null 
        }, { new: true });

        if (target && target.assignedUserId) {
            await ShadowBlacklist.deleteOne({ robloxUserId: target.assignedUserId });
        }
        return res.status(200).json({ success: true, message: "Token configuration footprint cleansed." });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/admin/blacklist/all', async (req, res) => {
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
app.listen(PORT, () => console.log(`>>> Spectre Network Engine online on port ${PORT}`));