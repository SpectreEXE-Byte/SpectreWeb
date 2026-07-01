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
    expiresAt: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now }
});

// Structural compound optimization indexes
keySchema.index({ assignedUserId: 1, isBlacklisted: 1 });
keySchema.index({ key: 1 }, { unique: true });

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
    if (!userId || userId === "0" || userId === "—" || userId === "UNBOUND") {
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
        // PROTECTION SHIELD: Verify if identity elements match active blacklists
        const shadowMatch = await ShadowBlacklist.findOne({
            $or: [{ robloxUserId: String(robloxUserId) }, { hwid: hwid }]
        });

        if (shadowMatch) {
            // Automatically burn clean key token they attempted to use
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

        if (new Date() > targetKey.expiresAt) {
             return res.status(403).json({ success: false, message: "Licensing temporal frame expired." });
        }

        // ACCOUNT SYNC: Update profile metadata history structures
        await UserProfile.findOneAndUpdate(
            { robloxUserId: String(robloxUserId) },
            { username, lastSeenHWID: hwid, lastSeenExecutor: executor, updatedAt: new Date() },
            { upsert: true, new: true }
        );

        // CONDITIONAL ASSIGNMENT: Bind unused clean key tokens automatically upon first link
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

        // COMPLIANCE POLICING ENFORCEMENT CONSTRAINTS
        let infractions = [];
        if (targetKey.assignedUserId !== String(robloxUserId)) infractions.push(`User account mismatch (${targetKey.assignedUser} vs ${username})`);
        if (targetKey.assignedHWID !== hwid) infractions.push("Hardware variance token split");

        if (infractions.length > 0) {
            const reason = infractions.join(" | ");
            targetKey.isBlacklisted = true;
            targetKey.blacklistReason = `Automated Security Lockdown: ${reason}`;
            await targetKey.save();

            // Establish shadow-ban signature locks across the platform database arrays
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

// Fetch collective dashboard metrics and extended keys roster data views
app.get('/api/admin/metrics', async (req, res) => {
    try {
        const keys = await Key.find().sort({ createdAt: -1 }).lean();
        const profiles = await UserProfile.find().lean();
        const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(18).lean();

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

// Create new access tokens
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

// Save persistent metadata/notes tracking content parameters against active profiles
app.post('/api/admin/profile/notes', async (req, res) => {
    try {
        const { robloxUserId, notes } = req.body;
        await UserProfile.findOneAndUpdate(
            { robloxUserId: String(robloxUserId) },
            { adminNotes: notes },
            { upsert: true }
        );
        return res.status(200).json({ success: true, message: "Account note synchronized." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// Revoke token and append signature structures directly to structural blacklists
app.post('/api/admin/keys/blacklist', async (req, res) => {
    try {
        const { key, reason } = req.body;
        const target = await Key.findOneAndUpdate({ key }, { isBlacklisted: true, blacklistReason: reason });
        if (!target) return res.status(404).json({ success: false, error: "License key untracked." });

        if (target.assignedUserId) {
            await ShadowBlacklist.findOneAndUpdate(
                { robloxUserId: target.assignedUserId },
                { robloxUserId: target.assignedUserId, hwid: target.assignedHWID || "MANUAL_BAN", reason: reason || "Manual System Administrator Action Overrule" },
                { upsert: true }
            );
            await AuditLog.create({
                event: "MANUAL_BAN",
                key: key,
                username: target.assignedUser || `UID: ${target.assignedUserId}`,
                hwid: target.assignedHWID || "N/A",
                status: "ENFORCED"
            });
        }
        return res.status(200).json({ success: true, message: "Token suspended and profiles shadow locked." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// Clear token ban histories and drop corresponding signature restrictions
app.post('/api/admin/keys/restore', async (req, res) => {
    try {
        const { key } = req.body;
        const target = await Key.findOne({ key });
        if (!target) return res.status(404).json({ success: false, error: "Key not found." });

        if (target.assignedUserId) {
            await ShadowBlacklist.deleteOne({ robloxUserId: target.assignedUserId });
        }

        await Key.findOneAndUpdate({ key }, { 
            isBlacklisted: false, 
            blacklistReason: "", 
            assignedUser: "", 
            assignedUserId: "", 
            assignedHWID: "", 
            assignedExecutor: "", 
            activatedAt: null 
        });

        return res.status(200).json({ success: true, message: "Token configuration footprint cleansed." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// Pull down comprehensive inventory containing every registered shadow-ban allocation
app.get('/api/admin/blacklist/all', async (req, res) => {
    try {
        const bannedProfiles = await ShadowBlacklist.find().sort({ flaggedAt: -1 }).lean();
        return res.status(200).json({ success: true, blacklist: bannedProfiles });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// Delete individual target hardware identities from blacklists (Lift Ban)
app.delete('/api/admin/blacklist/remove/:id', async (req, res) => {
    try {
        const targetId = req.params.id;
        const result = await ShadowBlacklist.deleteOne({ robloxUserId: String(targetId) });
        
        if (result.deletedCount === 0) {
            return res.status(404).json({ success: false, error: "Profile trace record mismatch." });
        }

        await AuditLog.create({ 
            event: "GLOBAL_UNBAN", 
            key: "SYSTEM", 
            username: `UID: ${targetId}`, 
            hwid: "RESTORATION", 
            status: "CLEARED" 
        });

        await dispatchSecurityAlert("GLOBAL FOOTPRINT RESTORED", `**Roblox User Identifier:** \`${targetId}\` has been removed from system enforcement arrays.`, 65280);

        return res.status(200).json({ success: true, message: "Enforcement parameters purged successfully." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// Housekeeping utility endpoints
app.post('/api/admin/keys/purge-expired', async (req, res) => {
    try {
        const output = await Key.deleteMany({ expiresAt: { $lt: new Date() } });
        return res.status(200).json({ success: true, message: `Purged ${output.deletedCount} old expired keys.` });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/logs/clear', async (req, res) => {
    try {
        await AuditLog.deleteMany({});
        return res.status(200).json({ success: true, message: "Audit logs streams cleared." });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

// Serve frontend layout interface
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => console.log(`>>> Spectre Network Engine online and listening on port ${PORT}`));