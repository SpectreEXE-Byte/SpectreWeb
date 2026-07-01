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
    assignedUserId: { type: String, default: "" }, 
    assignedHWID: { type: String, default: "" },
    assignedExecutor: { type: String, default: "" },
    activatedAt: { type: Date },
    expiresAt: { type: Date, required: true }
});
keySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); 
const Key = mongoose.model('Key', keySchema);

const auditLogSchema = new mongoose.Schema({
    event: { type: String, required: true },
    key: { type: String, required: true },
    username: { type: String, required: true },
    hwid: { type: String, required: true },
    status: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});
const AuditLog = mongoose.model('AuditLog', auditLogSchema);

const shadowBlacklistSchema = new mongoose.Schema({
    robloxUserId: { type: String, required: true, unique: true },
    reason: { type: String, default: "Enforcement Lockout" },
    flaggedAt: { type: Date, default: Date.now }
});
const ShadowBlacklist = mongoose.model('ShadowBlacklist', shadowBlacklistSchema);

// Tracks unique Discord IDs that have claimed a evaluation token
const trialClaimTrackerSchema = new mongoose.Schema({
    discordId: { type: String, required: true, unique: true },
    discordTag: { type: String, required: true },
    claimedAt: { type: Date, default: Date.now }
});
const TrialClaim = mongoose.model('TrialClaim', trialClaimTrackerSchema);

// ============================================================================
// CORE SYSTEMS HELPER ROUTINES
// ============================================================================

async function dispatchSecurityAlert(title, message, colorCode) {
    if (!DISCORD_WEBHOOK_URL) return;
    try {
        await axios.post(DISCORD_WEBHOOK_URL, {
            embeds: [{
                title: title,
                description: message,
                color: colorCode || 16711680,
                timestamp: new Date()
            }]
        });
    } catch (e) {
        console.error("Transmission error sending alert payload channel:", e.message);
    }
}

// ============================================================================
// OFFICIAL DISCORD OAUTH2 AUTHENTICATION CONTROLLER ENDPOINTS
// ============================================================================

// Route 1: Trigger login redirect sequence
app.get('/api/auth/login', (req, res) => {
    const redirectUrl = `https://discord.com/api/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.DISCORD_REDIRECT_URI)}&response_type=code&scope=identify`;
    res.redirect(redirectUrl);
});

// Route 2: Intercept token validation feedback channel from Discord authorization
app.get('/api/auth/callback', async (req, res) => {
    const code = req.query.code;
    if (!code) return res.send("<h3>OAuth verification handshake cancelled by developer application parameters.</h3>");

    try {
        // Exchange grant code for dynamic token access sequence
        const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
            client_id: process.env.DISCORD_CLIENT_ID,
            client_secret: process.env.DISCORD_CLIENT_SECRET,
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: process.env.DISCORD_REDIRECT_URI,
        }), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const accessToken = tokenResponse.data.access_token;

        // Query the Discord API securely for profile account properties
        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });

        const { id, username, discriminator } = userResponse.data;
        const completeTag = discriminator !== "0" ? `${username}#${discriminator}` : username;

        // Redirect user safely back to the user interface panel passing unique identifier queries
        res.redirect(`/trial-portal?uid=${id}&tag=${encodeURIComponent(completeTag)}`);
    } catch (err) {
        console.error("OAuth Exchange Telemetry Exception:", err.response ? err.response.data : err.message);
        res.status(500).send("<h3>OAuth Handshake Security Verification Token Integrity Broken. Try again later.</h3>");
    }
});

// Route 3: Validates structural requirements and generates a unique evaluation key
app.post('/api/trial/claim', async (req, res) => {
    const { discordId, discordTag } = req.body;

    if (!discordId || !discordTag) {
        return res.status(400).json({ success: false, message: "Missing required identification metadata." });
    }

    try {
        // Check if this explicit account identifier already claimed a license key token
        const alreadyClaimed = await TrialClaim.findOne({ discordId: String(discordId) });
        if (alreadyClaimed) {
            return res.status(403).json({ success: false, message: "ACCOUNT EXPIRED. LIMIT 1 EVALUATION KEY." });
        }

        // Setup unique evaluation validation array token parameters 
        const tokenSequence = `SPECTRE-TRIAL-${require('crypto').randomBytes(6).toString('hex').toUpperCase()}`;
        const activeSpanLimit = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)); // Exactly 7 Days Out

        // Write live evaluation pass key parameters inside central Roblox mapping array
        await Key.create({
            key: tokenSequence,
            expiresAt: activeSpanLimit,
            blacklistReason: "Evaluation Node Bound Only"
        });

        // Set restriction mapping flag blocking repeated generations
        await TrialClaim.create({
            discordId: String(discordId),
            discordTag: discordTag
        });

        // Broadcast analytical pipeline updates out to central operations log channel
        await AuditLog.create({
            event: "TRIAL_GEN",
            key: tokenSequence,
            username: discordTag,
            hwid: `DISCORD_ID: ${discordId}`,
            status: "REGISTERED"
        });

        await dispatchSecurityAlert("🔮 TRIAL ACCESS GENERATED", `**Operator Handle:** \`${discordTag}\`\n**Identity Record:** \`${discordId}\`\n**Assigned Key Ring:** \`${tokenSequence}\``, 9133302);

        return res.status(200).json({ success: true, key: tokenSequence });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// ============================================================================
// CORE TELEMETRY VALIDATION ENGINE (ROBLOX EXECUTION INBOUND LINKS)
// ============================================================================

app.post('/api/verify', async (req, res) => {
    try {
        const { key, executor, username, robloxUserId, hwid } = req.body;

        if (!key || !username || !robloxUserId || !hwid) {
            return res.status(400).json({ success: false, message: "MALFORMED REQUEST DATA FIELD PAYLOAD SCHEMA." });
        }

        const enforcementMatch = await ShadowBlacklist.findOne({ robloxUserId: String(robloxUserId) });
        if (enforcementMatch) {
            return res.status(403).json({ success: false, message: `ACCOUNT IS BLACKLISTED: ${enforcementMatch.reason}` });
        }

        const matchToken = await Key.findOne({ key: key });
        if (!matchToken) {
            return res.status(404).json({ success: false, message: "INVALID ACCESS KEY SPECIFIED." });
        }

        if (matchToken.isBlacklisted) {
            return res.status(403).json({ success: false, message: `KEY TERMINATED: ${matchToken.blacklistReason}` });
        }

        if (matchToken.expiresAt && new Date() > matchToken.expiresAt) {
            return res.status(403).json({ success: false, message: "LICENSE VALUE EXPIRED IN THE WEB CLOUD ENGINE." });
        }

        if (matchToken.assignedHWID !== "" && matchToken.assignedHWID !== hwid) {
            await Key.updateOne({ key: key }, { isBlacklisted: true, blacklistReason: "Automated Hardware Fingerprint Mismatch Mux Lock" });
            await AuditLog.create({ event: "HWID_LOCKOUT", key, username, hwid, status: "TERMINATED" });
            await dispatchSecurityAlert("🚨 MALICIOUS HARDWARE SHIFT LOCK", `**User:** \`${username}\`\n**Key:** \`${key}\`\n*Key permanently voided due to unexpected profile drift.*`);
            return res.status(403).json({ success: false, message: "HARDWARE ACCOUNT DRIFT ENFORCEMENT HIT." });
        }

        if (matchToken.assignedHWID === "") {
            matchToken.assignedHWID = hwid;
            matchToken.assignedUser = username;
            matchToken.assignedUserId = String(robloxUserId);
            matchToken.assignedExecutor = executor || "Unknown";
            matchToken.activatedAt = new Date();
            await matchToken.save();
        }

        await AuditLog.create({ event: "SUCCESS_AUTH", key, username, hwid, status: "VERIFIED" });
        return res.status(200).json({ success: true, message: "ACCESS HANDSHAKE COMPLETE VERIFIED." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// ============================================================================
// ADMINISTRATIVE METRICS DATA MANAGEMENT OVERRIDE API ENDPOINTS
// ============================================================================

app.get('/api/admin/metrics', async (req, res) => {
    try {
        const globalKeys = await Key.find().lean();
        const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(40).lean();
        const totalKeysCount = await Key.countDocuments();
        const activeBansCount = await ShadowBlacklist.countDocuments();
        const trialRegistrationsCount = await TrialClaim.countDocuments();

        return res.status(200).json({
            success: true,
            totalKeys: totalKeysCount,
            activeBans: activeBansCount,
            trialsIssued: trialRegistrationsCount,
            keysList: globalKeys,
            activityLogs: logs
        });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/keys/generate', async (req, res) => {
    try {
        const { days } = req.body;
        const generatedKeyString = `SPECTRE-PREM-${require('crypto').randomBytes(8).toString('hex').toUpperCase()}`;
        const durationWindow = new Date(Date.now() + (days * 24 * 60 * 60 * 1000));

        const newlyCreatedKey = await Key.create({ key: generatedKeyString, expiresAt: durationWindow });
        return res.status(201).json({ success: true, data: newlyCreatedKey });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/keys/blacklist', async (req, res) => {
    try {
        const { key, reason } = req.body;
        await Key.updateOne({ key: key }, { isBlacklisted: true, blacklistReason: reason || "Manual System Admin Enforcement Action Override" });
        return res.status(200).json({ success: true });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/keys/restore', async (req, res) => {
    try {
        const { key } = req.body;
        await Key.updateOne({ key: key }, { isBlacklisted: false, blacklistReason: "", assignedHWID: "" });
        return res.status(200).json({ success: true });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/blacklist/add', async (req, res) => {
    try {
        const { robloxUserId, reason } = req.body;
        await ShadowBlacklist.updateOne({ robloxUserId: String(robloxUserId) }, { reason: reason || "Manual Exclusion" }, { upsert: true });
        return res.status(200).json({ success: true });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/blacklist/remove/:id', async (req, res) => {
    try {
        const targetId = req.params.id;
        await ShadowBlacklist.deleteOne({ robloxUserId: String(targetId) });
        return res.status(200).json({ success: true });
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

// Serve Static Front-End routing directories mappings cleanly
app.use(express.static(path.join(__dirname, 'public')));

app.get('/trial-portal', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'trial.html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`>>> Spectre Backend Distribution Grid operational via routing port: ${PORT}`));