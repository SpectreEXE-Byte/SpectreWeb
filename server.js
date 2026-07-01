require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { rateLimit } = require('express-rate-limit');
const { createClient } = require('redis');

// Models
const Key = require('./models/Key');
const UserProfile = require('./models/UserProfile');
const ShadowBlacklist = require('./models/ShadowBlacklist');
const AuditLog = require('./models/AuditLog');
const AdminUser = require('./models/AdminUser');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "SPECTRE_SUPER_SECRET_CORE_VECTOR";
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Helper: Discord Alerts
async function dispatchSecurityAlert(title, description, color = 16711680) {
    if (!DISCORD_WEBHOOK_URL) return;
    try {
        await axios.post(DISCORD_WEBHOOK_URL, {
            embeds: [{
                title: title,
                description: description,
                color: color,
                timestamp: new Date()
            }]
        });
    } catch (err) {
        console.error("Discord Webhook Pipeline Error:", err.message);
    }
}

// ============================================================================
// INFRASTRUCTURE INITIALIZATION (REDIS & MONGO)
// ============================================================================
const redisClient = createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
redisClient.on('error', err => console.error('Redis Cache Pipeline Error:', err));
(async () => { await redisClient.connect().catch(() => console.log("⚠️ Redis offline, falling back to database.")); })();

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('>>> Spectre V3 Cluster Connected.'))
    .catch(err => console.error('!!! Database Failure:', err));

// ============================================================================
// MIDDLEWARE CONFIGURATIONS
// ============================================================================

// Global Rate Limiter
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    limit: 100,
    message: { success: false, message: "Too many requests to telemetry arrays." }
});
app.use('/api/', apiLimiter);

// JWT Role Verification Engine
const authorize = (roles = []) => {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: "Missing authorization token." });
        }
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
            if (roles.length && !roles.includes(decoded.role)) {
                return res.status(403).json({ success: false, message: "Access forbidden: insufficient clearance." });
            }
            next();
        } catch (err) {
            return res.status(401).json({ success: false, message: "Invalid or expired session token." });
        }
    };
};

// ============================================================================
// SECURITY & AUTHENTICATION ENDPOINTS
// ============================================================================

app.post('/api/auth/register-master', async (req, res) => {
    const { username, password, setupKey } = req.body;
    if (setupKey !== process.env.SETUP_KEY) return res.status(403).json({ message: "Invalid setup token key." });
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await AdminUser.create({ username, password: hashedPassword, role: 'owner' });
    res.status(200).json({ success: true, message: "Master account initialized.", user: { username: user.username, role: user.role } });
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await AdminUser.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ success: false, message: "Invalid credentials." });
    }
    const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.status(200).json({ success: true, token, user: { username: user.username, role: user.role } });
});

// ============================================================================
// SYSTEM HEALTH MONITORING
// ============================================================================
app.get('/api/health', async (req, res) => {
    const dbStatus = mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected';
    const redisStatus = redisClient.isOpen ? 'Active' : 'Offline';
    
    const start = Date.now();
    await mongoose.connection.db.admin().ping();
    const dbLatency = Date.now() - start;

    res.status(200).json({
        status: "Healthy",
        timestamp: new Date(),
        uptime: process.uptime(),
        services: { database: dbStatus, cache: redisStatus },
        performance: { dbPingMs: dbLatency },
        memory: process.memoryUsage()
    });
});

// ============================================================================
// HIGH PERFORMANCE CACHED ADMIN METRICS & ANALYTICS APIs
// ============================================================================
app.get('/api/admin/metrics', authorize(['owner', 'admin', 'moderator']), async (req, res) => {
    try {
        if (redisClient.isOpen) {
            const cachedMetrics = await redisClient.get('spectre_metrics');
            if (cachedMetrics) return res.status(200).json(JSON.parse(cachedMetrics));
        }

        const keys = await Key.find().sort({ createdAt: -1 }).lean();
        const profiles = await UserProfile.find().lean();
        const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(30).lean();
        const blacklistCount = await ShadowBlacklist.countDocuments();

        const extendedKeysList = keys.map(k => {
            const profile = profiles.find(p => p.robloxUserId === k.assignedUserId);
            return {
                ...k,
                avatarUrl: `https://www.roblox.com/headshot-thumbnail/image?userId=${k.assignedUserId || 1}&width=150&height=150&format=png`,
                adminNotes: profile ? profile.adminNotes : ""
            };
        });

        const dataPayload = {
            totalKeys: keys.length,
            activeKeys: keys.filter(k => !k.isBlacklisted).length,
            blacklistedKeys: keys.filter(k => k.isBlacklisted).length,
            hwidBlocks: blacklistCount,
            recentLogs: logs,
            keysList: extendedKeysList
        };

        if (redisClient.isOpen) {
            await redisClient.set('spectre_metrics', JSON.stringify(dataPayload), { EX: 5 }); // Cache for 5 seconds
        }

        return res.status(200).json(dataPayload);
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// Advanced Query Pipeline: Paginated Search and Advanced Filtering
app.get('/api/admin/logs/search', authorize(['owner', 'admin', 'moderator']), async (req, res) => {
    const { term, event, page = 1, limit = 15 } = req.query;
    let queryConditions = {};

    if (term) {
        queryConditions.$or = [
            { username: { $regex: term, $options: 'i' } },
            { key: { $regex: term, $options: 'i' } },
            { hwid: { $regex: term, $options: 'i' } }
        ];
    }
    if (event) queryConditions.event = event;

    const logs = await AuditLog.find(queryConditions)
        .sort({ timestamp: -1 })
        .skip((page - 1) * limit)
        .limit(Number(limit))
        .lean();

    const totalMatches = await AuditLog.countDocuments(queryConditions);

    res.status(200).json({ logs, totalMatches, pages: Math.ceil(totalMatches / limit) });
});

// Profile Deep Dive 
app.get('/api/admin/profile/deep-dive/:robloxUserId', authorize(['owner', 'admin', 'moderator']), async (req, res) => {
    const targetId = String(req.params.robloxUserId);
    const [profile, activeKeys, shadowBan] = await Promise.all([
        UserProfile.findOne({ robloxUserId: targetId }).lean(),
        Key.find({ assignedUserId: targetId }).lean(),
        ShadowBlacklist.findOne({ robloxUserId: targetId }).lean()
    ]);

    const comprehensiveLogs = await AuditLog.find({ $or: [{ key: { $in: activeKeys.map(k => k.key) } }, { username: profile?.username || '' }] }).sort({ timestamp: -1 }).lean();

    res.status(200).json({
        success: true,
        data: {
            identity: profile || { robloxUserId: targetId, username: "Unknown / Unsaved" },
            avatarUrl: `https://www.roblox.com/headshot-thumbnail/image?userId=${targetId}&width=150&height=150&format=png`,
            banStatus: shadowBan ? { active: true, reason: shadowBan.reason, flaggedAt: shadowBan.flaggedAt } : { active: false },
            associatedKeys: activeKeys,
            activityLogs: comprehensiveLogs
        }
    });
});

// ============================================================================
// MUTATION OPERATIONS WITH LIVE REAL-TIME SOCKET ALERTS
// ============================================================================

app.post('/api/admin/keys/create', authorize(['owner', 'admin']), async (req, res) => {
    const { customKey, durationHours } = req.body;
    const generatedKey = customKey ? customKey.toUpperCase() : "SPECTRE-" + Math.random().toString(36).substring(2, 10).toUpperCase();
    const expirationTime = new Date(Date.now() + (Number(durationHours || 24) * 60 * 60 * 1000));

    const newKey = await Key.create({ key: generatedKey, expiresAt: expirationTime });
    
    io.emit('notification', { type: 'success', message: `New license minted: ${generatedKey}` });
    res.status(200).json({ success: true, key: newKey });
});

app.post('/api/admin/keys/blacklist', authorize(['owner', 'admin']), async (req, res) => {
    const { key, reason } = req.body;
    const target = await Key.findOneAndUpdate({ key }, { isBlacklisted: true, blacklistReason: reason }, { new: true });
    
    if (target?.assignedUserId) {
        await ShadowBlacklist.findOneAndUpdate({ robloxUserId: target.assignedUserId }, { robloxUserId: target.assignedUserId, hwid: target.assignedHWID, reason }, { upsert: true });
        await AuditLog.create({
            event: "SHADOW_EVADE_BLOCK",
            key: key,
            username: `UID: ${target.assignedUserId}`,
            hwid: target.assignedHWID || "N/A",
            status: "ENFORCED"
        });
        await dispatchSecurityAlert("CRITICAL ENFORCEMENT", `Key **${key}** has been banned. User \`${target.assignedUserId}\` shadow-blacklisted. Context: ${reason}`);
    }

    io.emit('notification', { type: 'error', message: `License revoked & system shadow block enforced: ${key}` });
    res.status(200).json({ success: true, message: "Token suspended across clusters." });
});

// Housekeeping utility endpoints
app.post('/api/admin/keys/purge-expired', authorize(['owner']), async (req, res) => {
    try {
        const output = await Key.deleteMany({ expiresAt: { $lt: new Date() } });
        io.emit('notification', { type: 'success', message: `Purged ${output.deletedCount} old expired keys.` });
        return res.status(200).json({ success: true, message: `Purged ${output.deletedCount} old expired keys.` });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/logs/clear', authorize(['owner']), async (req, res) => {
    try {
        await AuditLog.deleteMany({});
        io.emit('notification', { type: 'error', message: "Audit logs streams cleared structural purge." });
        return res.status(200).json({ success: true, message: "Audit logs streams cleared." });
    } catch (err) { return res.status(500).json({ success: false, error: err.message }); }
});

// Verification Gateway Protocol Pipeline
app.post('/api/verify', async (req, res) => {
    const { key, username, robloxUserId, hwid, executor } = req.body;
    
    try {
        const shadowMatch = await ShadowBlacklist.findOne({ $or: [{ robloxUserId: String(robloxUserId) }, { hwid }] });
        if (shadowMatch) {
            await AuditLog.create({ event: "SHADOW_EVADE_BLOCK", key: key || "UNKNOWN", username, hwid, status: "DENIED" });
            io.emit('notification', { type: 'error', message: `Intrusion block triggered for user: ${username}` });
            return res.status(403).json({ success: false, message: "HARDWARE ACCESS SUSPENDED." });
        }

        const keyDoc = await Key.findOne({ key });
        if (!keyDoc) {
            await AuditLog.create({ event: "INITIALIZATION", key: key || "BAD_KEY", username, hwid, status: "INVALID" });
            return res.status(404).json({ success: false, message: "Key registry token not found." });
        }

        if (keyDoc.isBlacklisted) {
            return res.status(403).json({ success: false, message: "License footprint revoked by administration." });
        }

        if (new Date() > keyDoc.expiresAt) {
            return res.status(403).json({ success: false, message: "Licensing temporal frame expired." });
        }

        // Bind user details if unassigned
        if (!keyDoc.assignedUserId) {
            keyDoc.assignedUserId = String(robloxUserId);
            keyDoc.assignedUser = username;
            keyDoc.assignedHWID = hwid;
            keyDoc.assignedExecutor = executor;
            keyDoc.activatedAt = new Date();
            await keyDoc.save();

            await UserProfile.findOneAndUpdate(
                { robloxUserId: String(robloxUserId) },
                { username, lastHwid: hwid, $addToSet: { hwidHistory: hwid } },
                { upsert: true }
            );
        } else if (keyDoc.assignedUserId !== String(robloxUserId)) {
            await AuditLog.create({ event: "HANDSHAKE", key, username, hwid, status: "HWID_MISMATCH" });
            return res.status(403).json({ success: false, message: "Hardware key mapping mismatch." });
        }

        await AuditLog.create({ event: "HANDSHAKE", key, username, hwid, status: "SUCCESS" });
        return res.status(200).json({ success: true, message: "Handshake verified." });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

io.on('connection', (socket) => {
    console.log(`📡 Secure socket data link established: ${socket.id}`);
});

server.listen(PORT, () => console.log(`>>> Spectre Network Engine V3 online on port ${PORT}`));