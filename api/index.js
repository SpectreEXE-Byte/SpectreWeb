const express = require('express');
const cors = require('cors');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json());
app.use(cors());

// Serve static assets out of the public production distribution portal folder
app.use(express.static(path.join(__dirname, '../public')));

let cachedClient = null;
let cachedDb = null;

async function connectToDatabase() {
    if (cachedClient && cachedDb) {
        return { client: cachedClient, db: cachedDb };
    }
    
    if (!process.env.MONGO_URI) {
        throw new Error("CRITICAL ERROR: MONGO_URI environment variable is missing on host platform.");
    }

    const client = new MongoClient(process.env.MONGO_URI, {
        maxPoolSize: 5,
        minPoolSize: 0,
        maxIdleTimeMS: 10000,
        serverSelectionTimeoutMS: 5000
    });

    await client.connect();
    const db = client.db("spectre_registry");
    
    cachedClient = client;
    cachedDb = db;
    return { client, db };
}

async function sendDiscordWebhook(db, title, description, color = 10158335) {
    const config = await db.collection("settings").findOne({ _id: "global" });
    if (!config || !config.discordWebhook) return;
    
    try {
        await fetch(config.discordWebhook, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                embeds: [{
                    title,
                    description,
                    color,
                    timestamp: new Date().toISOString()
                }]
            })
        });
    } catch (err) {
        console.error("Webhook gateway pipeline communication broke down:", err);
    }
}

// ---------------- CLIENT WEB APP IN-GAME VALIDATION API ----------------

app.post('/api/verify', async (req, res) => {
    const { key, executor } = req.body;
    if (!key) return res.status(403).json({ success: false, message: "MISSING AUTHORIZATION CORE DATA." });

    try {
        const { db } = await connectToDatabase();
        const keyData = await db.collection("keys").findOne({ _id: key });

        if (!keyData) {
            return res.status(403).json({ success: false, message: "INVALID AUTH KEY NOT REGISTERED." });
        }
        if (keyData.status === "banned") {
            return res.status(403).json({ success: false, message: "ACCESS REVOKED BY CENTRAL CONTROL PANEL." });
        }

        const safeExecutorName = (executor || "Unknown").replace(/\./g, "_");
        const executorField = `executors.${safeExecutorName}`;

        await db.collection("keys").updateOne(
            { _id: key },
            { 
                $inc: { executions: 1, [executorField]: 1 } 
            }
        );

        sendDiscordWebhook(db, "🔑 Core Execution Trace", `**Token:** \`${key}\`\n**Platform Anchor:** \`${executor || "Unknown"}\``, 65280);
        res.json({ success: true, message: "ACCESS CONSOLE UNLOCKED SITE COMPLIANT." });
    } catch (err) {
        res.status(500).json({ success: false, message: "INTERNAL SYSTEM SYNC BREAKDOWN." });
    }
});

// ---------------- PANEL INTERNAL SYSTEM ADMINISTRATIVE ROUTING ----------------

app.get('/api/admin/keys', async (req, res) => {
    try {
        const { db } = await connectToDatabase();
        const keysArray = await db.collection("keys").find({}).toArray();
        
        const keyMap = {};
        keysArray.forEach(k => {
            if (k && k._id) {
                keyMap[k._id] = { 
                    status: k.status || "active", 
                    executions: k.executions || 0, 
                    executors: k.executors || {} 
                };
            }
        });
        res.json(keyMap);
    } catch (err) {
        console.error("Registry mapping retrieval crashed:", err);
        res.status(500).json({ error: "Internal cluster reading sync failure." });
    }
});

app.post('/api/admin/keys/create', async (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: "Initialization value schema broken" });

    try {
        const { db } = await connectToDatabase();
        await db.collection("keys").updateOne(
            { _id: key },
            { $setOnInsert: { status: "active", executions: 0, executors: {}, created: Date.now() } },
            { upsert: true }
        );

        sendDiscordWebhook(db, "➕ Licensing Matrix Expanded", `Identified key parameter established inside storage system: \`${key}\``, 3447003);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/keys/ban', async (req, res) => {
    const { key } = req.body;
    try {
        const { db } = await connectToDatabase();
        const result = await db.collection("keys").updateOne({ _id: key }, { $set: { status: "banned" } });
        if (result.matchedCount === 0) return res.status(404).json({ error: "No storage trace matching key data verified" });

        sendDiscordWebhook(db, "🚫 Token Ban Handover", `System trace matching entry flagged and blacklisted: \`${key}\``, 16711680);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/keys/delete', async (req, res) => {
    const { key } = req.body;
    try {
        const { db } = await connectToDatabase();
        const result = await db.collection("keys").deleteOne({ _id: key });
        if (result.deletedCount === 0) return res.status(404).json({ error: "No storage trace matching key data verified" });

        sendDiscordWebhook(db, "🗑️ Document Structure Deleted", `Entry systematically purged out of active cluster indices: \`${key}\``, 16753920);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/settings/webhook', async (req, res) => {
    const { url } = req.body;
    try {
        const { db } = await connectToDatabase();
        await db.collection("settings").updateOne(
            { _id: "global" },
            { $set: { discordWebhook: url } },
            { upsert: true }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Fallback routing configuration handles user dashboard navigation entries
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`SPECTRE NET INFRASTRUCTURE ACTIVE VIA FORWARDING LAYER PORT: ${port}`));