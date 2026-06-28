const express = require('express');
const cors = require('cors');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json());
app.use(cors());

// Serve administration UI dashboard static assets out of the public folder
app.use(express.static(path.join(__dirname, '../public')));

let cachedClient = null;
let cachedDb = null;

async function connectToDatabase() {
    if (cachedClient && cachedDb) {
        return { client: cachedClient, db: cachedDb };
    }
    
    if (!process.env.MONGO_URI) {
        throw new Error("CRITICAL ERROR: MONGO_URI environment variable is missing on host.");
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
        console.error("Webhook route broken:", err);
    }
}

// --------- ENDPOINTS ---------

// Game client authentication entry point
app.post('/api/verify', async (req, res) => {
    const { key, executor } = req.body;
    if (!key) return res.status(403).json({ success: false, message: "MISSING AUTHORIZATION KEY." });

    try {
        const { db } = await connectToDatabase();
        const keyData = await db.collection("keys").findOne({ _id: key });

        if (!keyData) {
            return res.status(403).json({ success: false, message: "INVALID ACCESS TOKEN." });
        }
        if (keyData.status === "banned") {
            return res.status(403).json({ success: false, message: "TOKEN HAS BEEN BLACKLISTED." });
        }

        // Sanitize string characters to prevent breaking MongoDB nested path lookups
        const safeExecutorName = (executor || "Unknown").replace(/\./g, "_");
        const executorField = `executors.${safeExecutorName}`;

        await db.collection("keys").updateOne(
            { _id: key },
            { 
                $inc: { executions: 1, [executorField]: 1 } 
            }
        );

        sendDiscordWebhook(db, "🔑 Token Verification Success", `**Key:** \`${key}\`\n**Client Platform:** \`${executor || "Unknown"}\``, 65280);
        res.json({ success: true, message: "ACCESS GRANTED." });
    } catch (err) {
        res.status(500).json({ success: false, message: "INTERNAL DATABASE SYNC ERROR." });
    }
});

// Admin Control Panel: Fetch live array mapping
app.get('/api/admin/keys', async (req, res) => {
    try {
        const { db } = await connectToDatabase();
        const keysArray = await db.collection("keys").find({}).toArray();
        
        const keyMap = {};
        keysArray.forEach(k => {
            keyMap[k._id] = { status: k.status, executions: k.executions, executors: k.executors || {} };
        });
        res.json(keyMap);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin Control Panel: Create/Register a license key string
app.post('/api/admin/keys/create', async (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: "Key string configuration missing" });

    try {
        const { db } = await connectToDatabase();
        await db.collection("keys").updateOne(
            { _id: key },
            { $setOnInsert: { status: "active", executions: 0, executors: {}, created: Date.now() } },
            { upsert: true }
        );

        sendDiscordWebhook(db, "➕ Key Token Registered", `New license deployed to registry: \`${key}\``, 3447003);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin Control Panel: Blacklist key string
app.post('/api/admin/keys/ban', async (req, res) => {
    const { key } = req.body;
    try {
        const { db } = await connectToDatabase();
        const result = await db.collection("keys").updateOne({ _id: key }, { $set: { status: "banned" } });
        if (result.matchedCount === 0) return res.status(404).json({ error: "Key registry token target not found" });

        sendDiscordWebhook(db, "🚫 License Revoked", `Key string permanently blacklisted: \`${key}\``, 16711680);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin Control Panel: Delete record completely
app.post('/api/admin/keys/delete', async (req, res) => {
    const { key } = req.body;
    try {
        const { db } = await connectToDatabase();
        const result = await db.collection("keys").deleteOne({ _id: key });
        if (result.deletedCount === 0) return res.status(404).json({ error: "Key registry token target not found" });

        sendDiscordWebhook(db, "🗑️ License Record Purged", `Key string completely cleared from MongoDB storage: \`${key}\``, 16753920);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin Control Panel: Route configuration tracking webhook
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

// Fallback routing: Pass remaining actions to frontend UI core router
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Dynamic configuration matching Render container assignments
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`SPECTRE CORE RUNNING ON ROUTE PORT: ${port}`));