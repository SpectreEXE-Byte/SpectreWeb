const { createClient } = require('redis');

const redisClient = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});

redisClient.on('error', (err) => {
    console.error('⚠️ Redis Core Cache Pipeline Error:', err.message);
});

redisClient.on('connect', () => {
    console.log('>>> High-Performance Redis Cache Cluster Linked.');
});

// Initialize connection wrapper asynchronously
const initializeRedisCache = async () => {
    try {
        await redisClient.connect();
    } catch (err) {
        console.log("⚠️ Redis offline/unreachable. System falling back to primary database queries dynamically.");
    }
};

module.exports = {
    redisClient,
    initializeRedisCache
};