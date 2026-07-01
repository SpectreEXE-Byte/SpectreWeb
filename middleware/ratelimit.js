const { rateLimit } = require('express-rate-limit');

const globalApiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 Minute observation cycle
    limit: 100, // Maximum connections allowed per singular IP footprint
    standardHeaders: 'draft-7', // Return standard rate-limiting headers
    legacyHeaders: false, // Disable older X-RateLimit headers
    message: { 
        success: false, 
        message: "Network exception: request frequency limits exceeded. Telemetry access temporarily throttled." 
    }
});

module.exports = globalApiLimiter;