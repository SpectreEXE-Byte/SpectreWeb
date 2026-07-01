const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || "SPECTRE_SUPER_SECRET_CORE_VECTOR";

const authorize = (allowedRoles = []) => {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                success: false, 
                message: "Missing access credentials. Authorization payload rejected." 
            });
        }

        const token = authHeader.split(' ')[1];

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;

            // Check roles if specific access control levels are requested
            if (allowedRoles.length && !allowedRoles.includes(decoded.role)) {
                return res.status(403).json({ 
                    success: false, 
                    message: "Access forbidden: your profile lacks sufficient execution clearance." 
                });
            }

            next();
        } catch (err) {
            return res.status(401).json({ 
                success: false, 
                message: "Session token state is invalid, altered, or has reached expiration." 
            });
        }
    };
};

module.exports = authorize;