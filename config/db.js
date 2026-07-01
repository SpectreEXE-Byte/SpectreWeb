const mongoose = require('mongoose');

const connectDatabaseCluster = async () => {
    try {
        const connectionString = process.env.MONGO_URI;
        if (!connectionString) {
            throw new Error("Critical Configuration Error: MONGO_URI string variable is completely undefined.");
        }

        await mongoose.connect(connectionString);
        console.log('>>> Spectre V3 Distributed Core Database Connected Securely.');
    } catch (err) {
        console.error('!!! Critical Database Initialization Failure:', err.message);
        process.exit(1);
    }
};

module.exports = connectDatabaseCluster;