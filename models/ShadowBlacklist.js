// High-performance search and filtering indexes
keySchema.index({ assignedUserId: 1, isBlacklisted: 1 });
keySchema.index({ key: 1 }, { unique: true });

// Compound text indexing for global search functionality
userProfileSchema.index({ username: "text", robloxUserId: "text" });

// Compound log aggregation and time-series optimizations
logSchema.index({ timestamp: -1, event: 1 });
shadowBlacklistSchema.index({ robloxUserId: 1, hwid: 1 });