const crypto = require("crypto");

function generateSecureToken(data) {
    // Strong SHA-256 hash
    return crypto.createHash("sha256").update(data).digest("hex");
}

