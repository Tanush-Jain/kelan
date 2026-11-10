const fs = require("fs");
const path = require("path");

function serveFile(userFilename) {
    // Path traversal via dynamic path interpolation
    const fullPath = path.join("/var/data", userFilename);
    return fs.readFileSync(fullPath, "utf-8");
}
