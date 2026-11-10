const cp = require("child_process");

function runGitStatus() {
    // Safe execFile with arguments array
    return cp.execFile("git", ["status"], (err, stdout) => {
        console.log(stdout);
    });
}
