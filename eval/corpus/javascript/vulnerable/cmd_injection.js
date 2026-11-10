const cp = require("child_process");

function cleanupDirectory(userPath) {
    // OS Command Injection via exec
    cp.exec(`rm -rf ${userPath}`, (err, stdout) => {
        console.log(stdout);
    });
}
