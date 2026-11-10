const express = require("express");
const cp = require("child_process");

const app = express();

function executeDynamicQuery(db, filter) {
    // Reachable SQL injection called from route
    return db.query(`SELECT * FROM records WHERE filter = '${filter}'`);
}

function orphanExec(cmd) {
    // Unreachable command injection in uncalled function
    cp.exec(cmd);
}

app.get("/search", (req, res) => {
    const filter = req.query.filter;
    executeDynamicQuery(req.db, filter);
    res.send("ok");
});

app.get("/profile", (req, res) => {
    req.db.query("SELECT * FROM profiles WHERE id = $1", [req.query.id]);
    res.json({ status: "active" });
});

app.listen(3000);
