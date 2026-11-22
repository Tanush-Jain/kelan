import pytest
from kelan.sast.engine import SastEngine


@pytest.fixture
def engine():
    return SastEngine()


@pytest.mark.asyncio
async def test_python_xxe_rule(engine):
    vuln_code = """
import xml.etree.ElementTree as ET
def parse(data):
    return ET.fromstring(data)
"""
    findings = await engine.scan_code("parse.py", vuln_code, use_reachability=False)
    assert any(f.cwe == "CWE-611" for f in findings)

    safe_code = """
import defusedxml.minidom
def parse(data):
    return defusedxml.minidom.parseString(data)
"""
    safe_findings = await engine.scan_code("safe.py", safe_code, use_reachability=False)
    assert not any(f.cwe == "CWE-611" for f in safe_findings)


@pytest.mark.asyncio
async def test_python_insecure_random_rule(engine):
    vuln_code = """
import random
def get_tok():
    auth_token = ''.join(random.choice('abc') for _ in range(16))
    return auth_token
"""
    findings = await engine.scan_code("tok.py", vuln_code, use_reachability=False)
    assert any(f.cwe == "CWE-330" for f in findings)


@pytest.mark.asyncio
async def test_python_weak_password_hash_rule(engine):
    vuln_code = """
import hashlib
def hash_pwd(password):
    return hashlib.md5(password.encode()).hexdigest()
"""
    findings = await engine.scan_code("pwd.py", vuln_code, use_reachability=False)
    assert any(f.cwe == "CWE-759" for f in findings)


@pytest.mark.asyncio
async def test_python_sensitive_logging_rule(engine):
    vuln_code = """
import logging
def login(username, password):
    logging.info(f"User {username} with password={password}")
"""
    findings = await engine.scan_code("log.py", vuln_code, use_reachability=False)
    assert any(f.cwe == "CWE-532" for f in findings)


@pytest.mark.asyncio
async def test_python_missing_auth_rule(engine):
    vuln_code = """
from fastapi import FastAPI
app = FastAPI()
@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int):
    return {"status": "ok"}
"""
    findings = await engine.scan_code("route.py", vuln_code, use_reachability=False)
    assert any(f.cwe == "CWE-284" for f in findings)


@pytest.mark.asyncio
async def test_js_nosql_injection_rule(engine):
    vuln_code = """
function findUsers(req, res) {
    User.find(req.body);
}
"""
    findings = await engine.scan_code("user.js", vuln_code, use_reachability=False)
    assert any(f.cwe == "CWE-943" for f in findings)


@pytest.mark.asyncio
async def test_js_prototype_pollution_rule(engine):
    vuln_code = """
function merge(target, k, v) {
    target["__proto__"][k] = v;
}
"""
    findings = await engine.scan_code("proto.js", vuln_code, use_reachability=False)
    assert any(f.cwe == "CWE-915" for f in findings)


@pytest.mark.asyncio
async def test_js_sensitive_logging_rule(engine):
    vuln_code = """
function auth(user, authToken) {
    console.log(`Token: ${authToken}`);
}
"""
    findings = await engine.scan_code("log.js", vuln_code, use_reachability=False)
    assert any(f.cwe == "CWE-532" for f in findings)


@pytest.mark.asyncio
async def test_js_missing_cookie_security_rule(engine):
    vuln_code = """
function setCookie(res, tok) {
    res.cookie("sid", tok, { path: "/" });
}
"""
    findings = await engine.scan_code("cookie.js", vuln_code, use_reachability=False)
    assert any(f.cwe == "CWE-614" for f in findings)


@pytest.mark.asyncio
async def test_go_sql_injection_rule(engine):
    vuln_code = """package main
import (
    "database/sql"
    "fmt"
)
func query(db *sql.DB, id string) {
    q := fmt.Sprintf("SELECT * FROM tbl WHERE id = '%s'", id)
    db.Query(q)
}
"""
    findings = await engine.scan_code("query.go", vuln_code, use_reachability=False)
    assert any(f.cwe == "CWE-89" for f in findings)


@pytest.mark.asyncio
async def test_go_command_injection_rule(engine):
    vuln_code = """package main
import "os/exec"
func run(cmd string) {
    c := exec.Command("sh", "-c", cmd)
    c.Run()
}
"""
    findings = await engine.scan_code("cmd.go", vuln_code, use_reachability=False)
    assert any(f.cwe == "CWE-78" for f in findings)
