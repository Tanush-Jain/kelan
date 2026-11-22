function setSafeSession(res, sessionToken) {
    res.cookie("session_id", sessionToken, { httpOnly: true, secure: true, sameSite: "strict" });
}
