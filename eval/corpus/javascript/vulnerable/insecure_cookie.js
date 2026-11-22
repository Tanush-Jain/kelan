function setSession(res, sessionToken) {
    // Insecure cookie without httpOnly or secure flags
    res.cookie("session_id", sessionToken, { path: "/" });
}
