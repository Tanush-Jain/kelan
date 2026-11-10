function findUserByEmailSafe(db, userEmail) {
    // Parameterized query execution
    return db.query("SELECT * FROM users WHERE email = $1", [userEmail]);
}
