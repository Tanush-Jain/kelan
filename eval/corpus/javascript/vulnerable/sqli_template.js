function findUserByEmail(db, userEmail) {
    // SQL Injection via template literal
    return db.query(`SELECT * FROM users WHERE email = '${userEmail}'`);
}

