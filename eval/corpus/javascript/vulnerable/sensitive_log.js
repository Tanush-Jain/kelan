function authenticateUser(user, authToken) {
    // Logging auth_token leaks credentials into console
    console.log(`User login succeeded with authToken=${authToken}`);
}
