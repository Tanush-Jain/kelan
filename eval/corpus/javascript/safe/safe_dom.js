function renderUserBioSafe(bioText) {
    const el = document.getElementById("bio-box");
    // Safe textContent assignment prevents XSS
    el.textContent = bioText;
}

