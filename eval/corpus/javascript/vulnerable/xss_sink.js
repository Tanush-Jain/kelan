function renderUserBio(bioText) {
    const el = document.getElementById("bio-box");
    // Cross-site scripting (XSS) DOM sink
    el.innerHTML = bioText;
}

function renderLegacyNotice(notice) {
    // Cross-site scripting (XSS) via document.write
    document.write("<div>" + notice + "</div>");
}

