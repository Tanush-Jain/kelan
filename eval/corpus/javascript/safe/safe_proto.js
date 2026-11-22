function safeUpdateConfig(key, val) {
    const safeObj = Object.create(null);
    safeObj[key] = val;
    return safeObj;
}
