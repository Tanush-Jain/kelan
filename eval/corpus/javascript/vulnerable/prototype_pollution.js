function updateConfig(target, key, val) {
    // Direct assignment to __proto__ causes prototype pollution
    target["__proto__"][key] = val;
}
