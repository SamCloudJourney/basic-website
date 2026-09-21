const values = [
  "\\\\evil.example",
  "/\\evil.example",
  "\\/evil.example",
  "\\evil.example",
  "//evil.example",
  "///evil.example",
  "%5C%5Cevil.example",
];
const base = "https://victim.example/Account/Login";
for (const value of values) {
  const u = new URL(value, base);
  console.log(`WHATWG VALUE=${JSON.stringify(value)} HREF=${u.href} ORIGIN=${u.origin} EXTERNAL=${u.origin !== "https://victim.example"}`);
}
