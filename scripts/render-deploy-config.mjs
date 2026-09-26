import { readFileSync, writeFileSync } from "node:fs";

const sourcePath = "wrangler.jsonc";
const outputPath = process.argv[2] || ".wrangler.deploy.json";
const databaseId = String(process.env.SECURITY_D1_DATABASE_ID || "").trim();
const databaseName = String(
  process.env.SECURITY_D1_DATABASE_NAME || "discord-security"
).trim();

if (!databaseId) {
  throw new Error(
    "SECURITY_D1_DATABASE_ID is required. Create the D1 database first and set the GitHub Actions variable."
  );
}
if (
  !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    databaseId
  )
) {
  throw new Error("SECURITY_D1_DATABASE_ID must be a valid D1 UUID.");
}
if (!databaseName || databaseName.length > 64) {
  throw new Error("SECURITY_D1_DATABASE_NAME is invalid.");
}

let config;
try {
  config = JSON.parse(readFileSync(sourcePath, "utf8"));
} catch (error) {
  throw new Error(
    "wrangler.jsonc must remain JSON-compatible for deployment rendering: " +
      (error instanceof Error ? error.message : String(error))
  );
}

if (!Array.isArray(config.d1_databases)) config.d1_databases = [];
let binding = config.d1_databases.find(item => item?.binding === "DB");
if (!binding) {
  binding = { binding: "DB" };
  config.d1_databases.push(binding);
}
binding.database_name = databaseName;
binding.database_id = databaseId;

writeFileSync(outputPath, JSON.stringify(config, null, 2) + "\n", {
  mode: 0o600
});
console.log(
  `Prepared deployment config for Worker "${config.name}" and D1 "${databaseName}".`
);
