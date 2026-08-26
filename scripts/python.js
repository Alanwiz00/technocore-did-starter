#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");

const requested = process.env.PYTHON && process.env.PYTHON.trim();
const candidates = requested
  ? [[requested, []]]
  : process.platform === "win32"
    ? [["python", []], ["py", ["-3.12"]], ["python3", []]]
    : [["python3", []], ["python", []]];

for (const [command, prefix] of candidates) {
  const result = spawnSync(command, [...prefix, ...process.argv.slice(2)], {
    stdio: "inherit",
    env: process.env,
  });
  if (!result.error || result.error.code !== "ENOENT") {
    if (result.error) {
      console.error(`failed to start ${command}: ${result.error.message}`);
      process.exit(1);
    }
    process.exit(result.status === null ? 1 : result.status);
  }
}

console.error("Python 3.12 was not found. Activate the project virtual environment or set PYTHON.");
process.exit(1);
