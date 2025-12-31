// build.js
import fs from "fs";
import path from "path";

const DOCS_DIR = "./docs";

// read all .md files
const files = fs.readdirSync(DOCS_DIR)
  .filter(f => f.endsWith(".md"));

// generate JS module
const output = `
export const BLOG_FILES = ${JSON.stringify(files, null, 2)};
`;

fs.writeFileSync(
  path.join(DOCS_DIR, "blogIndex.js"),
  output.trim()
);

console.log("✔ blogIndex.js generated:", files);
