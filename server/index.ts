import { execSync, spawn } from "child_process";
import * as path from "path";

const WORKSPACE = "/home/runner/workspace";

async function main() {
  console.log("============================================");
  console.log(" IDENTITY AGENT - Phase 1: Skeleton");
  console.log("============================================");

  console.log("\n[1/3] Building Go Core...");
  try {
    execSync(
      `cd ${path.join(WORKSPACE, "identity-agent-core")} && go build -o ${path.join(WORKSPACE, "bin", "identity-agent-core")} .`,
      { stdio: "inherit" }
    );
    console.log("      Go Core built successfully.");
  } catch (e) {
    console.error("      Failed to build Go Core:", e);
    process.exit(1);
  }

  console.log("\n[2/3] Building Flutter Web...");
  try {
    execSync(
      `cd ${path.join(WORKSPACE, "identity_agent_ui")} && flutter build web --release --base-href="/"`,
      { stdio: "inherit" }
    );
    console.log("      Flutter Web built successfully.");
  } catch (e) {
    console.error("      Failed to build Flutter Web:", e);
    process.exit(1);
  }

  console.log("\n[3/3] Starting Identity Agent Core on port 5000...");
  console.log("      API:  http://0.0.0.0:5000/api/health");
  console.log("      UI:   http://0.0.0.0:5000/");
  console.log("============================================\n");

  const goCore = spawn(
    path.join(WORKSPACE, "bin", "identity-agent-core"),
    [],
    {
      cwd: WORKSPACE,
      stdio: "inherit",
      env: {
        ...process.env,
        PORT: "5000",
        FLUTTER_WEB_DIR: path.join(WORKSPACE, "identity_agent_ui", "build", "web"),
      },
    }
  );

  goCore.on("exit", (code) => {
    console.log(`Go Core exited with code ${code}`);
    process.exit(code ?? 1);
  });

  process.on("SIGINT", () => {
    goCore.kill("SIGINT");
  });

  process.on("SIGTERM", () => {
    goCore.kill("SIGTERM");
  });
}

main();
