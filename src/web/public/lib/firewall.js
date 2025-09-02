const { execFile } = require("child_process");
const path = require("path");
const fs = require("fs");

/**
 * 執行 PowerShell 腳本，建立/檢查防火牆規則
 * 回傳 { status: 'created' | 'exists' | 'failed', code, stdout, stderr }
 */
function initFirewallRule() {
  // 1) 指向 ps1（用絕對路徑最穩）
  const psScriptPath = path.join(__dirname, "checkOrCreateGameServerFirewallRule.ps1");
  if (!fs.existsSync(psScriptPath)) {
    return Promise.resolve({
      status: "failed",
      code: -1,
      stdout: "",
      stderr: `PowerShell script not found: ${psScriptPath}`,
    });
  }

  // 2) 指向 .exe（示例：同層往上兩層的 7DaysToDieServer.exe；自行調整）
  const programPath = path.join(__dirname, "..", "..", "7daystodieserver", "7DaysToDieServer.exe");

  const args = [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-File", psScriptPath,
    "-ProgramPath", programPath,
    "-DisplayName", "7 Days To Die Server",
    "-Description", "Allow inbound TCP/UDP all ports for MyGame server",
  ];

  const options = {
    cwd: path.dirname(psScriptPath), // 讓 ps1 內相對路徑以腳本所在目錄為基準
    windowsHide: true,
  };

  return new Promise((resolve) => {
    execFile("powershell.exe", args, options, (error, stdoutRaw, stderrRaw) => {
      const code = error ? (error.code ?? -1) : 0;
      const stdout = (stdoutRaw || "").toString();
      const stderr = (stderrRaw || "").toString();

      // 依照 ps1 的輸出判斷狀態
      // ps1 會輸出：
      // - "Created: TCP ..." / "Created: UDP ..." → 代表有建立
      // - "Already present: TCP/UDP ..." → 代表已存在
      const createdRe = /Created:\s*(TCP|UDP)\s+/i;
      const alreadyRe = /Already present:/i;

      let status;
      if (code === 0) {
        if (createdRe.test(stdout)) {
          status = "created";
        } else if (alreadyRe.test(stdout)) {
          status = "exists";
        } else {
          // 成功退出但沒偵測到關鍵字，視為已存在（保守處理）
          status = "exists";
        }
      } else {
        status = "failed";
      }

      resolve({ status, code, stdout, stderr });
    });
  });
}

module.exports = { initFirewallRule };