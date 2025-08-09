const { spawn, execFile } = require("child_process");
const path = require("path");
const killTree = require("tree-kill");
const { log, error } = require("./logger");

const gameServer = {
  child: null,
  isRunning: false,
  isTelnetConnected: false,
  basePath: null,
  lastPid: null,

  /**
   * 啟動 7D2D 伺服器(保留相容: 由外部決定 args 與 cwd)
   * @param {string[]} args
   * @param {string} gameServerPath
   * @param {{exeName?:string,onExit?:(code:number,signal:string)=>void,onError?:(err:any)=>void}} options
   */
  start(args, gameServerPath, options = {}) {
    if (this.isRunning) throw new Error("遊戲伺服器已經在運行中");
    const { exeName = "7DaysToDieServer.exe", onExit, onError } = options;

    this.basePath = gameServerPath;
    const exePath = path.join(gameServerPath, exeName);

    log(
      `🚀 啟動遊戲伺服器: exe=${exePath}, cwd=${gameServerPath}, args=${JSON.stringify(
        args
      )}`
    );

    try {
      this.child = spawn(exePath, args, {
        cwd: gameServerPath,
        detached: true,
        stdio: "ignore",
      });
    } catch (err) {
      this.child = null;
      this.isRunning = false;
      this.basePath = null;
      error(`❌ 進程啟動失敗: ${err?.message || err}`);
      if (typeof onError === "function") onError(err);
      throw err;
    }

    this.isRunning = true;
    this.lastPid = this.child.pid;
    log(`✅ 遊戲伺服器進程啟動，pid=${this.child.pid}`);

    this.child.on("error", (err) => {
      this.isRunning = false;
      this.isTelnetConnected = false;
      this.child = null;
      this.basePath = null;
      error(`❌ 遊戲伺服器進程錯誤: ${err?.message || err}`);
      if (typeof onError === "function") {
        try {
          onError(err);
        } catch (_) {}
      }
    });

    let closed = false;
    const onClose = (code, signal) => {
      if (closed) return;
      closed = true;
      this.isRunning = false;
      this.isTelnetConnected = false;
      this.child = null;
      this.basePath = null;
      log(`🛑 遊戲伺服器進程結束 code=${code ?? -1}, signal=${signal || "-"}`);
      if (typeof onExit === "function") {
        try {
          onExit(code ?? -1, signal || null);
        } catch (_) {}
      }
    };

    this.child.on("exit", onClose);
    this.child.on("close", onClose);

    this.child.unref();
  },

  /** 取得目前或最後已知的 PID */
  getPid() {
    return this.child?.pid ?? this.lastPid ?? null;
  },

  /**
   * 以 PID 強制結束(Windows 使用 taskkill /T /F；其他平台用 process.kill)
   * 回傳 true 表示 taskkill 成功執行且退出碼為 0；false 表示失敗或無 PID
   */
  async killByPid(pid) {
    const targetPid = pid ?? this.getPid();
    if (!targetPid) {
      log("ℹ️ killByPid: 無可用 PID");
      return false;
    }

    if (process.platform === "win32") {
      // 透過 cmd 啟動 taskkill，避免 PATH/重導致問題
      const cmd = process.env.ComSpec || "cmd.exe";
      const args = ["/c", "taskkill", "/PID", String(targetPid), "/T", "/F"];

      log(`🗡️ killByPid: 執行 taskkill PID=${targetPid}`);
      const ok = await new Promise((resolve) => {
        execFile(cmd, args, { windowsHide: true }, (err, stdout, stderr) => {
          if (stdout) log(`taskkill stdout: ${stdout.trim()}`);
          if (stderr) error(`taskkill stderr: ${stderr.trim()}`);
          if (err) {
            error(
              `❌ taskkill 失敗 pid=${targetPid}, code=${
                err.code ?? "-"
              }, msg=${err.message}`
            );
            return resolve(false);
          }
          log(`✅ taskkill 成功 pid=${targetPid}`);
          resolve(true);
        });
      });

      // 無論成功與否，都重置內部狀態（避免卡死狀態）
      this.child = null;
      this.isRunning = false;
      this.isTelnetConnected = false;
      this.basePath = null;

      return ok;
    }

    // 非 Windows：使用 process.kill
    try {
      process.kill(targetPid, "SIGKILL");
      log(`✅ process.kill 成功 pid=${targetPid}`);
    } catch (e) {
      error(`❌ process.kill 失敗 pid=${targetPid}: ${e?.message || e}`);
      return false;
    } finally {
      this.child = null;
      this.isRunning = false;
      this.isTelnetConnected = false;
      this.basePath = null;
    }
    return true;
  },

  /**
   * 舊的樹狀結束（保留）
   */
  killTree() {
    if (this.child && !this.child.killed) {
      log(`🗡️ killTree() 結束子進程 pid=${this.child.pid}`);
      try {
        killTree(this.child.pid);
      } catch (e) {
        error(`❌ killTree 發生錯誤: ${e?.message || e}`);
      }
    } else {
      log("ℹ️ killTree(): 無子進程可結束，僅重置狀態");
    }
    this.child = null;
    this.isRunning = false;
    this.isTelnetConnected = false;
    this.basePath = null;
    log("✅ 狀態已重置");
  },
};

module.exports = gameServer;
