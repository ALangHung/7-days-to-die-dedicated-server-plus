# 7 Days to Die Dedicated Server Plus

🌐 [繁體中文](readme.md) | [English](readme.en.md)

一套整合 **Web 控制台** + **API** 的 7 Days to Die 專用伺服器管理工具，  
支援安裝 / 更新 Dedicated Server、啟動、關閉、備份存檔、Telnet 操作，以及伺服器資訊查詢。  
適合作為「開服懶人包」或本地 / 局域網伺服器管理解決方案。

![DEMO](demo.png)

---

## 功能特色

- ✅ **Web 操作伺服器**：支援啟動 / 關閉 Dedicated Server (可選 GUI / No GUI 模式)
- 📥 **一鍵安裝 / 更新**：整合 `steamcmd` 自動安裝 / 更新遊戲伺服器
- 💾 **遊戲存檔管理功能**
- 📜 **服務化運行** (支援安裝為 Windows 服務)
- 🔌 **模組管理功能** (計畫中)

---

## 專案結構

```
7-days-to-die-dedicated-server-plus/
├─ public/ # 前端 Web 介面
│ ├─ saves/ # 存檔備份目錄
│ └─ index.html
├─ server.js # 主 API 入口 (可打包成 server.exe)
├─ server.sample.json # 設定檔範本 (安裝程式會自動產生 server.json)
├─ scripts/ # 工具腳本
├─ tools/
│ ├─ steamcmd
│ ├─ 7-Zip
│ └─ nssm
├─ Amazon Root CA 1.crt # 解決 EOS 連線失敗用憑證
├─ LICENSE
└─ README.md
```

## 安裝與使用

### 🖥️ 一般使用者

#### 1. 下載安裝包並執行

安裝程式會：

- 安裝依賴工具 (7-Zip / steamcmd / nssm)
- 自動建立 `server.json` (含使用者帳號的存檔路徑)
- 註冊並安裝為 Windows 服務 (名稱：`7DTD-DS-P`)

#### 2. 開啟 Web 控制台

安裝完成後，瀏覽器將自動開啟：

```
http://localhost:26902/
```

#### 3. Web 介面功能

- 安裝 / 更新 Dedicated Server (可選版本分支)
- 查看管理後台設定 (讀取 server.json)
- 查看伺服器存檔清單
- 備份存檔至 ZIP
- 啟動 / 關閉伺服器
- Telnet 即時指令 (版本、玩家清單、設定查詢)

### 🛠️ 開發者

#### 1. 安裝 Node.js (建議 v22+)

以下擇一安裝：

- [Node.js](https://nodejs.org/)
- (推薦) [nvm-windows](https://github.com/coreybutler/nvm-windows.git)

#### 2. 安裝依賴

```bat
cd src\web
npm install
```

#### 3. 建立設定檔

```bat
copy server.sample.json server.json
```

依環境修改設定檔中的路徑與埠號。

#### 4. 啟動服務

```bat
npm start
```

#### 5. 訪問管理後臺

```
http://localhost:26903/
```

## 常用 API 一覽

| 路徑               | 方法 | 功能                                         |
| ------------------ | ---- | -------------------------------------------- |
| `/api/install`     | POST | 安裝 / 更新 Dedicated Server                 |
| `/api/start`       | POST | 啟動伺服器 (可傳 `{ nographics: true }`)     |
| `/api/stop`        | POST | 關閉伺服器                                   |
| `/api/backup`      | POST | 備份遊戲存檔                                 |
| `/api/view-saves`  | POST | 查看所有備份                                 |
| `/api/telnet`      | POST | 發送 Telnet 指令 (需傳 `{ command: "xxx" }`) |
| `/api/view-config` | POST | 查看管理後台設定                             |

---

## 設定檔說明 (server.json)

| 欄位                         | 說明                           |
| ---------------------------- | ------------------------------ |
| `web.port`                   | Web API 的監聽埠號             |
| `game_server.ip`             | 伺服器 IP (通常為 `127.0.0.1`) |
| `game_server.port`           | 遊戲連線用 Port                |
| `game_server.telnetPort`     | Telnet 管理埠                  |
| `game_server.telnetPassword` | Telnet 密碼                    |
| `game_server.serverConfig`   | `serverconfig.xml` 的路徑      |

# 授權 License

本專案使用 **GPLv3** 授權。  
你可以自由修改與再發佈，但需保留開源並沿用 GPL 條款。
