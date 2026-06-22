package main

const indexHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Company VPN</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f7fb;
      --panel: #ffffff;
      --text: #172033;
      --muted: #657084;
      --line: #d9e0ea;
      --primary: #147d73;
      --danger: #b42318;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", "Microsoft YaHei", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    header {
      height: 64px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 28px;
      background: var(--panel);
      border-bottom: 1px solid var(--line);
    }
    h1 { font-size: 20px; margin: 0; }
    main {
      max-width: 980px;
      margin: 24px auto;
      padding: 0 20px;
      display: grid;
      grid-template-columns: 360px 1fr;
      gap: 18px;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
    }
    h2 { font-size: 16px; margin: 0 0 14px; }
    label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 8px;
    }
    input[type=file], select {
      width: 100%;
      height: 36px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      padding: 6px 8px;
    }
    button {
      height: 36px;
      border: 0;
      border-radius: 6px;
      background: var(--primary);
      color: #fff;
      padding: 0 14px;
      font-weight: 600;
      cursor: pointer;
    }
    button.secondary { background: #455468; }
    button.danger { background: var(--danger); }
    .row { display: flex; gap: 8px; margin-top: 12px; }
    .row button { flex: 1; }
    .status {
      color: var(--muted);
      font-size: 13px;
    }
    pre {
      margin: 0;
      min-height: 310px;
      max-height: 520px;
      overflow: auto;
      padding: 12px;
      background: #0f172a;
      color: #dbeafe;
      border-radius: 8px;
      font-size: 12px;
      line-height: 1.45;
      white-space: pre-wrap;
    }
    .hint {
      margin: 10px 0 0;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
    }
  </style>
</head>
<body>
  <header>
    <h1>Company VPN</h1>
    <div class="status" id="status">未连接</div>
  </header>
  <main>
    <section>
      <h2>配置</h2>
      <label for="bundle">客户端配置包</label>
      <input id="bundle" type="file" accept=".json,application/json">
      <div class="row">
        <button type="button" onclick="importBundle()">导入配置包</button>
      </div>
      <p class="hint">配置包从管理后台用户列表下载。导入后每次连接都会实时获取最新配置。</p>

      <h2 style="margin-top:22px">连接方式</h2>
      <label for="profile">线路</label>
      <select id="profile"></select>
      <div class="row">
        <button type="button" onclick="connect()">连接</button>
        <button type="button" class="danger" onclick="disconnect()">断开</button>
      </div>
      <div class="row">
        <button type="button" class="secondary" onclick="refreshProfiles()">刷新</button>
      </div>
      <p class="hint">客户端仅使用 SSH Tunnel，全局模式由内置虚拟网卡完成。</p>
    </section>
    <section>
      <h2>运行日志</h2>
      <pre id="logs"></pre>
    </section>
  </main>
  <script>
    async function api(path, options) {
      const res = await fetch(path, options || {});
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || "操作失败");
      return data;
    }
    async function importBundle() {
      const input = document.getElementById("bundle");
      if (!input.files.length) {
        alert("请选择配置包");
        return;
      }
      const form = new FormData();
      form.append("bundle", input.files[0]);
      try {
        const data = await api("/api/import", { method: "POST", body: form });
        alert("已导入：" + data.name);
        await refreshProfiles();
      } catch (err) {
        alert(err.message);
      }
    }
    async function refreshProfiles() {
      try {
        const data = await api("/api/profiles");
        const select = document.getElementById("profile");
        select.innerHTML = "";
        for (const item of data.profiles) {
          const option = document.createElement("option");
          option.value = item.key;
          option.textContent = item.label;
          select.appendChild(option);
        }
      } catch (err) {
        alert(err.message);
      }
    }
    async function connect() {
      const target = document.getElementById("profile").value;
      const form = new URLSearchParams();
      form.set("target", target);
      try {
        await api("/api/connect", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: form
        });
        await refreshStatus();
      } catch (err) {
        alert(err.message);
      }
    }
    async function disconnect() {
      try {
        await api("/api/disconnect", { method: "POST" });
        await refreshStatus();
      } catch (err) {
        alert(err.message);
      }
    }
    async function refreshStatus() {
      try {
        const data = await api("/api/status");
        document.getElementById("status").textContent = data.status || "未连接";
        document.getElementById("logs").textContent = (data.logs || []).join("\n");
      } catch (err) {
        document.getElementById("status").textContent = err.message;
      }
    }
    refreshProfiles();
    refreshStatus();
    setInterval(refreshStatus, 1500);
  </script>
</body>
</html>`
