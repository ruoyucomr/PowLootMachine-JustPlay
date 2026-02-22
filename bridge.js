// ==============================================================
// PowLoot Bridge v5 — 浏览器端桥接脚本
// 在 powloot-elysiver.h-e.top 控制台粘贴执行
//
// v5 改进：
//   - 提交不阻塞主循环（找到解 → 后台提交 → 立即开始下一题）
//   - 更好的 HTTP 错误处理和重试
//   - WS 拦截：send() + constructor（不创建新连接）
// ==============================================================
(async () => {
  "use strict";

  const RUST_URL = "http://localhost:19527/";
  let WITHDRAW_THRESHOLD_MICRO = 100_000_00;

  // ---- 清理旧桥接实例 ----
  if (window.__plbridge) {
    if (window.__plbridge._relayWin) try { window.__plbridge._relayWin.close(); } catch {}
    if (window.__plbridge._onMessage) window.removeEventListener("message", window.__plbridge._onMessage);
    if (window.__plbridge._withdrawTimer) clearInterval(window.__plbridge._withdrawTimer);
    if (window.__plbridge._stop) window.__plbridge._stop(false);
    if (window.__plbridge._origSend) WebSocket.prototype.send = window.__plbridge._origSend;
    if (window.__plbridge._OrigWS) window.WebSocket = window.__plbridge._OrigWS;
  }

  // ---- 日志 ----
  function log(msg, type = "info") {
    const icons = { info: "›", success: "✓", warn: "⚠", error: "✕" };
    const colors = { info: "#8be9fd", success: "#50fa7b", warn: "#f1fa8c", error: "#ff5555" };
    const time = new Date().toTimeString().slice(0, 8);
    console.log(
      `%c[${time}] [Rust] ${icons[type] || "›"} %c${msg}`,
      `color:${colors[type] || "#8be9fd"};font-weight:bold`, "color:inherit"
    );
    try {
      const box = document.getElementById("logBox");
      if (box) {
        const entry = document.createElement("div");
        entry.className = `log-entry log-${type}`;
        entry.innerHTML = `<div class="log-icon">${icons[type] || "›"}</div>`
          + `<div class="log-content"><div class="log-time">${time}</div>`
          + `<div class="log-message">[Rust] ${msg.replace(/</g, "&lt;")}</div></div>`;
        box.appendChild(entry);
        box.scrollTop = box.scrollHeight;
      }
    } catch {}
  }

  // ---- 状态 ----
  let wsSecret = null;
  let wsSecretExpiresAtMs = 0;
  let pageWs = null;
  let relayWin = null;
  let relayConnected = false;
  let running = false;
  let currentRoundId = null;
  let currentTrack = null;
  let pendingResolve = null;
  let withdrawTimer = null;
  // 找到解时暂存，供主循环提交
  let lastSolution = null;

  function resolvePending() {
    if (pendingResolve) { const fn = pendingResolve; pendingResolve = null; fn(); }
  }

  // ============================================================
  // WS 拦截
  // ============================================================

  function onPageWsMessage(event) {
    try {
      const msg = JSON.parse(event.data);
      if (msg?.type === "secret") {
        wsSecret = msg.secret;
        wsSecretExpiresAtMs = Number(msg.expires_at_ms) || 0;
        log(`WS secret 已更新`);
      }
      if (msg?.type === "round_solved") {
        if (running && currentTrack === msg.track && currentRoundId === msg.round_id) {
          log(`本轮已被他人解出 (${msg.track})，切换下一题...`, "warn");
          lastSolution = null; // 不要提交了
          sendToRust({ type: "stop" });
          resolvePending();
        }
      }
      if (msg?.type === "kicked") {
        log("页面 WS 被踢下线（有新连接接入）", "warn");
      }
    } catch {}
  }

  function hookWs(ws) {
    if (ws.__plHooked) return;
    ws.__plHooked = true;
    pageWs = ws;
    ws.addEventListener("message", onPageWsMessage);
    ws.addEventListener("close", () => { if (pageWs === ws) pageWs = null; });
    log("已接入页面 WS 连接（secret 通道）");
  }

  function isServerWsUrl(url) {
    return typeof url === "string" && url.includes("/ws") && !url.includes("localhost");
  }

  const _origSend = WebSocket.prototype.send;
  WebSocket.prototype.send = function (data) {
    if (!this.__plHooked && isServerWsUrl(this.url)) hookWs(this);
    return _origSend.call(this, data);
  };

  const _OrigWS = window.WebSocket;
  window.WebSocket = function (url, protocols) {
    const ws = protocols !== undefined ? new _OrigWS(url, protocols) : new _OrigWS(url);
    if (isServerWsUrl(url)) ws.addEventListener("open", () => hookWs(ws));
    return ws;
  };
  window.WebSocket.prototype = _OrigWS.prototype;
  window.WebSocket.CONNECTING = _OrigWS.CONNECTING;
  window.WebSocket.OPEN = _OrigWS.OPEN;
  window.WebSocket.CLOSING = _OrigWS.CLOSING;
  window.WebSocket.CLOSED = _OrigWS.CLOSED;

  log("WS 拦截已安装");

  // ---- 中继窗口 ----
  function isRustConnected() {
    return relayWin && !relayWin.closed && relayConnected;
  }
  function sendToRust(obj) {
    if (isRustConnected()) {
      relayWin.postMessage({ _r: 1, t: "send", d: JSON.stringify(obj) }, "*");
    }
  }

  // ---- 页面 API ----
  async function fetchChallenge() {
    const r = await fetch("/challenge", { cache: "no-store" });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  // 提交解（带重试，返回结果或 null）
  async function submitSolution(track, roundId, nonce) {
    if (!wsSecret) { log("缺少 WS secret，无法提交", "error"); return null; }
    if (wsSecretExpiresAtMs && Date.now() > wsSecretExpiresAtMs + 1500) {
      log("WS secret 已过期，等待刷新...", "warn"); return null;
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const r = await fetch("/submit", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-POW-SECRET": wsSecret },
          body: JSON.stringify({ track, round_id: roundId, proof: { nonce } }),
        });
        if (r.ok) {
          const ct = r.headers.get("content-type") || "";
          if (ct.includes("json")) return r.json();
        }
        // 非 200 或非 JSON — 可能是 Cloudflare 拦截
        log(`提交 HTTP ${r.status} (attempt ${attempt + 1})`, "error");
        if (attempt === 0) await new Promise(r => setTimeout(r, 300));
      } catch (e) {
        log(`提交网络错误: ${e.message} (attempt ${attempt + 1})`, "error");
        if (attempt === 0) await new Promise(r => setTimeout(r, 300));
      }
    }
    return null;
  }

  async function checkAndWithdraw() {
    try {
      const r = await fetch("/balance");
      const d = await r.json();
      const balance = Number(d.pending_balance_micro) || 0;
      if (balance >= WITHDRAW_THRESHOLD_MICRO) {
        log(`余额 ${(balance / 1e6).toFixed(6)} 达到阈值，自动提现...`);
        const wr = await fetch("/withdraw_code", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        });
        const wd = await wr.json();
        if (wd.status === "ok" && wd.code) {
          const amount = (wd.amount_micro / 1e6).toFixed(6);
          log(`提现成功! 兑换码: ${wd.code}  金额: ${amount}`, "success");
          sendToRust({ type: "save_code", code: `${wd.code}|${amount}` });
        } else {
          log(`提现失败: ${wd.reason || JSON.stringify(wd)}`, "error");
        }
      }
    } catch {}
  }

  // ---- Rust 消息处理 ----
  function handleRustMessage(rawData) {
    let data;
    try { data = JSON.parse(rawData); } catch { return; }
    switch (data.type) {
      case "ready":
        log(`Rust 引擎就绪，${data.threads} 线程`, "success");
        addRustButton();
        updateRustBtn();
        break;
      case "solution":
        // 暂存解，不在这里提交（主循环负责提交）
        log(`找到解! nonce=${data.nonce.slice(0, 16)}...`, "success");
        lastSolution = { nonce: data.nonce, track: currentTrack, roundId: currentRoundId };
        resolvePending();
        break;
      case "stopped":
        resolvePending();
        break;
    }
  }

  // ---- 主挖矿循环 ----
  async function bridgeStart() {
    if (running || !isRustConnected()) return;
    running = true;
    updateRustBtn();

    withdrawTimer = setInterval(checkAndWithdraw, 30_000);
    log("Rust 挖矿开始...", "success");

    while (running) {
      if (!wsSecret) {
        log("等待 WS secret...（点一下页面「开始计算」再停止即可触发）", "warn");
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }

      let challenge;
      try {
        challenge = await fetchChallenge();
      } catch (e) {
        log(`获取挑战失败: ${e.message}`, "error");
        await new Promise(r => setTimeout(r, 1000));
        continue;
      }

      const { track, round_id, params } = challenge;
      currentTrack = track;
      currentRoundId = round_id;
      lastSolution = null;

      log(`赛道: ${track}  bits: ${params.bits}  round: ${round_id}`);

      sendToRust({ type: "mine", round_id, track, params });

      // 上报假算力
      if (pageWs?.readyState === 1) {
        const fakeHps = 10 + Math.random() * 20;
        pageWs.send(JSON.stringify({ type: "hashrate", hps: fakeHps, track }));
      }

      // 等待解或外部中断（round_solved / 超时）
      await new Promise(resolve => {
        pendingResolve = resolve;
        setTimeout(() => { if (pendingResolve === resolve) { pendingResolve = null; resolve(); } }, 300_000);
      });

      // 如果找到了解 → 提交并等待结果（避免 429 限流）
      if (lastSolution) {
        const sol = lastSolution;
        lastSolution = null;
        try {
          const result = await submitSolution(sol.track, sol.roundId, sol.nonce);
          if (result?.status === "win") {
            const payout = result.payout_micro ? (result.payout_micro / 1e6).toFixed(6) : "?";
            const time = result.solve_time_ms ? (result.solve_time_ms / 1000).toFixed(2) : "?";
            log(`获胜! +${payout}  用时 ${time}s`, "success");
            checkAndWithdraw();
          } else if (result?.status === "too_late") {
            log("被抢先", "warn");
          } else if (result) {
            log(`提交结果: ${result.reason || JSON.stringify(result)}`, "warn");
          }
        } catch (e) {
          log(`提交异常: ${e.message}`, "error");
        }
      }
    }

    log("Rust 挖矿已停止");
    if (withdrawTimer) { clearInterval(withdrawTimer); withdrawTimer = null; }
    updateRustBtn();
  }

  function bridgeStop(sendMsg = true) {
    running = false;
    if (sendMsg) sendToRust({ type: "stop" });
    lastSolution = null;
    resolvePending();
    currentTrack = null;
    currentRoundId = null;
    updateRustBtn();
  }

  // ---- 新增 Rust 按钮 ----
  let rustBtn = null;

  function addRustButton() {
    if (document.getElementById("rustBridgeBtn")) return;
    const stopBtn = document.getElementById("stopBtn");
    if (!stopBtn) { log("未找到 stopBtn", "warn"); return; }

    rustBtn = document.createElement("button");
    rustBtn.id = "rustBridgeBtn";
    rustBtn.className = stopBtn.className;
    rustBtn.style.cssText = "margin-left:8px;";
    rustBtn.textContent = "Rust 连接中...";
    rustBtn.disabled = true;
    rustBtn.addEventListener("click", () => {
      if (running) bridgeStop(true);
      else bridgeStart();
    });
    stopBtn.parentNode.insertBefore(rustBtn, stopBtn.nextSibling);
    log("已添加「Rust 挖矿」按钮");
  }

  function updateRustBtn() {
    if (!rustBtn) rustBtn = document.getElementById("rustBridgeBtn");
    if (!rustBtn) return;
    if (!isRustConnected()) {
      rustBtn.textContent = "Rust 连接中...";
      rustBtn.disabled = true;
    } else if (running) {
      rustBtn.textContent = "⬛ 停止 Rust";
      rustBtn.disabled = false;
    } else {
      rustBtn.textContent = "⚡ Rust 挖矿";
      rustBtn.disabled = false;
    }
  }

  // ---- 中继消息 ----
  function onRelayMessage(event) {
    if (!event.data || event.data._r !== 1) return;
    switch (event.data.t) {
      case "open":
        relayConnected = true;
        log("中继 WS 已连接 Rust 引擎", "success");
        addRustButton();
        updateRustBtn();
        break;
      case "msg":
        handleRustMessage(event.data.d);
        break;
      case "err":
        log("中继连接错误，请确认 powloot-machine.exe 已启动", "error");
        relayConnected = false;
        updateRustBtn();
        break;
      case "close":
        log("中继连接断开", "warn");
        relayConnected = false;
        if (running) bridgeStop(false);
        updateRustBtn();
        break;
    }
  }

  window.addEventListener("message", onRelayMessage);

  // ---- 启动 ----
  log("正在连接 Rust 计算引擎...");
  relayWin = window.open(RUST_URL, "_plRelay", "width=420,height=160");
  if (!relayWin || relayWin.closed) {
    log("无法打开中继窗口！请允许弹窗后重新粘贴脚本", "error");
    log("提示: 点击地址栏右侧弹窗拦截图标 → '始终允许'", "error");
  }

  window.__plbridge = {
    start: bridgeStart,
    stop: () => bridgeStop(true),
    status: () => ({
      running, rustConnected: isRustConnected(), track: currentTrack,
      secret: !!wsSecret, wsHooked: !!pageWs,
    }),
    withdraw: checkAndWithdraw,
    setThreshold: (micro) => { WITHDRAW_THRESHOLD_MICRO = micro; log(`提现阈值: ${micro} micro`); },
    _relayWin: relayWin,
    _onMessage: onRelayMessage,
    _stop: bridgeStop,
    _withdrawTimer: null,
    _origSend,
    _OrigWS,
  };

  log("Bridge v5 已加载", "success");
  log("提示：如 secret 未获取，请先点一下页面「开始计算」再停止即可触发", "warn");
})();
