"use strict";

(function () {
  var player = document.getElementById("player");
  var listEl = document.getElementById("recList");
  var listMeta = document.getElementById("listMeta");
  var listEmpty = document.getElementById("listEmpty");
  var controls = document.getElementById("controls");
  var nowMeta = document.getElementById("nowMeta");
  var toastEl = document.getElementById("toast");

  var playBtn = document.getElementById("playBtn");
  var progress = document.getElementById("progress");
  var curTime = document.getElementById("curTime");
  var durTime = document.getElementById("durTime");
  var volume = document.getElementById("volume");
  var speed = document.getElementById("speed");
  var fsBtn = document.getElementById("fsBtn");
  var downloadBtn = document.getElementById("downloadBtn");
  var refreshBtn = document.getElementById("refreshBtn");
  var logoutBtn = document.getElementById("logoutBtn");
  var stage = document.getElementById("stage");

  var current = null;

  function toast(msg) {
    toastEl.textContent = msg;
    toastEl.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { toastEl.hidden = true; }, 2600);
  }

  function fmtSize(bytes) {
    if (!bytes && bytes !== 0) return "-";
    var units = ["B", "KB", "MB", "GB"];
    var i = 0, n = Number(bytes);
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return n.toFixed(i === 0 ? 0 : 1) + " " + units[i];
  }

  function fmtTime(sec) {
    if (!isFinite(sec) || sec < 0) sec = 0;
    var s = Math.floor(sec % 60);
    var m = Math.floor((sec / 60) % 60);
    var h = Math.floor(sec / 3600);
    var mm = h > 0 ? String(m).padStart(2, "0") : String(m);
    var ss = String(s).padStart(2, "0");
    return h > 0 ? h + ":" + mm + ":" + ss : mm + ":" + ss;
  }

  function videoUrl(path) {
    return "/api/recordings/file?path=" + encodeURIComponent(path);
  }

  function selectItem(item, node) {
    current = item;
    Array.prototype.forEach.call(listEl.querySelectorAll(".pb-item"), function (n) {
      n.classList.remove("is-active");
    });
    if (node) node.classList.add("is-active");

    player.src = videoUrl(item.path);
    player.load();
    controls.hidden = false;
    nowMeta.hidden = false;
    nowMeta.innerHTML = "正在播放：<b>" + escapeHtml(item.name) + "</b>";
    downloadBtn.href = videoUrl(item.path);
    downloadBtn.setAttribute("download", item.name);
    player.play().catch(function () { /* 自动播放被拦截时由用户手动点击 */ });
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function renderList(items) {
    listEl.innerHTML = "";
    if (!items.length) {
      listEmpty.hidden = false;
      listMeta.textContent = "没有找到 MP4 文件";
      return;
    }
    listEmpty.hidden = true;
    listMeta.textContent = "共 " + items.length + " 个文件";
    items.forEach(function (item) {
      var li = document.createElement("li");
      li.className = "pb-item";
      li.innerHTML =
        '<div class="pb-item-name"></div>' +
        '<div class="pb-item-sub"><span class="sz"></span><span class="mt"></span></div>' +
        '<div class="pb-item-path"></div>';
      li.querySelector(".pb-item-name").textContent = item.name;
      li.querySelector(".sz").textContent = fmtSize(item.size);
      li.querySelector(".mt").textContent = item.mtime || "";
      li.querySelector(".pb-item-path").textContent = item.path;
      li.addEventListener("click", function () { selectItem(item, li); });
      listEl.appendChild(li);
    });
  }

  function loadList() {
    listMeta.textContent = "加载中…";
    fetch("/api/recordings", { credentials: "same-origin" })
      .then(function (res) {
        if (res.status === 401) { location.href = "/login"; return null; }
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) {
        if (!data) return;
        if (!data.ok) throw new Error(data.error || "加载失败");
        renderList(data.data || []);
      })
      .catch(function (err) {
        listMeta.textContent = "加载失败";
        toast("获取录制列表失败：" + err.message);
      });
  }

  // ---- 播放控制 ----
  playBtn.addEventListener("click", function () {
    if (player.paused) { player.play(); } else { player.pause(); }
  });

  player.addEventListener("play", function () { playBtn.textContent = "暂停"; });
  player.addEventListener("pause", function () { playBtn.textContent = "播放"; });

  player.addEventListener("loadedmetadata", function () {
    durTime.textContent = fmtTime(player.duration);
  });

  player.addEventListener("timeupdate", function () {
    curTime.textContent = fmtTime(player.currentTime);
    if (player.duration) {
      progress.value = String(Math.floor((player.currentTime / player.duration) * 1000));
    }
  });

  progress.addEventListener("input", function () {
    if (player.duration) {
      player.currentTime = (Number(progress.value) / 1000) * player.duration;
    }
  });

  volume.addEventListener("input", function () {
    player.volume = Number(volume.value) / 100;
    player.muted = player.volume === 0;
  });

  speed.addEventListener("change", function () {
    player.playbackRate = Number(speed.value);
  });

  player.addEventListener("error", function () {
    if (player.src) toast("视频加载失败，可能文件正在写入或已损坏");
  });

  fsBtn.addEventListener("click", function () {
    var el = document.fullscreenElement ? document : stage;
    var target = stage;
    if (!document.fullscreenElement) {
      (target.requestFullscreen || target.webkitRequestFullscreen || function () {}).call(target);
    } else {
      (document.exitFullscreen || document.webkitExitFullscreen || function () {}).call(document);
    }
  });

  refreshBtn.addEventListener("click", loadList);

  logoutBtn.addEventListener("click", function () {
    fetch("/api/logout", { method: "POST", credentials: "same-origin" })
      .then(function () { location.href = "/login"; })
      .catch(function () { location.href = "/login"; });
  });

  loadList();
})();
