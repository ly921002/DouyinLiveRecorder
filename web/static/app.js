/* DouyinLiveRecorder 嵌入式管理界面交互逻辑（无外部依赖） */
(function () {
  "use strict";

  var POLL_INTERVAL = 5000;
  var THEME_KEY = "dlr-web-theme";
  var COLLAPSE_KEY = "dlr-web-collapsed";

  var state = {
    view: "overview",
    status: null,
    rooms: [],
    fields: [],
    cookies: { fields: [], reveal: false },
    cookieCheck: {},
    cookieRows: [],
    logs: { lines: [] },
    system: null,
    polling: true,
    logAuto: false,
    keyword: "",
    filter: "all"
  };

  var dom = {
    app: document.getElementById("app"),
    nav: document.getElementById("nav"),
    sidebar: document.getElementById("sidebar"),
    scrim: document.getElementById("scrim"),
    viewTitle: document.getElementById("viewTitle"),
    viewSub: document.getElementById("viewSub"),
    liveDot: document.getElementById("liveDot"),
    pollMeta: document.getElementById("pollMeta"),
    themeBtn: document.getElementById("themeBtn"),
    logoutBtn: document.getElementById("logoutBtn"),
    collapseBtn: document.getElementById("collapseBtn"),
    drawerBtn: document.getElementById("drawerBtn"),
    sideVersion: document.getElementById("sideVersion"),
    statGrid: document.getElementById("statGrid"),
    countRecording: document.getElementById("countRecording"),
    countMonitoring: document.getElementById("countMonitoring"),
    countDisabled: document.getElementById("countDisabled"),
    listRecording: document.getElementById("listRecording"),
    listMonitoring: document.getElementById("listMonitoring"),
    listDisabled: document.getElementById("listDisabled"),
    roomSearch: document.getElementById("roomSearch"),
    roomFilter: document.getElementById("roomFilter"),
    roomRows: document.getElementById("roomRows"),
    roomEmpty: document.getElementById("roomEmpty"),
    refreshRoomsBtn: document.getElementById("refreshRoomsBtn"),
    addRoomBtn: document.getElementById("addRoomBtn"),
    settingsForm: document.getElementById("settingsForm"),
    cookieList: document.getElementById("cookieList"),
    cookieSearch: document.getElementById("cookieSearch"),
    cookieOnlyFilled: document.getElementById("cookieOnlyFilled"),
    cookieOnlyInvalid: document.getElementById("cookieOnlyInvalid"),
    cookieMeta: document.getElementById("cookieMeta"),
    cookieEmpty: document.getElementById("cookieEmpty"),
    cookieAlert: document.getElementById("cookieAlert"),
    refreshCookiesBtn: document.getElementById("refreshCookiesBtn"),
    revealCookiesBtn: document.getElementById("revealCookiesBtn"),
    saveSettingsBtn: document.getElementById("saveSettingsBtn"),
    resetSettingsBtn: document.getElementById("resetSettingsBtn"),
    logBox: document.getElementById("logBox"),
    logAuto: document.getElementById("logAuto"),
    logLimit: document.getElementById("logLimit"),
    logMeta: document.getElementById("logMeta"),
    refreshLogsBtn: document.getElementById("refreshLogsBtn"),
    systemGrid: document.getElementById("systemGrid"),
    systemDetail: document.getElementById("systemDetail"),
    toastWrap: document.getElementById("toastWrap"),
    modal: document.getElementById("modal"),
    modalTitle: document.getElementById("modalTitle"),
    modalBody: document.getElementById("modalBody"),
    modalOkBtn: document.getElementById("modalOkBtn"),
    modalCancelBtn: document.getElementById("modalCancelBtn"),
    modalCloseBtn: document.getElementById("modalCloseBtn")
  };

  var VIEW_TITLES = {
    overview: "总览",
    rooms: "直播间",
    settings: "录制设置",
    cookies: "Cookie 设置",
    logs: "运行日志",
    system: "系统信息"
  };

  var STATUS_TEXT = {
    recording: "录制中",
    monitoring: "监测中",
    idle: "待监测",
    disabled: "已禁用"
  };

  /* ---------------------------------------------------------- 基础工具 */

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function toast(message, kind) {
    var node = el("div", "toast" + (kind ? " is-" + kind : ""), message);
    dom.toastWrap.appendChild(node);
    window.setTimeout(function () {
      if (node.parentNode) {
        node.parentNode.removeChild(node);
      }
    }, 3200);
  }

  function formatDuration(seconds) {
    var total = Math.max(0, parseInt(seconds, 10) || 0);
    var days = Math.floor(total / 86400);
    var hours = Math.floor((total % 86400) / 3600);
    var minutes = Math.floor((total % 3600) / 60);
    var parts = [];
    if (days > 0) {
      parts.push(days + " 天");
    }
    parts.push(hours + " 小时");
    parts.push(minutes + " 分");
    return parts.join(" ");
  }

  function formatBytes(bytes) {
    var value = Number(bytes) || 0;
    if (value >= 1024 * 1024 * 1024) {
      return (value / (1024 * 1024 * 1024)).toFixed(2) + " GB";
    }
    if (value >= 1024 * 1024) {
      return (value / (1024 * 1024)).toFixed(1) + " MB";
    }
    return Math.max(0, Math.round(value / 1024)) + " KB";
  }

  /* ---------------------------------------------------------- 接口请求 */

  function requestError(message) {
    var error = new Error(message);
    error.userMessage = message;
    return error;
  }

  function api(path, options) {
    var config = options || {};
    var init = {
      method: config.method || "GET",
      headers: { Accept: "application/json" },
      cache: "no-store"
    };
    if (config.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(config.body);
    }
    return fetch(path, init).then(function (response) {
      return response.text().then(function (raw) {
        var payload = null;
        try {
          payload = raw ? JSON.parse(raw) : {};
        } catch (err) {
          throw requestError("服务端返回了无法解析的内容");
        }
        if (!response.ok || payload.ok === false) {
          throw requestError(payload && payload.error ? payload.error : "请求失败，状态码 " + response.status);
        }
        return payload;
      });
    });
  }

  /* ---------------------------------------------------------- 弹窗 */

  var modalHandler = null;

  function closeModal() {
    dom.modal.hidden = true;
    clear(dom.modalBody);
    modalHandler = null;
  }

  function openModal(config) {
    dom.modalTitle.textContent = config.title || "操作";
    clear(dom.modalBody);
    if (typeof config.render === "function") {
      config.render(dom.modalBody);
    } else if (config.message) {
      dom.modalBody.appendChild(el("p", "modal-text", config.message));
    }
    dom.modalOkBtn.textContent = config.okText || "确定";
    dom.modalOkBtn.className = "btn " + (config.danger ? "btn-danger" : "btn-primary");
    dom.modalCancelBtn.hidden = !!config.hideCancel;
    modalHandler = config.onOk || null;
    dom.modal.hidden = false;
  }

  function showConfirm(title, message, onOk, okText, danger) {
    openModal({
      title: title,
      message: message,
      okText: okText || "确定",
      danger: !!danger,
      onOk: onOk
    });
  }

  dom.modalOkBtn.addEventListener("click", function () {
    var handler = modalHandler;
    if (!handler) {
      closeModal();
      return;
    }
    var result = handler();
    if (result === false) {
      return;
    }
    if (result && typeof result.then === "function") {
      result.then(function () {
        closeModal();
      }).catch(function (error) {
        toast(error.userMessage || error.message || "操作失败", "error");
      });
      return;
    }
    closeModal();
  });

  dom.modalCancelBtn.addEventListener("click", closeModal);
  dom.modalCloseBtn.addEventListener("click", closeModal);

  /* ---------------------------------------------------------- 主题与布局 */

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    dom.themeBtn.textContent = theme === "dark" ? "亮色" : "暗色";
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch (err) {
      /* 忽略隐私模式下的存储失败 */
    }
  }

  function initTheme() {
    var saved = "light";
    try {
      saved = window.localStorage.getItem(THEME_KEY) || "light";
    } catch (err) {
      saved = "light";
    }
    applyTheme(saved === "dark" ? "dark" : "light");
  }

  function initLayout() {
    var collapsed = false;
    try {
      collapsed = window.localStorage.getItem(COLLAPSE_KEY) === "1";
    } catch (err) {
      collapsed = false;
    }
    dom.app.classList.toggle("is-collapsed", collapsed);
  }

  dom.themeBtn.addEventListener("click", function () {
    var current = document.documentElement.getAttribute("data-theme");
    applyTheme(current === "dark" ? "light" : "dark");
  });

  if (dom.logoutBtn) {
    dom.logoutBtn.addEventListener("click", function () {
      fetch("/api/logout", { method: "POST" })
        .catch(function () { /* 忽略网络错误，仍然跳转登录页 */ })
        .then(function () { window.location.replace("/login"); });
    });
  }

  dom.collapseBtn.addEventListener("click", function () {
    var collapsed = dom.app.classList.toggle("is-collapsed");
    try {
      window.localStorage.setItem(COLLAPSE_KEY, collapsed ? "1" : "0");
    } catch (err) {
      /* 忽略 */
    }
  });

  dom.drawerBtn.addEventListener("click", function () {
    var opened = dom.app.classList.toggle("is-drawer-open");
    dom.scrim.hidden = !opened;
  });

  dom.scrim.addEventListener("click", function () {
    dom.app.classList.remove("is-drawer-open");
    dom.scrim.hidden = true;
  });

  /* ---------------------------------------------------------- 视图切换 */

  function switchView(view) {
    state.view = view;
    var views = document.querySelectorAll(".view");
    for (var i = 0; i < views.length; i++) {
      views[i].classList.toggle("is-active", views[i].getAttribute("data-view") === view);
    }
    var items = dom.nav.querySelectorAll(".nav-item");
    for (var j = 0; j < items.length; j++) {
      items[j].classList.toggle("is-active", items[j].getAttribute("data-view") === view);
    }
    dom.viewTitle.textContent = VIEW_TITLES[view] || view;
    dom.app.classList.remove("is-drawer-open");
    dom.scrim.hidden = true;
    if (view === "rooms") {
      loadRooms();
    } else if (view === "settings") {
      loadSettings();
    } else if (view === "cookies") {
      loadCookies();
    } else if (view === "logs") {
      loadLogs();
    } else if (view === "system") {
      loadSystem();
    } else {
      renderOverview();
    }
  }

  dom.nav.addEventListener("click", function (event) {
    var button = event.target.closest ? event.target.closest(".nav-item") : null;
    if (button) {
      switchView(button.getAttribute("data-view"));
    }
  });

  /* ---------------------------------------------------------- 总览 */

  function recordingMatchesRoom(label, room) {
    var key = String(label || "").trim();
    var name = String(room.name || "").trim();
    var url = String(room.url || "").trim();
    if (url && key === url) {
      return true;
    }
    if (!name) {
      return false;
    }
    return key === name || key.slice(-(name.length + 1)) === " " + name;
  }

  function roomStatus(room, status) {
    if (room.disabled) {
      return "disabled";
    }
    var names = Object.keys((status && status.recording) || {});
    var times = Object.keys((status && status.recording_time_list) || {});
    var keys = names.concat(times);
    for (var i = 0; i < keys.length; i++) {
      if (recordingMatchesRoom(keys[i], room)) {
        return "recording";
      }
    }
    var running = (status && status.running_list) || [];
    if (running.indexOf(room.url) >= 0) {
      return "monitoring";
    }
    return "idle";
  }

  function statCard(label, value, foot, tone) {
    var card = el("div", "card stat-card");
    card.appendChild(el("div", "stat-label", label));
    var valueNode = el("div", "stat-value", value);
    if (tone) {
      valueNode.style.color = "var(--" + tone + ")";
    }
    card.appendChild(valueNode);
    if (foot) {
      card.appendChild(el("div", "stat-foot", foot));
    }
    return card;
  }

  function renderBoard(container, rooms, emptyText) {
    clear(container);
    if (!rooms.length) {
      container.appendChild(el("p", "empty", emptyText));
      return;
    }
    rooms.forEach(function (room) {
      var item = el("div", "board-item");
      item.appendChild(el("div", "board-item-title", room.name || "未命名直播间"));
      var meta = "[" + room.quality + "] 行号 " + room.line_id;
      item.appendChild(el("div", "board-item-meta", meta));
      item.appendChild(el("div", "board-item-meta", room.url));
      container.appendChild(item);
    });
  }

  function renderRuntimeRecordings(container, status, rooms) {
    clear(container);
    var recordings = (status && status.recording) || {};
    var labels = Object.keys(recordings);
    if (!labels.length) {
      container.appendChild(el("p", "empty", "当前没有正在录制的直播间"));
      return;
    }
    labels.forEach(function (label) {
      var detail = recordings[label] || {};
      var room = rooms.find(function (candidate) {
        return recordingMatchesRoom(label, candidate);
      });
      var displayName = room && room.name ? room.name : label.replace(/^序号\d+\s*/, "");
      var item = el("div", "board-item");
      item.appendChild(el("div", "board-item-title", displayName || label));
      var meta = detail.quality ? "[" + detail.quality + "]" : "录制进行中";
      if (detail.start_time) {
        meta += " | 开始于 " + detail.start_time;
      }
      item.appendChild(el("div", "board-item-meta", meta));
      if (room && room.url) {
        item.appendChild(el("div", "board-item-meta", room.url));
      }
      container.appendChild(item);
    });
  }

  function renderOverview() {
    var status = state.status || {};
    var rooms = state.rooms || [];
    var recordingLabels = Object.keys(status.recording || {});
    var monitoring = rooms.filter(function (room) {
      return roomStatus(room, status) === "monitoring";
    });
    var disabled = rooms.filter(function (room) {
      return room.disabled;
    });

    clear(dom.statGrid);
    dom.statGrid.appendChild(statCard("直播间总数", rooms.length, "已禁用 " + disabled.length));
    dom.statGrid.appendChild(statCard("监测中", monitoring.length, "线程数 " + (status.max_request || 0)));
    dom.statGrid.appendChild(statCard("录制中", recordingLabels.length, "实时运行状态", "danger"));
    dom.statGrid.appendChild(statCard("瞬时错误数", status.error_count || 0, "运行时长 " + formatDuration(status.uptime_seconds)));

    dom.countRecording.textContent = recordingLabels.length;
    dom.countMonitoring.textContent = monitoring.length;
    dom.countDisabled.textContent = disabled.length;

    renderRuntimeRecordings(dom.listRecording, status, rooms);
    renderBoard(dom.listMonitoring, monitoring, "当前没有监测中的直播间");
    renderBoard(dom.listDisabled, disabled, "没有被禁用的直播间");
  }

  /* ---------------------------------------------------------- 直播间 */

  function statusBadge(statusKey) {
    var node = el("span", "badge badge-" + statusKey, STATUS_TEXT[statusKey] || statusKey);
    return node;
  }

  function renderRooms() {
    var keyword = state.keyword.trim().toLowerCase();
    var status = state.status || {};
    var rows = state.rooms.filter(function (room) {
      if (state.filter !== "all" && roomStatus(room, status) !== state.filter) {
        return false;
      }
      if (!keyword) {
        return true;
      }
      var haystack = ((room.name || "") + " " + (room.url || "")).toLowerCase();
      return haystack.indexOf(keyword) >= 0;
    });

    clear(dom.roomRows);
    if (!rows.length) {
      dom.roomEmpty.hidden = false;
      return;
    }
    dom.roomEmpty.hidden = true;

    rows.forEach(function (room) {
      var statusKey = roomStatus(room, status);
      var tr = el("tr");
      tr.appendChild(el("td", null, room.line_id));

      var nameCell = el("td");
      nameCell.appendChild(el("div", null, room.name || "未命名"));
      nameCell.appendChild(el("span", "badge badge-platform", room.platform || "未知平台"));
      tr.appendChild(nameCell);

      var urlCell = el("td");
      urlCell.appendChild(el("div", "cell-url", room.url));
      tr.appendChild(urlCell);

      tr.appendChild(el("td", null, room.quality));

      var statusCell = el("td");
      statusCell.appendChild(statusBadge(statusKey));
      tr.appendChild(statusCell);

      var ops = el("td");
      var opsWrap = el("div", "ops");

      var editBtn = el("button", "btn btn-ghost", "编辑");
      editBtn.type = "button";
      editBtn.addEventListener("click", function () {
        openRoomForm(room);
      });

      var toggleBtn = el("button", "btn btn-ghost", room.disabled ? "启用" : "停用");
      toggleBtn.type = "button";
      toggleBtn.addEventListener("click", function () {
        var enabled = room.disabled;
        showConfirm(
          enabled ? "启用直播间" : "停用直播间",
          (enabled ? "启用后将继续监测：" : "停用后将停止监测与录制：") + (room.name || room.url),
          function () {
            return api("/api/rooms/" + room.line_id, {
              method: "PUT",
              body: { disabled: !enabled }
            }).then(function () {
              toast(enabled ? "已启用该直播间" : "已停用该直播间", "success");
              return loadRooms();
            });
          },
          enabled ? "启用" : "停用",
          !enabled
        );
      });

      var delBtn = el("button", "btn btn-ghost", "删除");
      delBtn.type = "button";
      delBtn.addEventListener("click", function () {
        showConfirm(
          "删除直播间",
          "确定删除第 " + room.line_id + " 行的直播间配置吗？该操作会写入 URL_config.ini。",
          function () {
            return api("/api/rooms/" + room.line_id, { method: "DELETE" }).then(function () {
              toast("已删除该直播间", "success");
              return loadRooms();
            });
          },
          "删除",
          true
        );
      });

      opsWrap.appendChild(editBtn);
      opsWrap.appendChild(toggleBtn);
      opsWrap.appendChild(delBtn);
      ops.appendChild(opsWrap);
      tr.appendChild(ops);
      dom.roomRows.appendChild(tr);
    });
  }

  function openRoomForm(room) {
    var isEdit = !!room;
    var fields = {};

    openModal({
      title: isEdit ? "编辑直播间（第 " + room.line_id + " 行）" : "添加直播间",
      okText: isEdit ? "保存" : "添加",
      render: function (container) {
        function addField(label, node, desc) {
          var wrap = el("div", "modal-field");
          wrap.appendChild(el("label", "field-label", label));
          wrap.appendChild(node);
          if (desc) {
            wrap.appendChild(el("span", "field-desc", desc));
          }
          container.appendChild(wrap);
        }

        var urlInput = el("input", "input");
        urlInput.type = "text";
        urlInput.placeholder = "https://live.douyin.com/745964462470";
        urlInput.value = isEdit ? room.url : "";
        fields.url = urlInput;

        var nameInput = el("input", "input");
        nameInput.type = "text";
        nameInput.placeholder = "可留空，默认使用直播间标题";
        nameInput.value = isEdit ? room.name : "";
        fields.name = nameInput;

        var qualitySelect = el("select", "select");
        ["原画", "蓝光", "超清", "高清", "标清", "流畅"].forEach(function (item) {
          var option = el("option", null, item);
          option.value = item;
          if (isEdit && room.quality === item) {
            option.selected = true;
          }
          qualitySelect.appendChild(option);
        });
        fields.quality = qualitySelect;

        var disabledSelect = el("select", "select");
        [["no", "启用监测"], ["yes", "停用（行首加 #）"]].forEach(function (pair) {
          var option = el("option", null, pair[1]);
          option.value = pair[0];
          if (isEdit && room.disabled === (pair[0] === "yes")) {
            option.selected = true;
          }
          disabledSelect.appendChild(option);
        });
        fields.disabled = disabledSelect;

        addField("直播间地址", urlInput);
        addField("主播名", nameInput, "兼容“主播: 主播名”写法，保存时会去掉前缀");
        addField("录制画质", qualitySelect);
        addField("监测状态", disabledSelect);
      },
      onOk: function () {
        var payload = {
          url: fields.url.value.trim(),
          name: fields.name.value.trim(),
          quality: fields.quality.value,
          disabled: fields.disabled.value === "yes"
        };
        if (!payload.url) {
          toast("请填写直播间地址", "error");
          return false;
        }
        var promise = isEdit
          ? api("/api/rooms/" + room.line_id, { method: "PUT", body: payload })
          : api("/api/rooms", { method: "POST", body: payload });
        return promise.then(function () {
          toast(isEdit ? "直播间已更新" : "直播间已添加", "success");
          return loadRooms();
        });
      }
    });
  }

  function loadRooms() {
    return api("/api/rooms").then(function (payload) {
      state.rooms = payload.data || [];
      renderRooms();
      renderOverview();
    }).catch(function (error) {
      toast(error.userMessage || "直播间列表加载失败", "error");
    });
  }

  dom.roomSearch.addEventListener("input", function () {
    state.keyword = dom.roomSearch.value;
    renderRooms();
  });

  dom.roomFilter.addEventListener("change", function () {
    state.filter = dom.roomFilter.value;
    renderRooms();
  });

  dom.refreshRoomsBtn.addEventListener("click", function () {
    loadRooms();
  });

  dom.addRoomBtn.addEventListener("click", function () {
    openRoomForm(null);
  });

  /* ---------------------------------------------------------- 录制设置 */

  function buildField(meta) {
    var wrap = el("div", "field" + (meta.danger ? " is-danger" : ""));
    var label = el("label", "field-label", meta.label);
    if (meta.danger) {
      var tag = el("span", "tag-danger", "谨慎修改");
      label.appendChild(tag);
    }
    wrap.appendChild(label);

    var input;
    if (meta.type === "boolean") {
      var switchWrap = el("label", "switch");
      input = document.createElement("input");
      input.type = "checkbox";
      input.checked = !!meta.value;
      switchWrap.appendChild(input);
      switchWrap.appendChild(el("span", null, input.checked ? "是" : "否"));
      input.addEventListener("change", function () {
        switchWrap.lastChild.textContent = input.checked ? "是" : "否";
      });
      wrap.appendChild(switchWrap);
    } else if (meta.type === "select") {
      input = el("select", "select");
      (meta.options || []).forEach(function (option) {
        var node = el("option", null, option);
        node.value = option;
        if (option === meta.value) {
          node.selected = true;
        }
        input.appendChild(node);
      });
      wrap.appendChild(input);
    } else {
      input = el("input", "input");
      input.type = meta.type === "string" ? "text" : "number";
      input.value = meta.value === null || meta.value === undefined ? "" : String(meta.value);
      if (meta.type !== "string") {
        if (meta.min !== null && meta.min !== undefined) {
          input.min = String(meta.min);
        }
        if (meta.max !== null && meta.max !== undefined) {
          input.max = String(meta.max);
        }
      }
      wrap.appendChild(input);
    }

    wrap.appendChild(el("span", "field-desc", meta.description || ""));
    wrap.input = input;
    wrap.meta = meta;
    return wrap;
  }

  function renderSettings() {
    clear(dom.settingsForm);
    state.settings = [];
    state.fields.forEach(function (meta) {
      var node = buildField(meta);
      dom.settingsForm.appendChild(node);
      state.settings.push(node);
    });
  }

  function loadSettings() {
    return api("/api/config").then(function (payload) {
      state.fields = (payload.data && payload.data.fields) || [];
      renderSettings();
    }).catch(function (error) {
      toast(error.userMessage || "录制设置加载失败", "error");
    });
  }

  function collectSettings() {
    var values = {};
    state.settings.forEach(function (node) {
      var meta = node.meta;
      var input = node.input;
      if (meta.type === "boolean") {
        values[meta.option] = input.checked ? "是" : "否";
      } else if (meta.type === "integer" || meta.type === "number") {
        values[meta.option] = input.value === "" ? meta.default : Number(input.value);
      } else {
        values[meta.option] = input.value;
      }
    });
    return values;
  }

  dom.saveSettingsBtn.addEventListener("click", function () {
    var values = collectSettings();
    dom.saveSettingsBtn.disabled = true;
    api("/api/config", { method: "PUT", body: { values: values } }).then(function (payload) {
      toast(payload.message || "配置已保存", "success");
      return loadSettings();
    }).catch(function (error) {
      toast(error.userMessage || "配置保存失败", "error");
    }).then(function () {
      dom.saveSettingsBtn.disabled = false;
    });
  });

  dom.resetSettingsBtn.addEventListener("click", function () {
    loadSettings();
  });

  /* ---------------------------------------------------------- Cookie 设置 */

  function cookieMatches(item) {
    var keyword = (dom.cookieSearch.value || "").trim().toLowerCase();
    if (dom.cookieOnlyFilled.checked && !item.has_value) {
      return false;
    }
    if (dom.cookieOnlyInvalid && dom.cookieOnlyInvalid.checked && item.check_status !== "invalid") {
      return false;
    }
    if (!keyword) {
      return true;
    }
    var haystack = ((item.label || "") + " " + (item.key || "")).toLowerCase();
    return haystack.indexOf(keyword) >= 0;
  }

  var COOKIE_STATUS_CLASS = {
    valid: "badge-monitoring",   // 绿：有效
    invalid: "badge-recording",  // 红：失效
    unknown: "badge-platform",   // 蓝：未适配专用接口，无法判定
    error: "badge-idle"          // 橙：网络异常/超时，不视为失效
  };

  function cookieStatusBadge(item) {
    if (!item.check_status) {
      return { cls: "badge", text: "未检测" };
    }
    return {
      cls: "badge " + (COOKIE_STATUS_CLASS[item.check_status] || "badge-platform"),
      text: item.check_status_text || item.check_status
    };
  }

  function formatCheckedAt(ts) {
    if (!ts) {
      return "";
    }
    var date = new Date(ts * 1000);
    if (isNaN(date.getTime())) {
      return "";
    }
    var pad = function (n) { return n < 10 ? "0" + n : "" + n; };
    return date.getFullYear() + "-" + pad(date.getMonth() + 1) + "-" + pad(date.getDate()) +
      " " + pad(date.getHours()) + ":" + pad(date.getMinutes());
  }

  function renderCookies() {
    clear(dom.cookieList);
    state.cookieRows = [];
    var fields = (state.cookies.fields || []).filter(cookieMatches);
    var revealed = !!state.cookies.reveal;

    dom.cookieAlert.hidden = !revealed;
    dom.revealCookiesBtn.textContent = revealed ? "隐藏明文" : "载入明文";
    var total = (state.cookies.fields || []).length;
    var filled = (state.cookies.fields || []).filter(function (item) {
      return item.has_value;
    }).length;
    dom.cookieMeta.textContent = "共 " + total + " 个平台，已填写 " + filled + " 个" + (revealed ? "（明文已载入）" : "");

    var check = state.cookieCheck || {};
    if (check.available) {
      var summary = check.summary || {};
      dom.cookieMeta.textContent += " · 检测于 " + (formatCheckedAt(check.updated_at) || "—") +
        "（有效 " + (summary.valid || 0) + " / 失效 " + (summary.invalid || 0) +
        " / 未知 " + (summary.unknown || 0) + " / 失败 " + (summary.error || 0) + "）";
    } else {
      dom.cookieMeta.textContent += " · 暂无检测结果";
    }

    if (!fields.length) {
      dom.cookieEmpty.hidden = false;
      return;
    }
    dom.cookieEmpty.hidden = true;

    fields.forEach(function (item) {
      var row = el("div", "cookie-item");

      var head = el("div", "cookie-head");
      head.appendChild(el("span", "cookie-label", item.label || item.key));
      head.appendChild(el("span", "badge badge-platform", item.key));
      head.appendChild(el("span", "badge" + (item.has_value ? " badge-monitoring" : ""),
        item.has_value ? "已填写 " + item.length + " 字符" : "未填写"));
      var status = cookieStatusBadge(item);
      var statusBadge = el("span", status.cls, status.text);
      if (item.check_detail) {
        statusBadge.title = item.check_detail +
          (item.check_at ? "（" + formatCheckedAt(item.check_at) + "）" : "");
      }
      head.appendChild(statusBadge);
      row.appendChild(head);

      var area = el("textarea", "input cookie-input");
      area.rows = 3;
      area.readOnly = !revealed;
      area.value = revealed ? (item.value || "") : (item.masked || "");
      area.placeholder = revealed ? "粘贴浏览器里复制的完整 Cookie" : "点击右上角“载入明文”后可编辑";
      row.appendChild(area);

      var ops = el("div", "ops");

      var saveBtn = el("button", "btn btn-primary", "保存");
      saveBtn.type = "button";
      saveBtn.disabled = !revealed;
      saveBtn.addEventListener("click", function () {
        saveCookie(item.key, area.value, revealed);
      });

      var clearBtn = el("button", "btn btn-ghost", "清空");
      clearBtn.type = "button";
      clearBtn.disabled = !revealed || !item.has_value;
      clearBtn.addEventListener("click", function () {
        showConfirm(
          "清空 Cookie",
          "确定清空“" + (item.label || item.key) + "”的 Cookie 吗？该操作会写入 config.ini。",
          function () {
            return saveCookie(item.key, "", revealed);
          },
          "清空",
          true
        );
      });

      ops.appendChild(saveBtn);
      ops.appendChild(clearBtn);
      row.appendChild(ops);
      dom.cookieList.appendChild(row);
      state.cookieRows.push(row);
    });
  }

  function saveCookie(key, value, revealed) {
    var payload = { values: {} };
    payload.values[key] = value;
    return api("/api/cookies", { method: "PUT", body: payload }).then(function (result) {
      toast(result.message || "Cookie 已保存", "success");
      return loadCookies(revealed);
    });
  }

  function loadCookies(reveal) {
    var url = "/api/cookies" + (reveal ? "?reveal=1" : "");
    return api(url).then(function (payload) {
      state.cookies = payload.data || { fields: [] };
      state.cookieCheck = payload.data.check || {};
      renderCookies();
    }).catch(function (error) {
      toast(error.userMessage || "Cookie 列表加载失败", "error");
    });
  }

  function loadCookieCheck() {
    return api("/api/cookie-check").then(function (payload) {
      state.cookieCheck = payload.data || {};
      renderCookies();
    }).catch(function () {
      /* 检测结果读不到不影响 Cookie 编辑，静默忽略 */
    });
  }

  dom.cookieSearch.addEventListener("input", renderCookies);
  dom.cookieOnlyFilled.addEventListener("change", renderCookies);
  if (dom.cookieOnlyInvalid) {
    dom.cookieOnlyInvalid.addEventListener("change", renderCookies);
  }
  dom.refreshCookiesBtn.addEventListener("click", function () {
    loadCookieCheck();
    loadCookies(!!state.cookies.reveal);
  });
  dom.revealCookiesBtn.addEventListener("click", function () {
    if (state.cookies.reveal) {
      loadCookies(false);
      return;
    }
    showConfirm(
      "载入明文 Cookie",
      "明文会显示在当前页面，请勿截图或共享屏幕。确认载入？",
      function () {
        return loadCookies(true);
      },
      "载入明文"
    );
  });

  /* ---------------------------------------------------------- 运行日志 */

  function renderLogs() {
    clear(dom.logBox);
    var lines = state.logs.lines || [];
    if (!lines.length) {
      dom.logBox.appendChild(el("span", "hint", "暂无日志记录"));
    } else {
      lines.forEach(function (line) {
        dom.logBox.appendChild(el("div", null, line));
      });
    }
    dom.logMeta.textContent = "共 " + lines.length + " 行，上限 " + (state.logs.max || 300) + " 行";
  }

  function loadLogs() {
    var limit = dom.logLimit.value || "100";
    return api("/api/logs?limit=" + encodeURIComponent(limit)).then(function (payload) {
      state.logs = payload.data || { lines: [] };
      renderLogs();
    }).catch(function (error) {
      toast(error.userMessage || "日志加载失败", "error");
    });
  }

  dom.logLimit.addEventListener("change", loadLogs);
  dom.refreshLogsBtn.addEventListener("click", loadLogs);
  dom.logAuto.addEventListener("change", function () {
    state.logAuto = dom.logAuto.checked;
  });

  /* ---------------------------------------------------------- 系统信息 */

  function renderSystem() {
    var info = state.system || {};
    clear(dom.systemGrid);
    dom.systemGrid.appendChild(statCard("应用版本", info.app_version || "-", "录制主程序版本"));
    dom.systemGrid.appendChild(statCard("Python 版本", info.python_version || "-", info.python_implementation || ""));
    dom.systemGrid.appendChild(statCard(
      "ffmpeg",
      info.ffmpeg_available ? "可用" : "不可用",
      info.ffmpeg_available ? "录制依赖已就绪" : "缺少 ffmpeg 无法录制",
      info.ffmpeg_available ? "success" : "danger"
    ));
    dom.systemGrid.appendChild(statCard("磁盘可用", (info.disk_free_gb || 0) + " GB", "总量 " + (info.disk_total_gb || 0) + " GB"));

    clear(dom.systemDetail);
    var items = [
      ["操作系统", (info.os_name || "-") + " " + (info.os_release || "")],
      ["CPU 架构", info.cpu_arch || "-"],
      ["CPU 核心数", info.cpu_count || "-"],
      ["Python 版本", info.python_version || "-"],
      ["ffmpeg 可用", info.ffmpeg_available ? "是" : "否"],
      ["磁盘总量", formatBytes(info.disk_total_bytes)],
      ["磁盘可用", formatBytes(info.disk_free_bytes)],
      ["已用空间", formatBytes(info.disk_used_bytes)]
    ];
    items.forEach(function (pair) {
      var row = el("div");
      row.appendChild(el("dt", null, pair[0]));
      row.appendChild(el("dd", null, pair[1]));
      dom.systemDetail.appendChild(row);
    });
  }

  function loadSystem() {
    return api("/api/system").then(function (payload) {
      state.system = payload.data || {};
      renderSystem();
    }).catch(function (error) {
      toast(error.userMessage || "系统信息加载失败", "error");
    });
  }

  /* ---------------------------------------------------------- 状态轮询 */

  function loadStatus() {
    return api("/api/status").then(function (payload) {
      state.status = payload.data || {};
      dom.liveDot.className = "live-dot";
      dom.viewSub.textContent = "录制中 " + Object.keys(state.status.recording || {}).length
        + " | 监测中 " + (state.status.monitoring || 0)
        + " | 运行时长 " + formatDuration(state.status.uptime_seconds);
      dom.sideVersion.textContent = "版本 " + (state.status.version || "-");
      renderOverview();
      renderRooms();
    }).catch(function (error) {
      dom.liveDot.className = "live-dot is-error";
      dom.viewSub.textContent = "状态获取失败：" + (error.userMessage || "未知错误");
    });
  }

  function startPolling() {
    loadStatus().then(function () {
      return loadRooms();
    }).then(function () {
      window.setInterval(function () {
        if (document.hidden) {
          return;
        }
        loadStatus();
        if (state.view === "rooms") {
          loadRooms();
        } else if (state.view === "logs" && state.logAuto) {
          loadLogs();
        }
      }, POLL_INTERVAL);
    });
  }

  dom.pollMeta.textContent = "每 " + (POLL_INTERVAL / 1000) + " 秒刷新";

  initTheme();
  initLayout();
  startPolling();
})();
