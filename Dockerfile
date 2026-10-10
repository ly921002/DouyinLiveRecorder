# syntax=docker/dockerfile:1

FROM python:3.11-slim

LABEL org.opencontainers.image.title="DouyinLiveRecorder" \
      org.opencontainers.image.description="Multi-platform live stream recorder (Douyin/TikTok/Bilibili and 40+ platforms)" \
      org.opencontainers.image.source="https://github.com/ihmily/DouyinLiveRecorder" \
      org.opencontainers.image.licenses="MIT"

# PYTHONUNBUFFERED: 让 print/loguru 实时输出到 `docker logs`
# DEBIAN_FRONTEND:   避免 tzdata 交互式配置卡住构建
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai \
    DEBIAN_FRONTEND=noninteractive \
    TERM=xterm-256color

# uv 固定使用镜像自带的 python3.11，禁止联网下载解释器
ENV UV_PYTHON=3.11 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    PROXYCHAINS_CONF_FILE=/etc/proxychains.conf

# NodeSource 主版本号，构建时可用 --build-arg NODE_MAJOR=18 覆盖
ARG NODE_MAJOR=20

WORKDIR /app

# ---------------------------------------------------------------------------
# 1. 系统依赖（放在 COPY 之前，代码变动不会导致这一层重装）
# ---------------------------------------------------------------------------
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        tzdata \
        ffmpeg; \
    ln -fs "/usr/share/zoneinfo/${TZ}" /etc/localtime; \
    echo "${TZ}" > /etc/timezone; \
    rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 2. Node.js（PyExecJS 需要 JS 运行时来跑 x-bogus / haixiu 等签名脚本）
#    NodeSource 在 CI 环境偶发不可达，失败时自动回退到 Debian 官方源的 nodejs
# ---------------------------------------------------------------------------
RUN set -eux; \
    apt-get update; \
    (curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -) \
        || echo "[warn] NodeSource unavailable, fallback to distro nodejs"; \
    apt-get install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/*; \
    node --version

# ---------------------------------------------------------------------------
# 3. proxychains-ng（提供 proxychains4 命令）
#    Debian 官方源有该包时直接 apt 安装，否则回退到源码编译
# ---------------------------------------------------------------------------
RUN set -eux; \
    apt-get update; \
    if apt-get install -y --no-install-recommends proxychains-ng; then \
        echo "[info] proxychains-ng installed from apt"; \
    else \
        echo "[warn] proxychains-ng not in apt repo, build from source"; \
        apt-get install -y --no-install-recommends gcc make git; \
        git clone --depth 1 https://github.com/rofl0r/proxychains-ng /tmp/proxychains-ng; \
        cd /tmp/proxychains-ng; \
        ./configure --prefix=/usr --sysconfdir=/etc; \
        make -j"$(nproc)"; \
        make install; \
        make install-config; \
        cd /; rm -rf /tmp/proxychains-ng; \
    fi; \
    rm -rf /var/lib/apt/lists/*; \
    command -v proxychains4

# 仓库内的代理配置 → 镜像默认配置路径
COPY proxychains.conf /etc/proxychains.conf

# ---------------------------------------------------------------------------
# 4. uv + Python 依赖
#    uv 用于运行：proxychains4 uv run python main.py
#    这里预先 sync 出 /app/.venv，容器启动时就不必再联网装依赖
# ---------------------------------------------------------------------------
COPY pyproject.toml requirements.txt README.md /app/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir uv \
    && uv --version

RUN uv sync || (echo "[warn] uv sync failed, fallback to uv pip install" \
        && uv venv && uv pip install -r requirements.txt)

# 兜底：系统解释器也装上依赖，方便直接 `python main.py` 调试
RUN pip install --no-cache-dir -r /app/requirements.txt

# ---------------------------------------------------------------------------
# 5. 应用代码
# ---------------------------------------------------------------------------
COPY . /app

# uv 已预装好依赖，运行时不再尝试联网同步（避免启动时卡在解析依赖）
ENV UV_NO_SYNC=1

# 预建数据目录，避免挂载前目录属主异常
RUN mkdir -p /app/logs /app/downloads /app/backup_config

VOLUME ["/app/config", "/app/logs", "/app/downloads", "/app/backup_config"]

CMD ["proxychains4", "uv", "run", "python", "main.py"]
