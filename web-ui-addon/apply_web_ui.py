# -*- coding: utf-8 -*-
"""把 DouyinLiveRecorder 的 Web 管理界面增量包套用到已有的原版源码目录。

用法：
    python apply_web_ui.py <目标仓库根目录>

示例：
    python apply_web_ui.py D:/code/DouyinLiveRecorder

执行内容：
    1. 复制 web/（Web 服务端与前端静态资源）与 tests/（单元测试）
    2. 用 git apply --3way 打补丁：
       - main.py            （必需：启动 Web 服务、运行时快照、空配置不阻塞）
       - docker-compose.yaml（可选：容器内启用 Web 并映射回环端口）
       - README.md          （可选：补充 Web 使用说明）
    3. 打印后续启动与访问方式
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PATCH_DIR = os.path.join(HERE, "patches")

REQUIRED_PATCH = "main.py.patch"
OPTIONAL_PATCHES = ("docker-compose.yaml.patch", "README.md.patch")


def run(cmd: list[str], cwd: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return 127, "命令不存在：{0}".format(cmd[0])
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def copy_tree(name: str, target_root: str) -> None:
    src = os.path.join(HERE, name)
    if not os.path.isdir(src):
        print("[跳过] 增量包缺少目录：{0}".format(name))
        return
    dst = os.path.join(target_root, name)
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    count = sum(len(files) for _root, _dirs, files in os.walk(dst))
    print("[完成] 已部署 {0}/ （{1} 个文件）".format(name, count))


def apply_patch(patch_name: str, target_root: str, required: bool) -> bool:
    patch_path = os.path.join(PATCH_DIR, patch_name)
    if not os.path.isfile(patch_path):
        print("[警告] 补丁不存在：{0}".format(patch_name))
        return not required
    code, output = run(["git", "apply", "--3way", "--ignore-whitespace", patch_path], target_root)
    if code == 0:
        print("[完成] 已应用补丁：{0}".format(patch_name))
        return True
    code2, output2 = run(["git", "apply", "--ignore-whitespace", patch_path], target_root)
    if code2 == 0:
        print("[完成] 已应用补丁：{0}".format(patch_name))
        return True
    print("[失败] 补丁 {0} 应用失败（退出码 {1}）".format(patch_name, code))
    if output:
        print(output[:1200])
    if required:
        print("        main.py 补丁是 Web 功能的关键，请手动合并或先同步到 v4.0.7 原版代码后重试。")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="部署 DouyinLiveRecorder Web 管理界面增量包")
    parser.add_argument("target", help="原版源码仓库根目录（包含 main.py 与 config 目录）")
    parser.add_argument("--skip-patches", action="store_true", help="只复制文件，不打补丁")
    args = parser.parse_args()

    target_root = os.path.abspath(args.target)
    if not os.path.isfile(os.path.join(target_root, "main.py")):
        print("目标目录中没有 main.py，请确认路径：{0}".format(target_root))
        return 2
    if not os.path.isdir(os.path.join(target_root, "config")):
        print("目标目录中没有 config 目录，请确认路径：{0}".format(target_root))
        return 2

    print("目标仓库：{0}".format(target_root))
    copy_tree("web", target_root)
    copy_tree("tests", target_root)

    ok = True
    if not args.skip_patches:
        ok = apply_patch(REQUIRED_PATCH, target_root, required=True)
        for patch_name in OPTIONAL_PATCHES:
            apply_patch(patch_name, target_root, required=False)

    print("")
    if ok:
        print("部署完成。启动录制程序后访问：http://127.0.0.1:8080")
        print("首次运行会自动在 config/config.ini 末尾创建 [Web] 小节（启用=是、127.0.0.1、8080）。")
        print("可选环境变量：DLR_WEB_ENABLED / DLR_WEB_HOST / DLR_WEB_PORT")
    else:
        print("文件已复制，但补丁未全部应用，请按上面的提示手动合并后再启动。")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
