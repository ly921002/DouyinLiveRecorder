# -*- coding: utf-8 -*-
"""嵌入式 Web 管理界面。

仅依赖 Python 标准库，不引入任何第三方依赖。
本包中的任何模块都不得反向 import main，运行时状态通过回调函数注入。
"""

__version__ = "1.0.0"

__all__ = ["service", "server"]
