# NXShield — 自研安卓 APK 加固控制台

NXShield 是一个自研的 Android APK 加固工具，包含完整的加固流水线（DEX 解析、抽函数、NX-VM
虚拟化、敏感字符串加密、assets 加密）以及 WeKit 风格的四栏控制台（主页 / 功能 / 日志 / 设置）。
所有核心算法均为自行实现，不依赖第三方加固 SDK。

> 仅用于加固你拥有合法授权的应用。

## 目录结构

```
backend/
  main.py                 FastAPI 服务：上传 / 加固 / 任务 / 日志 / 历史
  engine/
    dex.py                DEX 解析器（header / string / type / proto / method / class / code）
    crypto.py             NXS1 封装：SHA-256 KDF + HMAC-SHA256 + 滚动 XOR（自逆）
    strings.py            敏感字符串识别与加密（中文 + vip/premium 等关键词）
    obfuscate.py          抽函数选取、标识符重命名、方法体替换
    vm.py                 Dalvik → NX 字节码翻译器 + 镜像编译
    assets.py             assets/ 加密为 .nxs
    manifest.py           二进制 AndroidManifest.xml 解析
    zipio.py              APK（ZIP）读写
    jni.py                生成抽函数的 JNI 桥接源码与报告
    logger.py             JSONL 运行日志 + 历史任务/启用记录
    packer.py             加固流水线编排
  stub/                   NXShield 运行时桩（Java）：解密、NX-VM 解释器、字符串表
  tests/                  单元测试 + 最小 DEX 构造器
frontend/
  src/App.vue             四栏导航（主页 / 功能 / 日志 / 设置）
  src/pages/              HomePage / FeaturesPage / LogsPage / SettingsPage
  src/api.js              REST + SSE 客户端
```

## 加固能力

| 能力 | 开关 | 说明 |
| --- | --- | --- |
| 抽函数 / 方法混淆 | `extract_methods` | 按比例选取方法，方法体替换为等长占位，原始字节码进入 NX-VM 镜像 |
| NX-VM 虚拟化 | `vm_protect` | 自研指令集翻译（CONST/MOVE/算术/分支/INVOKE/RETURN/CSTR 等），镜像加密存储 |
| 敏感字符串保护 | `string_protect` | 识别并加密字面量，运行时按 string-id 索引解密 |
| 中文字符串加密 | `encrypt_cjk` | 覆盖所有 CJK 字面量 |
| VIP / Premium 关键词 | `encrypt_vip_keywords` | 内置 vip、premium、pro、license、trial、unlock、paywall 等 |
| assets 加密 | `asset_encrypt` | `assets/**` 加密为 `.nxs`，运行时解密到私有目录 |
| 标识符重命名 | `name_obfuscate` | 种子哈希重写字符串池标识符（实验性） |
| 保留原始签名 | `keep_signature` | 关闭后移除 META-INF 原签名，需重新签名 |
| 加固元数据 | `inject_stub_meta` | 生成 `assets/nxshield/meta.json` |

## 产物

一次性产出四类内容：

1. `<name>-nxshield-<job>.apk` — 加固后的 APK
2. `<...>.apk.jni.c` — 抽函数的 JNI 桥接源码（自研，按方法自动生成）
3. `<...>.apk.report.md` — 抽函数报告（按类分布 + 方法清单）
4. 每个任务一份运行日志：`backend/data/logs/<job>.log` 与 `.jsonl`

APK 内新增载荷：

```
assets/nxshield/vm.bin           加密的 NX-VM 镜像
assets/nxshield/vm.index.json    加密的方法索引
assets/nxshield/<dex>.str        加密的字符串表
assets/nxshield/meta.json        加固特征与统计
assets/**.nxs                    加密后的资源
```

## 日志与历史

- **运行日志**：结构化 JSONL + 文本日志，记录每一步（读取、解析、抽函数、字符串、assets、输出）
  与启用/关闭动作。
- **启用记录**：功能开关的启用/关闭历史，带时间戳与来源。
- **任务历史**：`backend/data/history.json` 持久化，控制台「日志」页可查看、保存、下载。

## 本地运行

```bash
# 1. 安装后端依赖
pip install --break-system-packages -r backend/requirements.txt

# 2. 启动后端（8000）
cd backend && python3 -m uvicorn main:app --host 0.0.0.0 --port 8000

# 3. 安装并启动前端（5173，已配置 /api 反向代理）
cd frontend && npm install && npm run dev
```

或直接执行 `./start.sh`（同时拉起前后端）。

## 测试

```bash
cd backend && python3 -m unittest tests.test_engine -v
```

覆盖密码学自逆、敏感词判定、DEX 解析、字符串保护与完整加固流水线。

## 运行时接入

`backend/stub/com/nxshield/runtime/` 提供运行时桩：

- `NXShieldRuntime` 在 `Application.attachBaseContext` 调用 `install(context, key)`
- 解密 `assets/nxshield/**`、注册 NX-VM 镜像与字符串表
- `NXVM.call(methodIdx, args...)` 执行抽取的方法
- `NXStrings.get(index)` 还原被加密的字面量

抽函数落地的两种方式：

1. **JNI 方式（推荐）**：将生成的 `.jni.c` 与 NX-VM 运行库（`libnxshield.so`）一起编译，
   在加载时注册抽取方法为 native，由 NX-VM 解释执行。
2. **桥接方式**：对方法体注入 `NXVM.call(index, args)` 调用桩，需配套 DEX 重写器完成
   method_id 引用与偏移重定位。

当前仓库已实现完整的离线分析与加密流水线、产物载荷与自动生成的 JNI 桥接源码；
第 1 种方式的 `.so` 需要 NDK 环境编译，第 2 种方式的 DEX 重写器可作为后续增量模块接入。
