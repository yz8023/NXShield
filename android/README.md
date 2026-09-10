# NXShield (Android)

Android APK 加固应用（Jetpack Compose / Material 3 / Kotlin），UI 风格参考 WeKit（底部四栏导航）。
自研加固方案，不依赖任何第三方加固 SDK。

## 功能

| 模块 | 说明 |
| --- | --- |
| NX-VM 抽函数 | 选中方法体替换为 return-void 占位，原字节码编译为 NX 镜像（NXS 加密），运行时由 NXVM 解释 |
| 敏感字符串保护 | 识别中文 / vip / premium / 密钥等字符串并原位清空，原文加密入载荷表，运行期按索引还原 |
| assets 加密 | assets/ 目录做滚动异或 + HMAC 封装（.nxs），运行时解密 |
| 标识符混淆 | DEX 类名 / 方法名 / 字段名哈希重命名 |
| 日志与历史 | JSONL 任务日志 + 功能启停记录 + 历史回溯（日志页 / 设置页） |

## 目录结构

```
android/
  app/src/main/java/
    com/nxshield/app/           # Application + MainActivity
    com/nxshield/app/ui/        # Compose UI（四栏导航 + 页面）
    com/nxshield/engine/        # 自研加固引擎（DexFile 解析、NXS 加密、ApkIo、NxVm、NxStrings、NxAssets、Packer）
    com/nxshield/runtime/       # 运行时桩（被加固应用接入：NXRuntime / NXVM / NXLog / NXReflect）
  app/src/main/res/             # 资源
support（保留）/ 加固接收端:
  X 存在第三方依赖（如 apksigner / smali）以外
```

## 构建

环境要求：JDK 17、Android SDK（compileSdk 35）。

```bash
cd android
# 使用 Android Studio 打开，或命令行：
./gradlew assembleDebug
```

产物：`app/build/outputs/apk/debug/app-debug.apk`

## 使用

1. 打开 App，主页「选择文件」导入 APK（SAF）
2. 配置加固选项：NX-VM 抽函数 / 字符串保护 / assets 加密 / 抽取比例
3. 「开始加固」→ 日志页查看任务记录与运行日志
4. 完成后导出加固 APK（需自行签名后安装到设备；同一密钥下产物可由内置运行时解密）

## 运行时接入（加固应用）

`com.nxshield.runtime.*` 提供解密入口：

```kotlin
NXRuntime.setKey("your-key")
val table = NXRuntime.stringTable(ctx)      // 字符串表
val vmRecords = NXVM.load(ctx)              // VM 镜像
NXLog.i("NXShield", "runtime ready")        // 日志
```

## 限制与合规

- 仅用于加固你对之拥有合法授权的应用；不得用于他人应用的逆向、破解或绕过授权检测。
- 设备端产物未经系统签名，需自行用官方工具签名后方可安装。
- 文件选择/导出使用 SAF，不请求额外存储权限。