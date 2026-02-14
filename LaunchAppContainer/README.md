# LaunchAppContainer

Windows 沙箱启动工具，支持 AppContainer 和 Restricted Token 两种沙箱模式，提供文件系统隔离、网络过滤、注册表保护等安全功能。

## 项目架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LaunchAppContainer                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────┐  │
│  │   config.ini    │    │  命令行参数      │    │    环境变量/注册表      │  │
│  │   配置文件      │    │  -i -m -c ...   │    │    自动检测             │  │
│  └────────┬────────┘    └────────┬────────┘    └────────────┬────────────┘  │
│           │                      │                          │               │
│           └──────────────────────┼──────────────────────────┘               │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         配置解析模块                                    │  │
│  │  • ParseCommandLine()     • ReadIniString()     • ParseAllowedPaths() │  │
│  │  • ParseCapabilityList()  • ParseAccessLevel()  • EnvOverrides        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        沙箱模式选择                                     │  │
│  │                                                                        │  │
│  │    ┌─────────────────────┐          ┌─────────────────────┐           │  │
│  │    │   AppContainer      │          │  Restricted Token   │           │  │
│  │    │   (强隔离)          │          │  (允许子进程)        │           │  │
│  │    │                     │          │                     │           │  │
│  │    │ • CreateAppContainer│          │ • SaferCreateLevel  │           │  │
│  │    │ • LPAC 支持         │          │ • 完整性级别控制     │           │  │
│  │    │ • 能力 SID          │          │ • 低完整性标签       │           │  │
│  │    │ • Win32k 锁定       │          │                     │           │  │
│  │    └─────────────────────┘          └─────────────────────┘           │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         安全模块                                        │  │
│  │                                                                        │  │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────────┐  │  │
│  │  │ 路径访问控制   │  │ 网络过滤      │  │ 注册表保护                │  │  │
│  │  │               │  │               │  │                           │  │  │
│  │  │ • ACL 设置    │  │ • HTTP 代理   │  │ • 低完整性虚拟化          │  │  │
│  │  │ • DACL 备份   │  │ • HTTPS 隧道  │  │                           │  │  │
│  │  │ • 低完整性标签│  │ • 域名白名单  │  │                           │  │  │
│  │  │ • 权限恢复    │  │ • 通配符匹配  │  │                           │  │  │
│  │  └───────────────┘  └───────────────┘  └───────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         进程创建模块                                    │  │
│  │                                                                        │  │
│  │  • CreateProcessAsUserW()    • ConPTY 伪终端支持                       │  │
│  │  • 属性列表初始化            • 环境变量注入                            │  │
│  │  • 进程缓解策略              • 子进程策略控制                          │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                       Bun/OpenCode 专用支持                             │  │
│  │                                                                        │  │
│  │  • 嵌入式 DLL 提取          • B: 驱动器映射                            │  │
│  │  • PE 验证和签名检查        • 多层回退目录                             │  │
│  │  • 默认环境路径配置         • 虚拟文件系统                             │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         清理模块                                        │  │
│  │                                                                        │  │
│  │  • RestoreSavedSecurity()   • DeleteTreeNoFollow()                    │  │
│  │  • CleanupBunVirtualDrive() • AppContainer 配置清理                   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 核心文件结构

```
LaunchAppContainer/
├── LaunchAppContainer.cpp      # 主程序入口和核心逻辑
├── NetworkFilterPlugin.h       # 网络过滤插件头文件
├── NetworkFilterPlugin.cpp     # HTTP/HTTPS 代理实现
├── LaunchAppContainer.sln      # Visual Studio 解决方案
├── LaunchAppContainer.vcxproj  # 项目配置文件
├── config.ini                  # 默认配置文件
├── LaunchSandboxMSRC.bat       # MSRC 赏金测试脚本
└── README.md                   # 项目文档
```

### 数据流图

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   用户输入   │────▶│  配置解析   │────▶│  权限设置   │────▶│  进程创建   │
│ config.ini  │     │             │     │  ACL/DACL   │     │             │
│  命令行参数  │     │             │     │  低完整性   │     │             │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                   │
                                                                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   日志输出   │◀────│  权限恢复   │◀────│  进程监控   │◀────│  沙箱进程   │
│             │     │             │     │  等待退出   │     │  运行中     │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

## 功能特性

- **双沙箱模式**: AppContainer（强隔离）和 Restricted Token（允许子进程）
- **文件系统隔离**: 精细的路径访问控制，支持四种权限级别
- **网络过滤**: 内置 HTTP/HTTPS 代理，支持域名白名单
- **注册表保护**: 低完整性级别自动启用注册表虚拟化
- **进程缓解策略**: Win32k 锁定、子进程控制等
- **Bun/OpenCode 支持**: 自动提取嵌入式 DLL，配置虚拟驱动器

## 快速开始

### 方式一：使用配置文件

在程序目录创建 `config.ini` 文件：

```ini
[App]
moniker = your-sandbox
displayName = MySandbox
exe = opencode.exe
wait = true
newConsole = true

; 使用 Restricted Token 模式（允许子进程）
restrictedToken = true
integrityLevel = low

; 路径访问控制
allowPaths = "C:\project\work:F,C:\Windows\System32:RX"
lowIntegrityOnPaths = true

; 网络过滤
networkFilterEnabled = true
networkFilterPort = 8080
networkFilterAllowedUrls = "*.github.com,api.openai.com"

log = true
```

然后直接运行 `LaunchAppContainer.exe`。

### 方式二：命令行参数

```
LaunchAppContainer.exe [选项]

必需参数:
  -i : 要启动的可执行文件路径
  -m : AppContainer 包名 (moniker)

可选参数:
  -d : AppContainer 显示名称
  -c : 能力 SID 列表 (分号分隔)
  -a : 允许访问的路径列表
  -e : 环境变量覆盖
  -p : PATH 环境变量预置路径

沙箱选项:
  -w : 等待子进程退出
  -r : 保留 AppContainer 配置文件
  -l : 启用 LPAC 模式
  -k : 启用 Win32k 锁定
  -C : 允许子进程创建
  -R : 使用 Restricted Token 模式
  -x : 退出时清理子目录
  -s : 跳过低完整性标签设置
  -g : 启用日志
```

## 沙箱模式对比

| 特性 | AppContainer | Restricted Token |
|-----|--------------|------------------|
| 隔离强度 | 强 | 中等 |
| 文件读取隔离 | ✅ 完全隔离 | ❌ 可读取所有 |
| 文件写入隔离 | ✅ 完全隔离 | ✅ 只能写入授权目录 |
| 网络隔离 | ✅ 完全支持 | ✅ 通过代理过滤 |
| 注册表隔离 | ✅ 完全隔离 | ⚠️ 虚拟化 |
| 子进程创建 | ❌ 默认禁止 | ✅ 允许 |

## 配置选项详解

### 基本配置

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `moniker` | 沙箱标识符 | 必需 |
| `displayName` | 显示名称 | 同 moniker |
| `exe` | 可执行文件路径 | 必需 |
| `wait` | 等待进程退出 | `true` |
| `newConsole` | 创建新控制台 | `true` |
| `conpty` | 使用 ConPTY 伪终端 | `false` |
| `log` | 启用日志 | `true` |

### 沙箱选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `restrictedToken` | 使用 Restricted Token 模式 | `false` |
| `integrityLevel` | 完整性级别 (low/medium/high) | `low` |
| `lpac` | 启用 LPAC 模式 | `false` |
| `noWin32k` | 禁用 Win32k 系统调用 | `false` |
| `allowChildProcess` | 允许子进程创建 | `false` |

### 路径访问控制

| 选项 | 说明 | 示例 |
|------|------|------|
| `allowPaths` | 允许访问的路径 | `"C:\work:F,C:\config:R"` |
| `pathPrepend` | PATH 预置路径 | `C:\tools\bin` |
| `lowIntegrityOnPaths` | 设置低完整性标签 | `true` |

**路径权限级别**:

| 级别 | 语法 | 说明 |
|------|------|------|
| ReadOnly | `path:R` | 只读 |
| ReadExecute | `path:RX` | 读取 + 执行 |
| ReadWrite | `path:RW` | 读写 |
| FullControl | `path:F` 或 `path` | 完全控制（默认） |

### 网络过滤

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `networkFilterEnabled` | 启用网络过滤 | `false` |
| `networkFilterPort` | 代理端口 | `8080` |
| `networkFilterAllowedUrls` | 允许的域名列表 | - |

**域名匹配规则**:
- 精确匹配: `api.example.com`
- 通配符匹配: `*.example.com`
- 允许所有: `*`

### 环境变量

| 选项 | 说明 | 示例 |
|------|------|------|
| `env` | 环境变量覆盖 | `HOME=C:\work,TEMP=C:\temp` |

### 清理选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `retainProfile` | 保留 AppContainer 配置 | `false` |
| `cleanupSubdirs` | 退出时清理子目录 | `false` |

## 使用示例

### 示例 1：运行 Node.js 应用

```ini
[App]
moniker = nodejs-sandbox
exe = node.exe
wait = true
restrictedToken = true
integrityLevel = low
allowPaths = "C:\project\myapp:F"
lowIntegrityOnPaths = true
log = true
```

### 示例 2：运行带网络限制的应用

```ini
[App]
moniker = network-limited
exe = myapp.exe
wait = true
restrictedToken = true
allowPaths = "C:\data:F"
networkFilterEnabled = true
networkFilterAllowedUrls = "api.myservice.com,*.cdn.example.com"
log = true
```

### 示例 3：MSRC 沙箱逃逸测试

```bash
LaunchAppContainer.exe -m 1.0.0.0_x86_en-us_TestProgram_wvx3sa3v3dj1m -c S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 -w -l -k -i cmd.exe
```

## Moniker 格式

Moniker 用于唯一标识 AppContainer 包，格式通常为：

```
版本_架构_语言_应用名_随机标识
```

示例：
```
1.0.0.0_x86_en-us_TestProgram_wvx3sa3v3dj1m
```

## 能力 (Capabilities)

AppContainer 和 LPAC 沙箱通过能力 SID 授予对系统资源的访问权限。

常用能力 SID：

| SID | 名称 | 用途 |
|-----|------|------|
| S-1-15-3-1 | internetClient | 网络客户端 |
| S-1-15-3-1024-... | lpacCom | COM 访问 |
| S-1-15-3-1024-... | registryRead | 注册表读取 |

## 进程缓解策略

### Win32k 锁定 (-k)

启用后，沙箱进程将无法：
- 调用任何 win32k 系统调用
- 创建任何 UI 元素

适用于无头服务、CLI 工具和 MSRC 赏金测试。

**编译要求**：
- 不链接任何调用 win32k 的 DLL
- 静态链接 VC 运行时

## MSRC 赏金提交

`LaunchSandboxMSRC.bat` 文件包含 MSRC 沙箱逃逸赏金计划所需的命令行选项和能力列表。

**注意事项**：
- 修改命令行选项或使用未包含的能力将不符合赏金资格
- 必须启用 Win32k 锁定（默认启用）
- 可能需要特殊的编译器选项

## 日志文件

- 沙箱日志: `LaunchAppContainer_YYYYMMDD_HHMMSSmmm.log`
- 代理日志: `NetworkFilterProxy_YYYYMMDD_HHMMSSmmm.log`

## 安全注意事项

1. **管理员权限**: 某些操作（如设置系统目录权限）需要管理员权限
2. **权限恢复**: 程序退出时会自动恢复原始权限设置
3. **网络过滤**: 仅对使用系统代理设置的应用有效
4. **注册表保护**: 低完整性级别自动启用注册表虚拟化

## 系统要求

- Windows 8 或更高版本
- 支持 32 位和 64 位进程

## 许可证

MIT License
