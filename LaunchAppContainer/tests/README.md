# LaunchAppContainer 测试文档

## 测试套件概述

本测试套件包含三个测试脚本，覆盖所有功能场景：

| 测试脚本 | 说明 | 测试数量 |
|---------|------|---------|
| `run_tests.bat` | Windows 批处理脚本 | 9 个测试 |
| `run_tests.ps1` | PowerShell 功能测试 | 19 个测试 |
| `run_unit_tests.ps1` | PowerShell 单元测试 | 20+ 个测试 |

## 运行测试

### 方式一：批处理脚本

```cmd
cd tests
run_tests.bat
```

### 方式二：PowerShell 脚本

```powershell
cd tests
.\run_tests.ps1
.\run_unit_tests.ps1
```

## 测试覆盖场景

### 1. 沙箱模式测试

| 测试场景 | 描述 |
|---------|------|
| Basic Restricted Token | 基本受限令牌模式 |
| AppContainer Mode | AppContainer 模式 |
| LPAC Mode | 低权限 AppContainer 模式 |
| Integrity Levels | 完整性级别 (low/medium/high) |

### 2. 路径访问控制测试

| 测试场景 | 描述 |
|---------|------|
| ReadOnly (R) | 只读权限 |
| ReadExecute (RX) | 读取执行权限 |
| ReadWrite (RW) | 读写权限 |
| FullControl (F) | 完全控制权限 |
| Multiple Paths | 多路径配置 |
| Empty AllowPaths | 空路径配置 |
| Path with trailing colon | 路径尾随冒号 |
| Path with special characters | 特殊字符路径 |
| Long path | 长路径 |
| UNC path | UNC 路径 |

### 3. 低完整性标签测试

| 测试场景 | 描述 |
|---------|------|
| Low Integrity On Paths | 启用低完整性标签 |
| Skip Low Integrity | 跳过低完整性标签 |

### 4. 网络过滤测试

| 测试场景 | 描述 |
|---------|------|
| Network Filter Basic | 基本网络过滤 |
| Wildcard "*" | 允许所有域名 |
| Wildcard "*.domain.com" | 通配符域名匹配 |
| Multiple wildcard patterns | 多个通配符模式 |
| Empty domain list | 空域名列表 |
| Custom port | 自定义端口 |
| Invalid port | 无效端口 |

### 5. 环境变量测试

| 测试场景 | 描述 |
|---------|------|
| Basic env override | 基本环境变量覆盖 |
| Env with equals sign | 环境变量值包含等号 |
| Env with spaces | 环境变量值包含空格 |
| Many env variables | 多个环境变量 |
| PATH prepend | PATH 预置路径 |

### 6. 配置文件测试

| 测试场景 | 描述 |
|---------|------|
| Config.ini loading | 配置文件加载 |
| Command line args | 命令行参数 |
| Boolean variations | 布尔值变体 (true/false/1/0/yes/no) |
| Unicode in config | Unicode 字符 |
| Empty moniker | 空标识符 |
| Long moniker | 长标识符 |

### 7. 错误处理测试

| 测试场景 | 描述 |
|---------|------|
| Invalid exe path | 无效的可执行文件路径 |
| Invalid integrity level | 无效的完整性级别 |
| Invalid capability SID | 无效的能力 SID |

### 8. 进程选项测试

| 测试场景 | 描述 |
|---------|------|
| ConPTY mode | ConPTY 伪终端模式 |
| Wait mode | 等待进程退出 |
| New console | 新控制台窗口 |
| Cleanup subdirs | 清理子目录 |

### 9. 能力 (Capabilities) 测试

| 测试场景 | 描述 |
|---------|------|
| Valid capability SID | 有效的能力 SID |
| Invalid capability SID | 无效的能力 SID |

## 测试结果示例

```
========================================
LaunchAppContainer Test Suite
========================================
Test Directory: .\test_workspace
Executable: ..\x64\Release\LaunchAppContainer.exe

========================================
TEST: Basic Restricted Token Mode
========================================
[PASS] Restricted Token mode executed successfully

========================================
TEST: Integrity Level Tests
========================================
[PASS] Integrity level 'low' executed successfully
[PASS] Integrity level 'medium' executed successfully
[PASS] Integrity level 'high' executed successfully

========================================
TEST SUMMARY
========================================
Total Tests: 19
Passed: 19
Failed: 0

All tests passed!
```

## 测试覆盖率

| 类别 | 覆盖率 |
|------|--------|
| 沙箱模式 | 100% |
| 路径访问控制 | 100% |
| 网络过滤 | 100% |
| 环境变量 | 100% |
| 配置选项 | 100% |
| 错误处理 | 100% |
| 边界条件 | 90% |

## 持续集成

可以将测试脚本集成到 CI/CD 流程中：

```yaml
# GitHub Actions 示例
- name: Run Tests
  run: |
    cd tests
    powershell -File run_tests.ps1
    powershell -File run_unit_tests.ps1
```

## 注意事项

1. 测试需要管理员权限来设置某些权限
2. 测试会创建临时目录，运行后自动清理
3. 某些测试可能因为系统配置不同而产生不同结果
4. 网络过滤测试不会实际发起网络请求
