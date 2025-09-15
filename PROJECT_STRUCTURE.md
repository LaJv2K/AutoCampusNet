# 校园网自动认证助手 - 项目文件结构

## 文件列表

```
campus-net-auth/
├── main.go                 # 主程序入口，包含所有核心功能
├── icon.go                 # 系统托盘图标数据
├── go.mod                  # Go模块依赖管理
├── build.bat              # Windows构建脚本
├── README.md              # 项目说明文档
├── CONFIG.md              # 配置文件说明
├── INSTALL.md             # 安装部署指南
├── templates/             # HTML模板目录
│   └── config.html        # Web配置页面模板
└── static/               # 静态资源目录
    └── style.css         # 配置页面CSS样式
```

## 文件功能说明

### 核心程序文件
- **main.go**: 主程序，包含所有功能实现
- **icon.go**: 系统托盘图标数据定义

### 配置文件
- **go.mod**: Go模块文件，定义项目依赖
- **build.bat**: Windows构建脚本

### 模板和样式
- **templates/config.html**: Web配置界面HTML模板
- **static/style.css**: 配置界面CSS样式文件

### 文档文件
- **README.md**: 项目介绍和使用说明
- **CONFIG.md**: 详细的配置参数说明
- **INSTALL.md**: 安装部署指南

## 编译后文件
运行 `build.bat` 后会生成：
- **campus-net-auth.exe**: 主程序可执行文件

## 运行时文件
程序运行时会在用户目录创建：
```
%USERPROFILE%\CampusNetAuth\
├── config.json           # 用户配置文件
└── app.log              # 程序运行日志
```

## 主要功能特性

### ✅ 已实现功能
- [x] 校园网自动认证
- [x] 网络状态检测
- [x] 系统托盘集成
- [x] Web配置界面
- [x] Windows通知
- [x] 开机自启动
- [x] 多实例检测
- [x] 日志记录
- [x] IPv4/IPv6支持
- [x] 隐藏控制台窗口
- [x] 中文界面
- [x] 高DPI托盘菜单
- [x] 现代化通知
- [x] 防重复通知
- [x] 配置热重载

### 🛠️ 技术实现
- **语言**: Go 1.20+
- **GUI**: Fyne.io/systray (系统托盘)
- **通知**: gopkg.in/toast.v1 (Windows通知)
- **Web界面**: html/template + embed
- **多实例**: Windows Mutex
- **开机自启**: Windows注册表
- **IP检测**: net包标准库
- **HTTP客户端**: net/http标准库

### 📋 使用流程
1. 运行程序 → 自动创建系统托盘图标
2. 首次运行 → 打开Web配置界面
3. 配置账号密码 → 开始后台监控
4. 网络断开 → 自动重新认证
5. 认证成功/失败 → 显示Windows通知

### 🔧 配置选项
- **基本配置**: 账号、密码、检查间隔
- **高级配置**: 检查URL、登录URL、开机自启
- **实时状态**: 网络连接状态、认证结果
- **运行日志**: 详细的操作记录

## 依赖包版本

```go
fyne.io/systray v1.10.0           // 系统托盘
golang.org/x/sys v0.10.0          // Windows API
gopkg.in/toast.v1 v1.0.0          // Windows通知
```

## 构建命令

```bash
# 开发构建（显示控制台）
go build -o campus-net-auth.exe

# 生产构建（隐藏控制台）
go build -ldflags "-H windowsgui" -o campus-net-auth.exe

# 使用构建脚本
build.bat
```

## 兼容性

- **操作系统**: Windows 10/11
- **架构**: x64 (默认), x86, ARM64
- **运行时**: 无需额外依赖，独立可执行文件
- **权限**: 普通用户权限（开机自启需管理员权限）

---

此项目为完整的校园网自动认证解决方案，包含所有必要的功能和文档。
