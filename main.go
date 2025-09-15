package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"gopkg.in/toast.v1"
)

//go:embed templates/* static/*
var embedFS embed.FS

// 配置结构体
type Config struct {
	Account       string `json:"account"`
	Password      string `json:"password"`
	CheckURL      string `json:"check_url"`
	LoginURL      string `json:"login_url"`
	AutoStart     bool   `json:"auto_start"`
	CheckInterval int    `json:"check_interval"`
}

// 全局变量
var (
	config           Config
	configMutex      sync.RWMutex
	webServer        *http.Server
	logger           *log.Logger
	logFile          *os.File
	appMutex         *windows.Handle
	authFailNotified bool
)

// Windows API 函数
var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procShowWindow       = user32.NewProc("ShowWindow")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
)

const (
	SW_HIDE = 0
	SW_SHOW = 1
)

func init() {
	// 初始化默认配置
	config = Config{
		CheckURL:      "http://10.10.102.50:801/eportal/portal/online_list",
		LoginURL:      "http://10.10.102.50:801/eportal/portal/login?callback=dr1005&login_method=1&user_account=%2C0%2C{account}%40unicom&user_password={password}&wlan_user_ip={wlan_user_ip}&wlan_user_ipv6={wlan_user_ipv6}&wlan_user_mac=000000000000&wlan_ac_ip=&wlan_ac_name=&jsVersion=4.1.3&terminal_type=1",
		AutoStart:     true,
		CheckInterval: 30,
	}
}

func main() {
	// 单实例检测：若已运行，则仅打开配置页
	if !createSingleInstanceMutex() {
		openConfigPage()
		return
	}
	defer closeMutex()

	setupLogging()
	defer logFile.Close()
	logger.Println("程序启动")

	hideConsoleWindow()

	loadConfig()

	// 首次运行：自动开启 Web 页面
	if config.Account == "" || config.Password == "" {
		startWebServer()
		showNotification("校园网认证助手", "首次使用，请配置账号和密码")
		openConfigPage()
	}

	// 托盘
	systray.Run(onTrayReady, onTrayExit)
}

// 创建单实例互斥锁
func createSingleInstanceMutex() bool {
	mutexName := "CampusNetworkAuthenticator_Mutex"
	mutexPtr, err := windows.UTF16PtrFromString(mutexName)
	if err != nil {
		return true
	}
	handle, err := windows.CreateMutex(nil, false, mutexPtr)
	if err != nil {
		return true
	}
	if windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		windows.CloseHandle(handle)
		return false
	}
	appMutex = &handle
	return true
}

func closeMutex() {
	if appMutex != nil {
		windows.CloseHandle(*appMutex)
	}
}

// 设置日志
func setupLogging() {
	homeDir, _ := os.UserHomeDir()
	logDir := filepath.Join(homeDir, "CampusNetAuth")
	_ = os.MkdirAll(logDir, 0755)
	logPath := filepath.Join(logDir, "app.log")
	var err error
	logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	logger = log.New(logFile, "", log.LstdFlags)
}

// 隐藏控制台窗口
func hideConsoleWindow() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, SW_HIDE)
	}
}

// 托盘初始化
func onTrayReady() {
	systray.SetIcon(getIcon())
	systray.SetTitle("校园网认证")
	systray.SetTooltip("校园网自动认证助手")

	mConfig := systray.AddMenuItem("⚙️ 配置", "打开配置页面")
	mStatus := systray.AddMenuItem("🌐 网络状态", "检查网络连接状态")
	systray.AddSeparator()
	mAutoStart := systray.AddMenuItemCheckbox("🚀 开机自启", "设置开机自启动", config.AutoStart)
	systray.AddSeparator()
	mExit := systray.AddMenuItem("退出", "退出程序")

	// 启动 Web 服务
	go startWebServer()

	go func() {
		for {
			select {
			case <-mConfig.ClickedCh:
				openConfigPage()
			case <-mStatus.ClickedCh:
				go checkNetworkStatus()
			case <-mAutoStart.ClickedCh:
				toggleAutoStart(mAutoStart)
			case <-mExit.ClickedCh:
				systray.Quit()
			}
		}
	}()

	// 若已有配置则开启认证循环
	if config.Account != "" && config.Password != "" {
		go startAuthenticationLoop()
	}
}

func onTrayExit() {
	if webServer != nil {
		_ = webServer.Shutdown(context.Background())
	}
	logger.Println("程序退出")
}

// 简单图标（16x16 PNG）
func getIcon() []byte {
	iconData := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
		0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0xF3, 0xFF, 0x61, 0x00, 0x00, 0x00,
		0x19, 0x74, 0x45, 0x58, 0x74, 0x53, 0x6F, 0x66, 0x74, 0x77, 0x61, 0x72,
		0x65, 0x00, 0x41, 0x64, 0x6F, 0x62, 0x65, 0x20, 0x49, 0x6D, 0x61, 0x67,
		0x65, 0x52, 0x65, 0x61, 0x64, 0x79, 0x71, 0xC9, 0x65, 0x3C, 0x00, 0x00,
		0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x38, 0x8D, 0x63, 0x60, 0x18, 0x05,
		0xA3, 0x60, 0x14, 0x8C, 0x02, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
		0x44, 0xAE, 0x42, 0x60, 0x82,
	}
	return iconData
}

// 认证循环
func startAuthenticationLoop() {
	ticker := time.NewTicker(time.Duration(config.CheckInterval) * time.Second)
	defer ticker.Stop()
	checkAndAuthenticate()
	for range ticker.C {
		checkAndAuthenticate()
	}
}

// 检查并认证
func checkAndAuthenticate() {
	logger.Println("检查网络状态...")
	online, err := checkOnlineStatus()
	if err != nil {
		logger.Printf("检查网络状态失败: %v", err)
		return
	}
	if !online {
		logger.Println("网络未连接，开始认证...")
		if err := authenticate(); err != nil {
			logger.Printf("认证失败: %v", err)
			if !authFailNotified {
				showNotification("认证失败", fmt.Sprintf("校园网认证失败: %v", err))
				authFailNotified = true
			}
		} else {
			logger.Println("认证成功")
			showNotification("认证成功", "校园网认证成功，网络已连接")
			authFailNotified = false
		}
	}
}

// 检查在线状态
func checkOnlineStatus() (bool, error) {
	configMutex.RLock()
	checkURL := config.CheckURL
	configMutex.RUnlock()

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(checkURL)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	// JSONP: jsonpReturn({...});
	re := regexp.MustCompile(`jsonpReturn\((.+)\);?`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return false, fmt.Errorf("无法解析响应格式")
	}
	var result struct {
		Result int    `json:"result"`
		Msg    string `json:"msg"`
	}
	if err := json.Unmarshal([]byte(matches[1]), &result); err != nil {
		return false, err
	}
	// result == 1 认为在线；0 为未在线
	return result.Result == 1, nil
}

// 执行认证
func authenticate() error {
	// 获取本机 IP
	ipv4, ipv6, err := getLocalIPs()
	if err != nil {
		return fmt.Errorf("获取IP地址失败: %v", err)
	}

	// 读取参数
	configMutex.RLock()
	loginURL := config.LoginURL
	account := config.Account
	password := config.Password
	configMutex.RUnlock()

	// IPv6 按需求展开编码
	formattedIPv6 := formatIPv6ForURL(ipv6)

	// 替换占位符
	loginURL = strings.ReplaceAll(loginURL, "{account}", url.QueryEscape(account))
	loginURL = strings.ReplaceAll(loginURL, "{password}", url.QueryEscape(password))
	loginURL = strings.ReplaceAll(loginURL, "{wlan_user_ip}", ipv4)
	loginURL = strings.ReplaceAll(loginURL, "{wlan_user_ipv6}", formattedIPv6)

	logger.Printf("认证URL: %s", loginURL)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(loginURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	logger.Printf("认证响应: %s", string(body))

	re := regexp.MustCompile(`jsonpReturn\((.+)\);?`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) >= 2 {
		var result struct {
			Result int    `json:"result"`
			Msg    string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(matches[1]), &result); err == nil {
			if result.Result == 1 {
				return nil
			}
			return fmt.Errorf("认证失败: %s", result.Msg)
		}
	}
	if strings.Contains(string(body), "success") || strings.Contains(string(body), "成功") {
		return nil
	}
	return fmt.Errorf("认证失败: %s", string(body))
}

// 获取本机 IP
func getLocalIPs() (ipv4, ipv6 string, err error) {
	// Define Wi-Fi keywords for different OS
	var wifiKeywords []string
	if runtime.GOOS == "windows" {
		wifiKeywords = []string{"wi-fi", "wlan"}
	} else {
		wifiKeywords = []string{"wlan", "wifi"}
	}

	ifaces, e := net.Interfaces()
	if e != nil {
		return "", "", e
	}

	for _, iface := range ifaces {
		name := strings.ToLower(iface.Name)
		matched := false
		for _, k := range wifiKeywords {
			if strings.Contains(name, k) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		addrs, e := iface.Addrs()
		if e != nil {
			return ipv4, ipv6, e
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					ipv4 = ip4.String()
				} else if ip6 := ipnet.IP.To16(); ip6 != nil && ipnet.IP.To4() == nil {
					// Skip link-local addresses (fe80::/10)
					if !ip6.IsLinkLocalUnicast() && !ip6.IsLinkLocalMulticast() {
						ipv6 = ip6.String()
					}
				}
			}
		}
	}
	return ipv4, ipv6, nil
}

// 按要求展开 IPv6 并用 %3A 分隔
func formatIPv6ForURL(ipv6 string) string {
	if ipv6 == "" {
		return ""
	}
	ip := net.ParseIP(ipv6)
	if ip == nil || ip.To4() != nil {
		return ""
	}
	b := ip.To16()
	if b == nil {
		return ""
	}
	parts := make([]string, 8)
	for i := 0; i < 16; i += 2 {
		parts[i/2] = fmt.Sprintf("%02x%02x", b[i], b[i+1])
	}
	return strings.ReplaceAll(strings.Join(parts, ":"), ":", "%3A")
}

// 通知
func showNotification(title, message string) {
	n := toast.Notification{
		AppID:   "CampusNetAuth",
		Title:   title,
		Message: message,
		Icon:    "",
		Actions: []toast.Action{{
			Type:      "protocol",
			Label:     "打开配置",
			Arguments: "http://localhost:8080",
		}},
	}
	if err := n.Push(); err != nil {
		logger.Printf("显示通知失败: %v", err)
	}
}

// Web 服务
func startWebServer() {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.FileServer(http.FS(embedFS)))
	mux.HandleFunc("/", configHandler)
	mux.HandleFunc("/api/config", apiConfigHandler)
	mux.HandleFunc("/api/status", apiStatusHandler)
	mux.HandleFunc("/api/auth", apiAuthHandler)
	mux.HandleFunc("/api/exit", apiExitHandler)

	webServer = &http.Server{Addr: ":8080", Handler: mux}
	go func() {
		if err := webServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Printf("Web服务器启动失败: %v", err)
		}
	}()
}

// 配置页面
func configHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(embedFS, "templates/config.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	configMutex.RLock()
	data := config
	configMutex.RUnlock()
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

// 配置 API
func apiConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		configMutex.RLock()
		_ = json.NewEncoder(w).Encode(config)
		configMutex.RUnlock()
		return
	}
	if r.Method == http.MethodPost {
		var newConfig Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		configMutex.Lock()
		config = newConfig
		configMutex.Unlock()
		saveConfig()
		if config.AutoStart {
			setAutoStart(true)
		} else {
			setAutoStart(false)
		}
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
		logger.Println("配置已更新")
		go checkAndAuthenticate()
		return
	}
	http.Error(w, "Method not allowed", 405)
}

// 状态 API
func apiStatusHandler(w http.ResponseWriter, r *http.Request) {
	online, err := checkOnlineStatus()
	resp := map[string]interface{}{"online": online}
	if err != nil {
		resp["error"] = err.Error()
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// 手动认证 API（同步返回结果）
func apiAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if err := authenticate(); err != nil {
		logger.Printf("手动认证失败: %v", err)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	logger.Println("手动认证成功")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// 退出 API
func apiExitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	logger.Println("收到退出请求")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "exiting"})
	go func() {
		time.Sleep(1 * time.Second)
		systray.Quit()
	}()
}

// 菜单：检查网络状态
func checkNetworkStatus() {
	online, err := checkOnlineStatus()
	var msg string
	if err != nil {
		msg = fmt.Sprintf("网络状态检查失败: %v", err)
	} else if online {
		msg = "网络已连接"
	} else {
		msg = "网络未连接"
	}
	showNotification("网络状态", msg)
}

// 切换开机自启
func toggleAutoStart(item *systray.MenuItem) {
	config.AutoStart = !config.AutoStart
	if config.AutoStart {
		item.Check()
		setAutoStart(true)
	} else {
		item.Uncheck()
		setAutoStart(false)
	}
	saveConfig()
}

// 打开配置页面
func openConfigPage() {
	_ = exec.Command("cmd", "/c", "start", "", "http://localhost:8080").Start()
}

// 注册表开机自启
func setAutoStart(enable bool) {
	key, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		logger.Printf("打开注册表失败: %v", err)
		return
	}
	defer key.Close()
	const appName = "CampusNetAuth"
	if enable {
		exePath, _ := os.Executable()
		if err := key.SetStringValue(appName, exePath); err != nil {
			logger.Printf("设置开机自启失败: %v", err)
		} else {
			logger.Println("开机自启已启用")
		}
	} else {
		if err := key.DeleteValue(appName); err != nil && err != registry.ErrNotExist {
			logger.Printf("禁用开机自启失败: %v", err)
		} else {
			logger.Println("开机自启已禁用")
		}
	}
}

// 加载配置
func loadConfig() {
	homeDir, _ := os.UserHomeDir()
	configPath := filepath.Join(homeDir, "CampusNetAuth", "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	if err := json.Unmarshal(data, &config); err != nil {
		logger.Printf("解析配置失败: %v", err)
	}
}

// 保存配置
func saveConfig() {
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, "CampusNetAuth")
	_ = os.MkdirAll(configDir, 0755)
	configPath := filepath.Join(configDir, "config.json")
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		logger.Printf("序列化配置失败: %v", err)
		return
	}
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		logger.Printf("保存配置失败: %v", err)
	}
}
