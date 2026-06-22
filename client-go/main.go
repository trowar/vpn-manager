package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		relaunched, err := ensureElevatedOrRelaunch(args)
		if err != nil {
			return err
		}
		if relaunched {
			return nil
		}
		normalizeSystemProxyOnLaunch()
		return launchClientUI()
	}

	switch args[0] {
	case "tun2socks-child":
		return runTun2SocksChild(args[1:])
	case "import":
		if len(args) < 2 {
			return errors.New("用法: company-vpn.exe import <配置包.json>")
		}
		bundle, err := loadBootstrap(args[1])
		if err != nil {
			return err
		}
		if err := storeBootstrap(bundle); err != nil {
			return err
		}
		fmt.Println("已导入:", bundle.Name)
		return nil
	case "list":
		return listProfiles()
	case "connect":
		target := ""
		if len(args) >= 2 {
			target = args[1]
		}
		return connectProfile(target)
	case "dir":
		dir, err := appDir()
		if err != nil {
			return err
		}
		fmt.Println(dir)
		return nil
	case "console":
		return interactive()
	case "help", "-h", "--help":
		printHelp()
		return nil
	default:
		printHelp()
		return fmt.Errorf("未知命令: %s", args[0])
	}
}

func normalizeSystemProxyOnLaunch() {
	if err := disableSystemProxy(); err != nil {
		appendLog("关闭残留系统代理失败: " + err.Error())
		return
	}
	appendLog("已确认系统代理关闭")
}

func printHelp() {
	fmt.Println("Company VPN Client")
	fmt.Println("")
	fmt.Println("用法:")
	fmt.Println("  company-vpn.exe import <配置包.json>   导入管理员分发的引导配置")
	fmt.Println("  company-vpn.exe list                  查看已导入的连接方式")
	fmt.Println("  company-vpn.exe connect [名称]         连接；不填名称时使用第一个配置")
	fmt.Println("  company-vpn.exe dir                   显示本地数据目录")
	fmt.Println("  company-vpn.exe console               打开控制台菜单")
	fmt.Println("")
	fmt.Println("说明: 每次连接前都会从服务器实时获取最新 OpenVPN 或 SS/KCPTUN 配置。")
}
