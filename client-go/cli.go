package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func interactive() error {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("")
		fmt.Println("Company VPN Client")
		fmt.Println("1. 导入配置包")
		fmt.Println("2. 查看连接方式")
		fmt.Println("3. 连接")
		fmt.Println("4. 退出")
		fmt.Print("请选择: ")
		line, _ := reader.ReadString('\n')
		switch strings.TrimSpace(line) {
		case "1":
			fmt.Print("配置包路径: ")
			path, _ := reader.ReadString('\n')
			bundle, err := loadBootstrap(strings.Trim(strings.TrimSpace(path), "\""))
			if err != nil {
				fmt.Println("导入失败:", err)
				continue
			}
			if err := storeBootstrap(bundle); err != nil {
				fmt.Println("保存失败:", err)
				continue
			}
			fmt.Println("已导入:", bundle.Name)
		case "2":
			if err := listProfiles(); err != nil {
				fmt.Println("读取失败:", err)
			}
		case "3":
			fmt.Print("连接名称，可留空: ")
			name, _ := reader.ReadString('\n')
			if err := connectProfile(strings.TrimSpace(name)); err != nil {
				fmt.Println("连接失败:", err)
			}
		case "4", "q", "quit", "exit":
			return nil
		default:
			fmt.Println("无效选择")
		}
	}
}
