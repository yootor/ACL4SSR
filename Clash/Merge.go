package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// 规则去重并在重复项前面加注释
func deduplicateFiles(inputFiles []string, deduplicatedFiles []string) error {
	ruleSet := make(map[string]string)                                                        // 记录规则及其来源文件
	domainRegex := regexp.MustCompile(`(?i)(DOMAIN|DOMAIN-SUFFIX|KEYWORD|IP-CIDR),([^"\s]+)`) // 匹配 Clash 规则

	for index, fileName := range inputFiles {
		file, err := os.Open(fileName)
		if err != nil {
			return fmt.Errorf("无法打开文件 %s: %v", fileName, err)
		}
		defer file.Close()

		outputFileName := deduplicatedFiles[index]
		outFile, err := os.Create(outputFileName)
		if err != nil {
			return fmt.Errorf("无法创建去重文件 %s: %v", outputFileName, err)
		}
		defer outFile.Close()

		scanner := bufio.NewScanner(file)
		writer := bufio.NewWriter(outFile)

		//输出文件增加时间戳等信息
		writer.WriteString("# 去重复后的规则, 来自https://github.com/ACL4SSR/ACL4SSR\n")
		currentTime := time.Now().Format("2006-01-02 15:04:05")
		writer.WriteString(fmt.Sprintf("# 文件生成时间: %s\n\n", currentTime)) // 将时间戳写入文件头部

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				writer.WriteString("\n")
				continue
			}

			matches := domainRegex.FindStringSubmatch(line)
			if len(matches) == 3 {
				_, value := matches[1], matches[2]
				if sourceFile, exists := ruleSet[value]; exists {
					// 规则已存在，标记重复项
					commentedLine := fmt.Sprintf("# %s  # 与 %s 重复\n", line, sourceFile)
					writer.WriteString(commentedLine)
				} else {
					// 规则不存在，存入去重集合
					ruleSet[value] = fileName
					writer.WriteString(line + "\n")
				}
			} else {
				// 直接写入非规则行（如注释或空行）
				writer.WriteString(line + "\n")
			}
		}

		writer.Flush()
		fmt.Println("去重后的文件已生成:", outputFileName)
	}

	return nil
}

// 生成 MOSDNS 规则文件
func generateMosdnsRules(inputFiles []string, outputFile string) error {
	var keywordRules, domainRules, fullRules []string
	domainRegex := regexp.MustCompile(`(?i)(DOMAIN|DOMAIN-SUFFIX|KEYWORD),([^"\s]+)`) // 解析规则

	for _, fileName := range inputFiles {
		file, err := os.Open(fileName)
		if err != nil {
			return fmt.Errorf("无法打开去重后文件 %s: %v", fileName, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue // 跳过注释和空行
			}

			matches := domainRegex.FindStringSubmatch(line)
			if len(matches) == 3 {
				ruleType, value := matches[1], matches[2]
				switch strings.ToUpper(ruleType) {
				case "DOMAIN":
					fullRules = append(fullRules, fmt.Sprintf("FULL,%s", value))
				case "DOMAIN-SUFFIX":
					domainRules = append(domainRules, fmt.Sprintf("DOMAIN,%s", value))
				case "KEYWORD":
					keywordRules = append(keywordRules, fmt.Sprintf("KEYWORD,%s", value))
				}
			}
		}
	}

	// 排序规则
	sort.Strings(keywordRules)
	sort.Strings(domainRules)
	sort.Strings(fullRules)

	// 创建输出文件
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("无法创建 MOSDNS 规则文件: %v", err)
	}
	defer outFile.Close()

	outWriter := bufio.NewWriter(outFile)

	// 写入文件头部信息（日期）
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	outWriter.WriteString("# MOSDNS 合并的所有去广告规则, 来自https://github.com/ACL4SSR/ACL4SSR\n")
	outWriter.WriteString(fmt.Sprintf("# MOSDNS 规则文件\n# 生成时间: %s\n\n", currentTime))

	// 写入规则
	outWriter.WriteString("# 关键字规则\n")
	for _, rule := range keywordRules {
		outWriter.WriteString(rule + "\n")
	}

	outWriter.WriteString("\n# 域名规则\n")
	for _, rule := range domainRules {
		outWriter.WriteString(rule + "\n")
	}

	outWriter.WriteString("\n# 全匹配规则\n")
	for _, rule := range fullRules {
		outWriter.WriteString(rule + "\n")
	}

	outWriter.Flush()
	fmt.Println("MOSDNS 规则文件已生成:", outputFile)
	return nil
}

func main() {
	// 输入规则文件
	inputFiles := []string{
		"./BanProgramAD.list",
		"./BanAD.list",
		"./BanEasyList.list",
		"./BanEasyListChina.list",
		"./BanEasyPrivacy.list",
		"./Custom.list",
		"./Microsoft.list",
		"./Google.list",
		"./ProxyMedia.list",
		"./ProxyGFWlist.list",
		"./CustomCN.list",
		"./games.list",
		"./ChinaMedia.list",
		"./ChinaDomain.list",

		//"./naisi_AD.list",
	}
	// 生成去重后的文件
	deduplicatedFiles := []string{
		"./Rules/BanProgramAD.list",
		"./Rules/BanAD.list",
		"./Rules/BanEasyList.list",
		"./Rules/BanEasyListChina.list",
		"./Rules/BanEasyPrivacy.list",
		"./Rules/Custom.list",
		"./Rules/Microsoft.list",
		"./Rules/Google.list",
		"./Rules/ProxyMedia.list",
		"./Rules/ProxyGFWlist.list",
		"./Rules/CustomCN.list",
		"./Rules/games.list",
		"./Rules/ChinaMedia.list",
		"./Rules/ChinaDomain.list",
	}

	// 执行规则去重
	err := deduplicateFiles(inputFiles, deduplicatedFiles)
	if err != nil {
		fmt.Println("规则去重失败:", err)
		return
	}

	// 选择去重后的文件进行合并，生成 MOSDNS 规则
	selectedFiles := []string{
		"./Rules/BanProgramAD.list",
		"./Rules/BanAD.list",
		"./Rules/BanEasyList.list",
		"./Rules/BanEasyListChina.list",
		"./Rules/BanEasyPrivacy.list",
	}
	// 这里可以调整选择哪些文件进行合并
	outputFile := "./Rules/mosdns_rules.txt"
	err = generateMosdnsRules(selectedFiles, outputFile)
	if err != nil {
		fmt.Println("生成 MOSDNS 规则失败:", err)
		return
	}
}
