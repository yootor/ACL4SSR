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

const maxFileSize = 2048 * 1024 // 2048KB 限制

// 规则去重，并在超过文件大小时进行拆分
func deduplicateFiles(inputFiles []string, deduplicatedFiles []string) error {
	ruleSet := make(map[string]string)                                                        // 记录规则及其来源文件
	domainRegex := regexp.MustCompile(`(?i)(DOMAIN|DOMAIN-SUFFIX|KEYWORD|IP-CIDR),([^"\s]+)`) //匹配Clash规则

	for index, fileName := range inputFiles {
		file, err := os.Open(fileName)
		if err != nil {
			return fmt.Errorf("无法打开文件 %s: %v", fileName, err)
		}
		defer file.Close()

		// **确保文件始终在 ./Rules/ 目录**
		baseName := strings.TrimSuffix(deduplicatedFiles[index], ".list")
		//fileIndex := 1
		outputFileName := fmt.Sprintf("%s.list", baseName)
		outFile, err := os.Create(outputFileName)
		if err != nil {
			return fmt.Errorf("无法创建去重文件 %s: %v", outputFileName, err)
		}
		defer outFile.Close()

		writer := bufio.NewWriter(outFile)
		currentSize := 0

		// **写入文件头部**
		header := fmt.Sprintf("# 去重后的规则, 来源: https://github.com/ACL4SSR/ACL4SSR\n# 生成时间: %s\n\n",
			time.Now().Format("2006-01-02 15:04:05"))
		writer.WriteString(header)
		writer.Flush()
		currentSize += len(header)

		scanner := bufio.NewScanner(file)
		fileIndex := 1

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			// 直接写入空行和注释
			if line == "" || strings.HasPrefix(line, "#") {
				writer.WriteString(line + "\n")
				currentSize += len(line) + 1
				continue
			}

			// 解析规则
			matches := domainRegex.FindStringSubmatch(line)
			if len(matches) == 3 {
				_, value := matches[1], matches[2]
				if originalFile, exists := ruleSet[value]; exists {
					// **规则重复，添加注释*
					duplicateNote := fmt.Sprintf("# %s  # 与 %s 重复\n", line, originalFile)
					writer.WriteString(duplicateNote)
					currentSize += len(duplicateNote)
				} else {
					ruleSet[value] = fileName
					formattedLine := line + "\n"
					lineSize := len(formattedLine)

					// **文件大小超限，创建新文件**
					if currentSize+lineSize > maxFileSize {
						writer.Flush()
						outFile.Close()

						if fileIndex == 1 {
							os.Rename(outputFileName, fmt.Sprintf("%s_1.list", baseName)) // 先重命名
						}

						fileIndex++
						outputFileName = fmt.Sprintf("%s_%d.list", baseName, fileIndex)
						outFile, err = os.Create(outputFileName)
						if err != nil {
							return fmt.Errorf("无法创建拆分文件 %s: %v", outputFileName, err)
						}
						writer = bufio.NewWriter(outFile)

						// **写入新文件头部**
						writer.WriteString(header)
						writer.Flush()
						currentSize = len(header)
					}

					// **写入规则**
					writer.WriteString(formattedLine)
					currentSize += lineSize
				}
			} else {
				// 非匹配规则的内容仍然写入
				formattedLine := line + "\n"
				lineSize := len(formattedLine)

				// **文件大小超限，创建新文件**
				if currentSize+lineSize > maxFileSize {
					writer.Flush()
					outFile.Close()

					if fileIndex == 1 {
						os.Rename(outputFileName, fmt.Sprintf("%s_1.list", baseName)) // 先重命名文件，避免覆盖
					}

					fileIndex++
					outputFileName = fmt.Sprintf("%s_%d.list", baseName, fileIndex)
					outFile, err = os.Create(outputFileName)
					if err != nil {
						return fmt.Errorf("无法创建拆分文件 %s: %v", outputFileName, err)
					}
					writer = bufio.NewWriter(outFile)

					// **写入新文件头部**
					writer.WriteString(header)
					writer.Flush()
					currentSize = len(header)
				}

				// **写入内容**
				writer.WriteString(formattedLine)
				currentSize += lineSize
			}
		}

		writer.Flush()
		fmt.Println("去重后的文件已生成:", outputFileName)

		// **如果只有一个文件，且是 `_1` 结尾，去掉 `_1`**
		if fileIndex == 1 {
			originalName := fmt.Sprintf("%s.list", baseName)
			if _, err := os.Stat(fmt.Sprintf("%s_1.list", baseName)); err == nil {
				os.Rename(fmt.Sprintf("%s_1.list", baseName), originalName)
			}
		}
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
					fullRules = append(fullRules, fmt.Sprintf("full:%s", value))
				case "DOMAIN-SUFFIX":
					domainRules = append(domainRules, fmt.Sprintf("domain:%s", value))
				case "KEYWORD":
					keywordRules = append(keywordRules, fmt.Sprintf("keyword:%s", value))
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
	// 输入规则文件,主要是针对广告规则，其余规则屏蔽
	inputFiles := []string{
		"./BanProgramAD.list",
		"./BanAD.list",
		"./BanEasyList.list",
		"./BanEasyListChina.list",
		"./BanEasyPrivacy.list",
		"./AI.list",
		"./MyCN.list",
		"./ProxyDNS.list",
		"./BlockiOSUpdate.list",
		"./Microsoft.list",
		"./Google.list",
		"./ProxyMedia.list",
		"./ProxyGFWlist.list",
		"./Apple.list",
		"./ChinaDomain.list",
	}
	// 生成去重后的文件，主要是针对广告规则，其余规则屏蔽
	deduplicatedFiles := []string{

		"./Rules/BanProgramAD.list",
		"./Rules/BanAD.list",
		"./Rules/BanEasyList.list",
		"./Rules/BanEasyListChina.list",
		"./Rules/BanEasyPrivacy.list",
		"./Rules/AI.list",
		"./Rules/MyCN.list",
		"./Rules/ProxyDNS.list",
		"./Rules/BlockiOSUpdate.list",
		"./Rules/Microsoft.list",
		"./Rules/Google.list",
		"./Rules/ProxyMedia.list",
		"./Rules/ProxyGFWlist.list",
		"./Rules/Apple.list",
		"./Rules/ChinaDomain.list",
	}

	// 规则去重与拆分
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

	// 生成 MOSDNS 规则
	outputFile := "./Rules/mosdns_rules.txt"
	err = generateMosdnsRules(selectedFiles, outputFile)
	if err != nil {
		fmt.Println("生成 MOSDNS 规则失败:", err)
		return
	}
}
