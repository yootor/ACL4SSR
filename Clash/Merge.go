package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	// 引入 Mihomo 内核依赖
	constant "github.com/metacubex/mihomo/constant/provider"
	ruleProvider "github.com/metacubex/mihomo/rules/provider"
)

const maxFileSize = 2048 * 1024 // 2048KB 限制

// =====================================================================
// 1. 规则去重
// =====================================================================
func deduplicateFiles(inputFiles []string, outputDir string) error {
	ruleSet := make(map[string]string)
	domainRegex := regexp.MustCompile(`(?i)(DOMAIN|DOMAIN-SUFFIX|KEYWORD|IP-CIDR),([^"\s]+)`)

	os.MkdirAll(outputDir, 0755)

	for _, fileName := range inputFiles {
		file, err := os.Open(fileName)
		if err != nil {
			fmt.Printf("   ⚠️ 无法打开源文件 %s: %v\n", fileName, err)
			continue
		}
		defer file.Close()

		pureName := strings.TrimSuffix(filepath.Base(fileName), ".list")
		basePath := filepath.Join(outputDir, pureName)
		outputFileName := fmt.Sprintf("%s.list", basePath)

		outFile, err := os.Create(outputFileName)
		if err != nil {
			return err
		}

		writer := bufio.NewWriter(outFile)
		currentSize := 0
		header := fmt.Sprintf("# 去重后的规则, 来源: https://github.com/ACL4SSR/ACL4SSR\n# 生成时间: %s\n\n",
			time.Now().Format("2006-01-02 15:04:05"))
		writer.WriteString(header)
		writer.Flush()
		currentSize += len(header)

		scanner := bufio.NewScanner(file)
		fileIndex := 1
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				writer.WriteString(line + "\n")
				currentSize += len(line) + 1
				continue
			}

			matches := domainRegex.FindStringSubmatch(line)
			if len(matches) == 3 {
				_, value := matches[1], matches[2]
				if originalFile, exists := ruleSet[value]; exists {
					duplicateNote := fmt.Sprintf("# %s  # 与 %s 重复\n", line, filepath.Base(originalFile))
					writer.WriteString(duplicateNote)
					currentSize += len(duplicateNote)
				} else {
					ruleSet[value] = fileName
					formattedLine := line + "\n"
					lineSize := len(formattedLine)
					if currentSize+lineSize > maxFileSize {
						writer.Flush()
						outFile.Close()
						if fileIndex == 1 {
							os.Rename(outputFileName, fmt.Sprintf("%s_1.list", basePath))
						}
						fileIndex++
						outputFileName = fmt.Sprintf("%s_%d.list", basePath, fileIndex)
						outFile, _ = os.Create(outputFileName)
						writer = bufio.NewWriter(outFile)
						writer.WriteString(header)
						writer.Flush()
						currentSize = len(header)
					}
					writer.WriteString(formattedLine)
					currentSize += lineSize
				}
			} else {
				formattedLine := line + "\n"
				lineSize := len(formattedLine)
				if currentSize+lineSize > maxFileSize {
					writer.Flush()
					outFile.Close()
					if fileIndex == 1 {
						os.Rename(outputFileName, fmt.Sprintf("%s_1.list", basePath))
					}
					fileIndex++
					outputFileName = fmt.Sprintf("%s_%d.list", basePath, fileIndex)
					outFile, _ = os.Create(outputFileName)
					writer = bufio.NewWriter(outFile)
					writer.WriteString(header)
					writer.Flush()
					currentSize = len(header)
				}
				writer.WriteString(formattedLine)
				currentSize += lineSize
			}
		}
		writer.Flush()
		outFile.Close()
		fmt.Println("   ✅ 去重后的规则已生成:", outputFileName)

		if fileIndex == 1 {
			originalName := fmt.Sprintf("%s.list", basePath)
			if _, err := os.Stat(fmt.Sprintf("%s_1.list", basePath)); err == nil {
				os.Rename(fmt.Sprintf("%s_1.list", basePath), originalName)
			}
		}
	}
	return nil
}

// =====================================================================
// 2. MOSDNS 规则生成
// =====================================================================
func generateMosdnsRules(inputFiles []string, outputFile string) error {
	var keywordRules, domainRules, fullRules []string
	domainRegex := regexp.MustCompile(`(?i)(DOMAIN|DOMAIN-SUFFIX|KEYWORD),([^"\s]+)`)
	for _, fileName := range inputFiles {
		file, err := os.Open(fileName)
		if err != nil {
			continue
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			matches := domainRegex.FindStringSubmatch(line)
			if len(matches) == 3 {
				t, v := strings.ToUpper(matches[1]), matches[2]
				switch t {
				case "DOMAIN":
					fullRules = append(fullRules, "full:"+v)
				case "DOMAIN-SUFFIX":
					domainRules = append(domainRules, "domain:"+v)
				case "KEYWORD":
					keywordRules = append(keywordRules, "keyword:"+v)
				}
			}
		}
	}
	sort.Strings(keywordRules)
	sort.Strings(domainRules)
	sort.Strings(fullRules)
	outFile, _ := os.Create(outputFile)
	defer outFile.Close()
	w := bufio.NewWriter(outFile)
	fmt.Fprintf(w, "# MOSDNS 规则生成时间: %s\n\n# 关键字规则\n%s\n\n# 域名规则\n%s\n\n# 全匹配\n%s\n",
		time.Now().Format("2006-01-02 15:04:05"), strings.Join(keywordRules, "\n"), strings.Join(domainRules, "\n"), strings.Join(fullRules, "\n"))
	return w.Flush()
}

// =====================================================================
// 3. MRS 编译模块，只支持domain规则，不支持keywords和IP-CIDR (支持多任务、多文件合并)
// =====================================================================

type MrsTask struct {
	TargetName string   // 目标文件名 (如 Ads.mrs)
	Sources    []string // 来源 .list 文件路径
}

func compileMrsTasks(tasks []MrsTask, outputDir string) {
	os.MkdirAll(outputDir, 0755)
	fmt.Println("\n▶️ 开始执行 MRS 编译任务...")

	for _, task := range tasks {
		var allPayloads []string
		payloadSet := make(map[string]bool)

		for _, source := range task.Sources {
			file, err := os.Open(source)
			if err != nil {
				continue
			}

			domainRegex := regexp.MustCompile(`(?i)^(DOMAIN|DOMAIN-SUFFIX),([^,\s]+)`)
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				matches := domainRegex.FindStringSubmatch(line)
				if len(matches) == 3 {
					t, v := strings.ToUpper(matches[1]), matches[2]
					p := v
					if t == "DOMAIN-SUFFIX" {
						p = "+." + strings.TrimPrefix(v, ".")
					}
					if !payloadSet[p] {
						payloadSet[p] = true
						allPayloads = append(allPayloads, p)
					}
				}
			}
			file.Close()
		}

		if len(allPayloads) > 0 {
			outPath := filepath.Join(outputDir, task.TargetName)
			outFile, _ := os.Create(outPath)

			// 捕获可能由于内核版本不一致导致的崩溃
			err := func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("%v", r)
					}
				}()
				return ruleProvider.ConvertToMrs([]byte(strings.Join(allPayloads, "\n")), constant.Domain, constant.TextRule, outFile)
			}()
			outFile.Close()

			if err != nil {
				fmt.Printf("   ❌ [%s] 编译失败: %v\n", task.TargetName, err)
			} else {
				fmt.Printf("   ✅ [%s] 编译完成 (包含 %d 条规则)\n", task.TargetName, len(allPayloads))
			}
		}
	}
}

func main() {
	// 🟢 [配置1] 所有需要去重的源文件
	allInputFiles := []string{
		"./BanProgramAD.list",
		"./BanAD.list",
		"./BanEasyList.list",
		"./BanEasyListChina.list",
		"./BanEasyPrivacy.list",
		"./MyCN.list",
		"./MyProxy.list",
		"./ProxyDNS.list",
		"./AI.list",
		"./Google.list",
		"./ProxyMedia.list",
		"./Microsoft.list",
		"./ProxyGFWlist.list",
		"./Apple.list",
		"./ChinaDomain.list",
		"./BlockiOSUpdate.list",
	}

	fmt.Println("🚀 开始执行自动化规则构建任务...")

	// 1. 执行规则去重
	deduplicateFiles(allInputFiles, "./Rules")

	// 🟢 选择需要转换为 MOSDNS的规则
	mosdnsSources := []string{
		"./Rules/BanProgramAD.list",
		"./Rules/BanAD.list",
		"./Rules/BanEasyList.list",
		"./Rules/BanEasyListChina.list",
		"./Rules/BanEasyPrivacy.list",
	}
	generateMosdnsRules(mosdnsSources, "./Rules/mosdns_rules.txt")

	// 🟢 自定义 MRS 任务区
	mrsTasks := []MrsTask{
		{
			// 任务A：合并去广告规则
			TargetName: "AdBlock.mrs",
			Sources: []string{
				"./Rules/BanProgramAD.list",
				"./Rules/BanAD.list",
				"./Rules/BanEasyList.list",
				"./Rules/BanEasyListChina.list",
				"./Rules/BanEasyPrivacy.list",
			},
		},
		{
			// 任务B：配置生成MRS的其余规则文件
			TargetName: "ProxyGFW.mrs",
			Sources: []string{
				"./Rules/ProxyGFW.list",
			},
		},
		/*{
			// 任务C：如果你想把 Google 也转成 MRS，就加一条
			TargetName: "Google.mrs",
			Sources:    []string{
				"./Rules/Google.list",
			},
		},*/
	}

	// 2. 执行 MRS 编译
	compileMrsTasks(mrsTasks, "./Mrs")

	fmt.Println("\n✨ 全部任务执行完毕！")
}
