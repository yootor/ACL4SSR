package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	// 引入 Mihomo 内核依赖
	constant "github.com/metacubex/mihomo/constant/provider"
	ruleProvider "github.com/metacubex/mihomo/rules/provider"
)

const maxFileSize = 2048 * 1024 // 2048KB 限制

type RuleLine struct {
	Raw       string
	RuleType  string
	Value     string
	UniqueKey string
	IsComment bool
}

func parseRuleLine(raw string) RuleLine {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return RuleLine{Raw: raw, IsComment: true}
	}

	cleanLine := line
	if idx := strings.Index(cleanLine, " //"); idx != -1 {
		cleanLine = strings.TrimSpace(cleanLine[:idx])
	}

	parts := strings.Split(cleanLine, ",")
	if len(parts) >= 2 {
		rType := strings.ToUpper(strings.TrimSpace(parts[0]))
		rVal := strings.TrimSpace(parts[1])
		rType = strings.ReplaceAll(rType, "_", "-")

		uniqueValue := rVal
		if len(parts) > 2 {
			uniqueValue += "," + strings.TrimSpace(strings.Join(parts[2:], ","))
		}

		return RuleLine{
			Raw:       raw,
			RuleType:  rType,
			Value:     rVal,
			UniqueKey: rType + "," + uniqueValue,
		}
	}

	return RuleLine{Raw: raw, IsComment: false}
}

// =====================================================================
// 核心逻辑：智能后缀包含判断 (附带顶级域名保护机制)
// =====================================================================
func isAbsorbedBySuffix(domain string, pool map[string]bool, isDomainRule bool) (bool, string) {
	checkDomain := domain

	// 如果是 DOMAIN 规则，首先检查它本身是否在后缀池中
	if isDomainRule && pool[checkDomain] {
		return true, checkDomain
	}

	// 逐级向上寻找父域名
	for {
		idx := strings.Index(checkDomain, ".")
		if idx == -1 {
			break
		}
		checkDomain = checkDomain[idx+1:]

		// 【顶级域名保护机制】：防止 `cn` 或 `com` 无差别吞噬一切。
		// 只有包含 "." 的域名（如 baidu.cn, com.cn）才有资格作为父级吞噬子域名。
		if !strings.Contains(checkDomain, ".") {
			break
		}

		if pool[checkDomain] {
			return true, checkDomain
		}
	}
	return false, ""
}

func buildSuffixPool(rawSuffixes []string) map[string]bool {
	sort.Slice(rawSuffixes, func(i, j int) bool {
		if len(rawSuffixes[i]) == len(rawSuffixes[j]) {
			return rawSuffixes[i] < rawSuffixes[j]
		}
		return len(rawSuffixes[i]) < len(rawSuffixes[j])
	})

	validSuffixes := make(map[string]bool)
	for _, d := range rawSuffixes {
		absorbed, _ := isAbsorbedBySuffix(d, validSuffixes, false)
		if !absorbed {
			validSuffixes[d] = true
		}
	}
	return validSuffixes
}

// =====================================================================
// 1. 策略文件去重 (严格单文件处理)
// =====================================================================
func processSingleFiles(inputFiles []string, outputDir string) error {
	os.MkdirAll(outputDir, 0755)
	fmt.Println("▶️ [阶段 1/3] 正在执行文件单文件去重...")

	for _, fileName := range inputFiles {
		file, err := os.Open(fileName)
		if err != nil {
			fmt.Printf("  ⚠️ 无法打开源文件 %s: %v\n", fileName, err)
			continue
		}

		var lines []RuleLine
		var localRawSuffixes []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			rl := parseRuleLine(scanner.Text())
			lines = append(lines, rl)
			if rl.RuleType == "DOMAIN-SUFFIX" {
				localRawSuffixes = append(localRawSuffixes, rl.Value)
			}
		}
		file.Close()

		localSuffixPool := buildSuffixPool(localRawSuffixes)
		localWritten := make(map[string]bool)

		pureName := strings.TrimSuffix(filepath.Base(fileName), ".list")
		basePath := filepath.Join(outputDir, pureName)
		outputFileName := fmt.Sprintf("%s.list", basePath)
		outFile, _ := os.Create(outputFileName)
		writer := bufio.NewWriter(outFile)

		header := fmt.Sprintf("#去重后的规则, 来源: https://github.com/ACL4SSR/ACL4SSR\n# 生成时间: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
		writer.WriteString(header)
		currentSize := len(header)
		fileIndex := 1

		for _, line := range lines {
			if line.IsComment || line.RuleType == "" {
				formatted := line.Raw + "\n"
				writer.WriteString(formatted)
				currentSize += len(formatted)
				continue
			}

			if localWritten[line.UniqueKey] {
				duplicateNote := fmt.Sprintf("# %s  # [文件内完全重复]\n", line.Raw)
				writer.WriteString(duplicateNote)
				currentSize += len(duplicateNote)
				continue
			}

			redundantNote := ""
			if line.RuleType == "DOMAIN-SUFFIX" {
				absorbed, parent := isAbsorbedBySuffix(line.Value, localSuffixPool, false)
				if absorbed {
					redundantNote = fmt.Sprintf("# %s  # [层级冗余] 已被本文件内 DOMAIN-SUFFIX,%s 包含\n", line.Raw, parent)
				}
			} else if line.RuleType == "DOMAIN" {
				absorbed, parent := isAbsorbedBySuffix(line.Value, localSuffixPool, true)
				if absorbed {
					redundantNote = fmt.Sprintf("# %s  # [降维冗余] 已被本文件内 DOMAIN-SUFFIX,%s 包含\n", line.Raw, parent)
				}
			}

			if redundantNote != "" {
				writer.WriteString(redundantNote)
				currentSize += len(redundantNote)
				continue
			}

			localWritten[line.UniqueKey] = true
			formattedLine := line.Raw + "\n"

			if currentSize+len(formattedLine) > maxFileSize {
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
				currentSize = len(header)
			}

			writer.WriteString(formattedLine)
			currentSize += len(formattedLine)
		}
		writer.Flush()
		outFile.Close()

		if fileIndex == 1 {
			originalName := fmt.Sprintf("%s.list", basePath)
			if _, err := os.Stat(fmt.Sprintf("%s_1.list", basePath)); err == nil {
				os.Rename(fmt.Sprintf("%s_1.list", basePath), originalName)
			}
		}
		fmt.Printf("  ✅ [%s] 单文件去重完成\n", pureName)
	}
	return nil
}

// =====================================================================
// 2. 去广告合集生成 (全局跨文件)
// =====================================================================
func buildGlobalAdBlock(inputFiles []string, outputDir string) error {
	fmt.Println("\n▶️ [阶段 2/3] 正在构建去广告合集 (MOSDNS & AdBlock)...")
	os.MkdirAll(outputDir, 0755)

	var allLines []RuleLine
	var globalRawSuffixes []string

	for _, fileName := range inputFiles {
		file, err := os.Open(fileName)
		if err != nil {
			fmt.Printf("  ⚠️ 无法打开源文件 %s: %v\n", fileName, err)
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			rl := parseRuleLine(scanner.Text())
			if !rl.IsComment && rl.RuleType != "" {
				allLines = append(allLines, rl)
				if rl.RuleType == "DOMAIN-SUFFIX" {
					globalRawSuffixes = append(globalRawSuffixes, rl.Value)
				}
			}
		}
		file.Close()
	}

	globalSuffixPool := buildSuffixPool(globalRawSuffixes)

	var clashAdRules []string
	var mosdnsKeyword, mosdnsDomain, mosdnsFull, mosdnsIp []string
	uniqueOutput := make(map[string]bool)

	for _, rl := range allLines {
		if uniqueOutput[rl.UniqueKey] {
			clashAdRules = append(clashAdRules, fmt.Sprintf("# %s  # [全局完全重复]", rl.Raw))
			continue
		}

		redundantNote := ""
		if rl.RuleType == "DOMAIN-SUFFIX" {
			absorbed, parent := isAbsorbedBySuffix(rl.Value, globalSuffixPool, false)
			if absorbed {
				redundantNote = fmt.Sprintf("# %s  # [全局层级冗余] 被全局 DOMAIN-SUFFIX,%s 包含", rl.Raw, parent)
			}
		} else if rl.RuleType == "DOMAIN" {
			absorbed, parent := isAbsorbedBySuffix(rl.Value, globalSuffixPool, true)
			if absorbed {
				redundantNote = fmt.Sprintf("# %s  # [全局降维冗余] 被全局 DOMAIN-SUFFIX,%s 包含", rl.Raw, parent)
			}
		}

		if redundantNote != "" {
			clashAdRules = append(clashAdRules, redundantNote)
			continue
		}

		uniqueOutput[rl.UniqueKey] = true
		clashAdRules = append(clashAdRules, rl.Raw)

		var mosdnsStr string
		isIp := false
		switch rl.RuleType {
		case "DOMAIN":
			mosdnsStr = "full:" + rl.Value
		case "DOMAIN-SUFFIX":
			mosdnsStr = "domain:" + rl.Value
		case "KEYWORD", "DOMAIN-KEYWORD":
			mosdnsStr = "keyword:" + rl.Value
		case "IP-CIDR", "IP-CIDR6":
			mosdnsStr = rl.Value
			isIp = true
		}

		if mosdnsStr != "" {
			if isIp {
				mosdnsIp = append(mosdnsIp, mosdnsStr)
			} else if rl.RuleType == "DOMAIN" {
				mosdnsFull = append(mosdnsFull, mosdnsStr)
			} else if rl.RuleType == "DOMAIN-SUFFIX" {
				mosdnsDomain = append(mosdnsDomain, mosdnsStr)
			} else {
				mosdnsKeyword = append(mosdnsKeyword, mosdnsStr)
			}
		}
	}

	clashOutPath := filepath.Join(outputDir, "Adblock.list")
	clashFile, _ := os.Create(clashOutPath)
	cw := bufio.NewWriter(clashFile)
	fmt.Fprintf(cw, "# 全局去重广告拦截合集\n# 生成时间: %s\n# 包含原始记录: %d 条\n\n", time.Now().Format("2006-01-02 15:04:05"), len(clashAdRules))
	cw.WriteString(strings.Join(clashAdRules, "\n") + "\n")
	cw.Flush()
	clashFile.Close()
	fmt.Printf("  ✅ [%s] 已生成\n", clashOutPath)

	sort.Strings(mosdnsKeyword)
	sort.Strings(mosdnsDomain)
	sort.Strings(mosdnsFull)
	sort.Strings(mosdnsIp)

	mosdnsOutPath := filepath.Join(outputDir, "mosdns_rules.txt")
	mosdnsFile, _ := os.Create(mosdnsOutPath)
	mw := bufio.NewWriter(mosdnsFile)
	fmt.Fprintf(mw, "# MOSDNS 规则生成时间: %s\n# 有效规则统计 - Keyword: %d, Domain: %d, Full: %d, IP-CIDR: %d\n\n",
		time.Now().Format("2006-01-02 15:04:05"),
		len(mosdnsKeyword), len(mosdnsDomain), len(mosdnsFull), len(mosdnsIp))

	fmt.Fprintf(mw, "# 关键字规则\n%s\n\n# 域名规则\n%s\n\n# 全匹配\n%s\n",
		strings.Join(mosdnsKeyword, "\n"), strings.Join(mosdnsDomain, "\n"), strings.Join(mosdnsFull, "\n"))

	if len(mosdnsIp) > 0 {
		fmt.Fprintf(mw, "\n# IP-CIDR 规则\n%s\n", strings.Join(mosdnsIp, "\n"))
	}
	mw.Flush()
	mosdnsFile.Close()
	fmt.Printf("  ✅ [%s] 已生成\n", mosdnsOutPath)

	return nil
}

// =====================================================================
// 3. MRS 编译模块
// =====================================================================
type MrsTask struct {
	TargetName string
	Sources    []string
}

func compileMrsTasks(tasks []MrsTask, outputDir string) {
	os.MkdirAll(outputDir, 0755)
	fmt.Println("\n▶️ [阶段 3/3] 开始执行 MRS 编译任务...")

	for _, task := range tasks {
		var allPayloads []string
		payloadSet := make(map[string]bool)

		for _, source := range task.Sources {
			file, err := os.Open(source)
			if err != nil {
				continue
			}

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				rl := parseRuleLine(scanner.Text())
				if rl.IsComment || rl.RuleType == "" {
					continue
				}
				if rl.RuleType == "DOMAIN" || rl.RuleType == "DOMAIN-SUFFIX" {
					p := rl.Value
					if rl.RuleType == "DOMAIN-SUFFIX" {
						p = "+." + strings.TrimPrefix(p, ".")
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
				fmt.Printf("  ❌ [%s] 编译失败: %v\n", task.TargetName, err)
			} else {
				fmt.Printf("  ✅ [%s] 编译完成 (包含 %d 条有效规则)\n", task.TargetName, len(allPayloads))
			}
		}
	}
}

func main() {
	fmt.Println("🚀 开始执行自动化规则构建任务...")

	singleProcessFiles := []string{
		"./MyCN.list",
		"./MyProxy.list",
		"./ProxyDNS.list",
		"./AI.list",
		"./Google.list",
		"./ProxyMedia.list",
		"./Microsoft.list",
		"./ProxyGFW.list",
		"./Apple.list",
		"./ChinaDomain.list",
		"./BlockiOSUpdate.list",
	}
	processSingleFiles(singleProcessFiles, "./Rules")

	adBlockSources := []string{
		"./BanProgramAD.list",
		"./BanAD.list",
		"./BanEasyList.list",
		"./BanEasyListChina.list",
		"./BanEasyPrivacy.list",
	}
	buildGlobalAdBlock(adBlockSources, "./Rules")

	mrsTasks := []MrsTask{
		{
			TargetName: "AdBlock.mrs",
			Sources: []string{
				"./Rules/Adblock.list",
			},
		},
		{
			TargetName: "ProxyGFW.mrs",
			Sources: []string{
				"./Rules/ProxyGFW.list",
			},
		},
	}
	compileMrsTasks(mrsTasks, "./Mrs")

	fmt.Println("\n✨ 全部构建任务完美收工！")
}
