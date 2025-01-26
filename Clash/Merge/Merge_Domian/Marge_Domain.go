package main

//合并规则、去重、胜场MOSDNS规则和Clash规则，并且针对一级域名相同有5个以上的规则合并成一个规则，使用一级域名后缀的方式匹配，会误杀

import (
	"bufio"
	//"fmt"
	"os"
	"strings"
	"time"
)

func extractPrimaryDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, ".")
}

func classifyRules(ruleSet map[string]struct{}) map[string][]string {
	groupedRules := make(map[string][]string)
	for rule := range ruleSet {
		primaryDomain := extractPrimaryDomain(rule)
		groupedRules[primaryDomain] = append(groupedRules[primaryDomain], rule)
	}
	return groupedRules
}

func processFile(Merge string, ruleSet map[string]struct{}, keywordRules *[]string, ipRules *[]string) error {
	file, err := os.Open(Merge)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { // 忽略空行和注释行
			continue
		}
		if strings.Contains(line, "IP-CIDR") { // 收集 IP 规则
			*ipRules = append(*ipRules, line)
		} else if strings.HasPrefix(line, "DOMAIN-KEYWORD,") || strings.HasPrefix(line, "KEYWORD,") { // 收集并去掉前缀的 keyword 规则
			cleanRule := strings.TrimPrefix(strings.TrimPrefix(line, "DOMAIN-KEYWORD,"), "KEYWORD,")
			*keywordRules = append(*keywordRules, cleanRule)
		} else if strings.HasPrefix(line, "DOMAIN-SUFFIX,") { // 去掉 DOMAIN-SUFFIX 前缀
			domain := strings.TrimPrefix(line, "DOMAIN-SUFFIX,")
			ruleSet[domain] = struct{}{}
		} else { // 其他规则直接添加
			ruleSet[line] = struct{}{}
		}

		if err := scanner.Err(); err != nil {
			return err
		}
	}
	return nil
}

func writeMosdnsFile(filename string, ruleSet map[string]struct{}, keywordRules []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// 写入注释和当前时间
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err = writer.WriteString("# Merged and deduplicated rules\n")
	if err != nil {
		return err
	}
	_, err = writer.WriteString("# Generated on: " + now + "\n\n")
	if err != nil {
		return err
	}

	// 用于去重的 map
	writtenRules := make(map[string]struct{})

	// 写入 keyword 规则
	for _, rule := range keywordRules {
		keywordRule := "KEYWORD," + rule
		if _, exists := writtenRules[keywordRule]; !exists {
			writtenRules[keywordRule] = struct{}{}
			_, err := writer.WriteString(keywordRule + "\n")
			if err != nil {
				return err
			}
		}
	}

	// 写入一个空白行，并增加说明

	_, err = writer.WriteString(" \n")
	if err != nil {
		return err
	}
	_, err = writer.WriteString("#以下部分是Domain规则 \n")
	if err != nil {
		return err
	}

	// 将规则按一级域名分组
	groupedRules := classifyRules(ruleSet)

	// 写入其他规则
	for primaryDomain, rules := range groupedRules {
		if len(rules) > 5 { // 如果子域数量多于 5，则合并为一级域名规则
			domainRule := primaryDomain
			if _, exists := writtenRules[domainRule]; !exists {
				writtenRules[domainRule] = struct{}{}
				_, err := writer.WriteString(domainRule + "\n")
				if err != nil {
					return err
				}
			}
		} else { // 否则逐个写入子域规则
			for _, rule := range rules {
				domainRule := rule
				if _, exists := writtenRules[domainRule]; !exists {
					writtenRules[domainRule] = struct{}{}
					_, err := writer.WriteString(domainRule + "\n")
					if err != nil {
						return err
					}
				}
			}
		}
	}

	// 刷新缓冲区
	return writer.Flush()
}

func writeClashFile(filename string, ruleSet map[string]struct{}, keywordRules, ipRules []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// 写入注释和当前时间
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err = writer.WriteString("# Merged and deduplicated rules\n")
	if err != nil {
		return err
	}
	_, err = writer.WriteString("# Generated on: " + now + "\n\n")
	if err != nil {
		return err
	}

	// 用于去重的 map
	writtenRules := make(map[string]struct{})

	// 写入 keyword 规则
	for _, rule := range keywordRules {
		keywordRule := "KEYWORD," + rule
		if _, exists := writtenRules[keywordRule]; !exists {
			writtenRules[keywordRule] = struct{}{}
			_, err := writer.WriteString(keywordRule + "\n")
			if err != nil {
				return err
			}
		}
	}

	// 写入一个空白行，并增加说明

	_, err = writer.WriteString(" \n")
	if err != nil {
		return err
	}
	_, err = writer.WriteString("#以下部分是Domain规则 \n")
	if err != nil {
		return err
	}

	// 将规则按一级域名分组
	groupedRules := classifyRules(ruleSet)

	// 写入其他规则
	for primaryDomain, rules := range groupedRules {
		if len(rules) > 5 { // 如果子域数量多于 5，则合并为一级域名规则
			domainRule := "DOMAIN-SUFFIX," + primaryDomain
			if _, exists := writtenRules[domainRule]; !exists {
				writtenRules[domainRule] = struct{}{}
				_, err := writer.WriteString(domainRule + "\n")
				if err != nil {
					return err
				}
			}
		} else { // 否则逐个写入子域规则
			for _, rule := range rules {
				domainRule := "DOMAIN-SUFFIX," + rule
				if _, exists := writtenRules[domainRule]; !exists {
					writtenRules[domainRule] = struct{}{}
					_, err := writer.WriteString(domainRule + "\n")
					if err != nil {
						return err
					}
				}
			}
		}
	}

	// 写入一个空白行，并增加说明

	_, err = writer.WriteString(" \n")
	if err != nil {
		return err
	}
	_, err = writer.WriteString("#以下部分是IP规则, 只用于Clash \n")
	if err != nil {
		return err
	}

	// 写入 IP 规则
	for _, rule := range ipRules {
		if _, exists := writtenRules[rule]; !exists {
			writtenRules[rule] = struct{}{}
			_, err := writer.WriteString(rule + "\n")
			if err != nil {
				return err
			}
		}
	}

	// 刷新缓冲区
	return writer.Flush()
}

func main() {
	inputFiles := []string{
		"C:/Users/Kobe/Documents/GitHub/ACL4SSR/Clash/Anti_AD.txt",
		"C:/Users/Kobe/Documents/GitHub/ACL4SSR/Clash/BanAD.list",
		"C:/Users/Kobe/Documents/GitHub/ACL4SSR/Clash/BanEasyList.list",
		"C:/Users/Kobe/Documents/GitHub/ACL4SSR/Clash/BanEasyListChina.list",
		"C:/Users/Kobe/Documents/GitHub/ACL4SSR/Clash/BanProgramAD.list",
	} // 示例文件列表
	ruleSet := make(map[string]struct{})
	keywordRules := []string{}
	ipRules := []string{}

	for _, fileName := range inputFiles {
		err := processFile(fileName, ruleSet, &keywordRules, &ipRules)
		if err != nil {
			panic(err)
		}
	}

	outputFile := "Mosdns_AD_test.txt"
	err := writeMosdnsFile(outputFile, ruleSet, keywordRules)
	if err != nil {
		panic(err)
	}

	println("Rules have been successfully processed and saved to", outputFile)

	outputFile = "Clash_AD_Test.txt"
	err = writeClashFile(outputFile, ruleSet, keywordRules, ipRules)
	if err != nil {
		panic(err)
	}

	println("Rules have been successfully processed and saved to", outputFile)
}
