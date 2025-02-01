package main

//合并规则、去重、胜场MOSDNS规则和Clash规则

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	// 输入文件列表
	inputFiles := []string{
		"./BanAD.list",
		"./BanEasyList.list",
		"./BanEasyListChina.list",
		"./BanEasyPrivacy.list",
		"./BanProgramAD.list",
	} // 替换为你的文件名

	// 输出 MOSDNS 文件
	mosdnsFile := "Mosdns_AD.txt"
	// 输出 Clash 规则文件
	//clashFile := "Clash_AD.list"

	// 创建一个集合用于存储规则并去重
	ruleSet := make(map[string]struct{})
	keywordRules := []string{} // 存储包含 keyword 的规则
	ipRules := []string{}      // 存储 IP 规则

	// 遍历输入文件并读取规则
	for _, file := range inputFiles {
		if err := processFile(file, ruleSet, &keywordRules, &ipRules); err != nil {
			fmt.Printf("Error processing file %s: %v\n", file, err)
		}
	}

	// 写入 MOSDNS 规则文件（将 keyword 规则放在最前面），写入异常报错
	if err := writeMosdnsFile(mosdnsFile, ruleSet, keywordRules); err != nil {
		fmt.Printf("Error writing MOSDNS file %s: %v\n", mosdnsFile, err)
	} else {
		fmt.Printf("MOSDNS rules written to %s\n", mosdnsFile)
	}
	/*
		// 生成 Clash 格式规则文件（域名规则和 IP 规则），写入异常报错
		if err := writeClashFile(clashFile, ruleSet, ipRules, keywordRules); err != nil {
			fmt.Printf("Error writing Clash file %s: %v\n", clashFile, err)
		} else {
			fmt.Printf("Clash rules written to %s\n", clashFile)
		}
	*/
}

// 处理单个文件，将规则加入集合、keyword 列表和 IP 列表
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

// 写入 MOSDNS 文件（将 keyword 规则放在最前面，其他域名规则排序后写入）
func writeMosdnsFile(mosdnsFile string, ruleSet map[string]struct{}, keywordRules []string) error {
	file, err := os.Create(mosdnsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// 写入注释和当前时间
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err = writer.WriteString("#规则合并ACL4SSR与Anti-AD规则 \n")
	if err != nil {
		return err
	}
	_, err = writer.WriteString("# 修改时间: " + now + "\n\n")
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

	// 写入Rules规则
	domains := []string{}
	for domain := range ruleSet {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	for _, domain := range domains {
		domainRule := "DOMAIN," + domain
		if _, exists := writtenRules[domainRule]; !exists {
			writtenRules[domainRule] = struct{}{}
			_, err := writer.WriteString(domainRule + "\n")
			if err != nil {
				return err
			}
		}
	}
	// 刷新缓冲区
	return writer.Flush()
}

/*// 写入 Clash 文件（包含域名规则和 IP 规则，不对 keyword 规则添加 DOMAIN-SUFFIX, 前缀）

func writeClashFile(clashFile string, ruleSet map[string]struct{}, ipRules []string, keywordRules []string) error {
	output, err := os.Create(clashFile)
	if err != nil {
		return err
	}
	defer output.Close()

	writer := bufio.NewWriter(output)

	// 写入注释和当前时间
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err = writer.WriteString("#规则合并ACL4SSR与Anti-AD规则 \n")
	if err != nil {
		return err
	}
	_, err = writer.WriteString("# 修改时间: " + now + "\n\n")
	if err != nil {
		return err
	}

	// 用于去重的 map
	writtenRules := make(map[string]struct{})

	// 写入 keyword 规则
	for _, rule := range keywordRules {
		keywordRule := "DOMAIN-KEYWORD," + rule
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

	// 写入Rules规则
	domains := []string{}
	for domain := range ruleSet {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	for _, domain := range domains {
		clashRule := "DOMAIN-SUFFIX," + domain
		if _, exists := writtenRules[clashRule]; !exists {
			writtenRules[clashRule] = struct{}{}
			_, err := writer.WriteString(clashRule + "\n")
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
	_, err = writer.WriteString("#以下部分是IP规则, 适用于Clash \n")
	if err != nil {
		return err
	}

	// 添加 IP 规则到文件末尾，先排序
	sort.Strings(ipRules)

	for _, ipRule := range ipRules {
		if _, exists := writtenRules[ipRule]; !exists {
			writtenRules[ipRule] = struct{}{}
			_, err := writer.WriteString(ipRule + "\n")
			if err != nil {
				return err
			}
		}
	}
	// 刷新缓冲区
	return writer.Flush()
}

*/
