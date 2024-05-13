package main

import (
	"fmt"

	"github.com/hz157/gowaf"
)

func main() {
	gowaf.ThreatBookInit("key")
	threatData, _ := gowaf.GetThreat("110.242.68.66", "zh")
	fmt.Println(threatData)
	// 遍历 ThreatbookLab、XReward 和 OpenSource 中的每个威胁情报
	for _, threatSource := range threatData.Intelligences.ThreatbookLab {
		// 执行匹配
		if gowaf.FilterIntelType(threatSource) {
			// 威胁类型匹配成功，采取相应的操作
			fmt.Println("Threat matched - ThreatbookLab:", threatSource)
		}
	}

	for _, threatSource := range threatData.Intelligences.XReward {
		// 执行匹配
		if gowaf.FilterIntelType(threatSource) {
			// 威胁类型匹配成功，采取相应的操作
			fmt.Println("Threat matched - XReward:", threatSource)
		}
	}

	for _, threatSource := range threatData.Intelligences.OpenSource {
		// 执行匹配
		if gowaf.FilterIntelType(threatSource) {
			// 威胁类型匹配成功，采取相应的操作
			fmt.Println("Threat matched: - OpenSource", threatSource)
		}
	}

}
