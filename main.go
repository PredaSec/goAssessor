package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PredaSec/goAssessor/runner"
	"github.com/PredaSec/goAssessor/utils"
)

func main() {

	utils.ShowBanner()

	var targetIP string
	var targetFile string
	var APIKey string
	var op string
	var convert2csv string

	flag.StringVar(&targetIP, "target", "", "IP Address")
	flag.StringVar(&targetFile, "list", "", "Text file of IPs")
	flag.StringVar(&APIKey, "key", "", "Shodan API key (required when using fullscan)")
	flag.StringVar(&op, "op", "", "ipscan: IP Reconnaissance\ncvescan: Vulnerability Scan\nfullscan: IP Reconnaissance + Vulnerability Scan")
	flag.StringVar(&convert2csv, "convert2csv", "", "Save output to CSV file (default output is CLI table)")

	flag.Parse()

	// check if no flags are provided
	if flag.NFlag() == 0 {
		fmt.Println("Type -h for usage")
		os.Exit(0)
	}

	//check if there are two entries
	if (targetIP != "") && (targetFile != "") {
		fmt.Println("You cannot provide a list and IP at the same time!")
		os.Exit(0)
	}

	// target 
	var target []string
	if targetIP != "" {
		if !utils.VerifyIP(targetIP) {
			fmt.Println("Invalid IP")
			os.Exit(0)
		}
		target = append(target, targetIP)
	} else {
		target = utils.VerifyFile(targetFile)
	}

	// output verification
	OutIsCSV := false
	if convert2csv != "" && utils.VerifyFileName(convert2csv) {
		OutIsCSV = true
	} else if convert2csv != "" {
		fmt.Println("Invalid CSV filename!")
		os.Exit(0)
	}

	var ipItem = &runner.IpInfos{}
	switch op {
	case "ipscan":
		var IpCollection = &[]runner.IpInfos{}
		for _, d := range target {

			//remove spaces
			trimmed := strings.TrimSpace(d)
			ipItem.Fetch_ip_info(trimmed)

			// check for information existance
			if ipItem.IP != "" {
				//calculate cves number
				ipItem.Cve_counter()
				// collect results 
				*IpCollection = append(*IpCollection, *ipItem)
			}
		}
		if OutIsCSV {
			utils.ProcessCollection2CSV(IpCollection, convert2csv)
		} else {
			// print results into table
			utils.Iptabler(IpCollection)
		}

	case "cvescan":
		var CveCollection = &[]runner.CVESCAN{}
		var cveScan = &runner.CVESCAN{}
		var cveItem = &runner.Cve_infos{}

		for _, d := range target {
			trimmed := strings.TrimSpace(d)
			ipItem.Fetch_ip_info(trimmed)
			if (ipItem.IP != "") && (len(ipItem.CVEs) != 0) { // checking if there is info associated with the ip and it has cves
				cveScan.FillCve(ipItem.IP, ipItem.CVEs, cveItem)  // fetch cves (ip + cves x [cve_info])
				*CveCollection = append(*CveCollection, *cveScan) // collect results (ips + cves info)
			}
		}
		if OutIsCSV {
			utils.ProcessCollection2CSV(CveCollection, convert2csv)
		} else {
			// print results into table
			utils.CVETabler(CveCollection)
		}

	case "fullscan":
		if APIKey == "" {
			fmt.Println("You need to provide an API key for this operation")
			os.Exit(0)
		} else {
			utils.VerifyAPIKey(APIKey)
		}
		var localFullScan = &runner.APIScan{}
		var APICollection = &[]runner.APIScan{}
		for i, d := range target {
			trimmed := strings.TrimSpace(d)
			localFullScan.FullScan(trimmed, APIKey)
			if localFullScan.IP != "" { // checking if data not empty
				*APICollection = append(*APICollection, *localFullScan) // append results
			}
			if i != len(target)-1 {
				time.Sleep(time.Second) //rate limit of 1 request per second (for all api plan in shodan)
			}
		}
		if OutIsCSV {
			utils.ProcessCollection2CSV(APICollection, convert2csv)
		} else {
			// print results into table
			utils.FullscanTabler(APICollection)
		}
	default:
		fmt.Printf("Invalid operation! \nType 'goAssessor -h' for more information.")

	}
}
