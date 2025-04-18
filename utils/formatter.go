package utils

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const banner = `
                     █████████                                                              
                    ███░░░░░███                                                             
  ███████  ██████  ░███    ░███   █████   █████   ██████   █████   █████   ██████  ████████ 
 ███░░███ ███░░███ ░███████████  ███░░   ███░░   ███░░███ ███░░   ███░░   ███░░███░░███░░███
░███ ░███░███ ░███ ░███░░░░░███ ░░█████ ░░█████ ░███████ ░░█████ ░░█████ ░███ ░███ ░███ ░░░ 
░███ ░███░███ ░███ ░███    ░███  ░░░░███ ░░░░███░███░░░   ░░░░███ ░░░░███░███ ░███ ░███     
░░███████░░██████  █████   █████ ██████  ██████ ░░██████  ██████  ██████ ░░██████  █████    
 ░░░░░███ ░░░░░░  ░░░░░   ░░░░░ ░░░░░░  ░░░░░░   ░░░░░░  ░░░░░░  ░░░░░░   ░░░░░░  ░░░░░     
 ███ ░███                                                                                   
░░██████                                                                                    
 ░░░░░░                                                                               v1.0    `

func VerifyIP(Ip string) bool {
	r, _ := regexp.Compile(`\b((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\b`) // thank you chatgpt
	return r.MatchString(Ip)
}

func VerifyFile(filepath string) []string {
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatal("error opening file:", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	var lines []string
	for scanner.Scan() {
		if !VerifyIP(scanner.Text()) {
			print("Something wrong with the file!")
			os.Exit(0)
		}
		lines = append(lines, scanner.Text())
	}
	return lines
}

func VerifyFileName(s string) bool {
	r, _ := regexp.Compile("^[a-zA-Z0-9]+$")
	return r.MatchString(s)
}

func ConvertCPE(s []string) string {
	var res []string
	for _, d := range s {
		part := strings.SplitN(d, ":", 3)
		res = append(res, part[2])
	}
	return strings.Join(res, ", ")
}

func VerifyAPIKey(s string) {
	res, _ := http.Get(fmt.Sprintf("https://api.shodan.io/api-info?key=%v", s))
	if res.StatusCode != http.StatusOK {
		print("Invalid API key")
		os.Exit(0)
	}
}

func ShowBanner() {
	fmt.Printf("%s\n", banner)
	fmt.Printf("\t\tPredaSec \n\n")
	fmt.Printf("[WARNING]: \n- Use with caution\n[WARNING]: \n- Zoom out for clear results in CLI\n[DISCLAIMER]: \n - internetdb (free Shodan API) is only updated once a week whereas the regular shodan API is updated in real-time\n\n\n")
}
