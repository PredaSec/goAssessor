package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

// models

type IpInfos struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	Ports     []int    `json:"ports"`
	CVEs      []string `json:"vulns"`
	CPES      []string `json:"cpes"`
	Nb_CVEs   int
}

type Cve_infos struct {
	CVE_id       string  `json:"cve_id"`
	CVSS         float64 `json:"cvss"`
	CVSS_version float64 `json:"cvss_version"`
	EPSS         float64 `json:"epss"`
	Reference    string
	KEV          bool `json:"kev"`
}

type CVESCAN struct {
	IP   string
	CVES []Cve_infos
}

type CVEInfoAPI struct {
	CVSS         float64 `json:"cvss"`
	CVSS_version float64 `json:"cvss_version"`
	EPSS         float64 `json:"epss"`
	//References   []string `json:"references"`
}

type FullScanData struct {
	Port    int                   `json:"port"`
	Product string                `json:"product"`
	Version string                `json:"version"`
	Vulns   map[string]CVEInfoAPI `json:"vulns"`
}

type APIScan struct {
	IP    string         `json:"ip_str"`
	ISP   string         `json:"isp"`
	Ports []int          `json:"ports"`
	Data  []FullScanData `json:"data"`
}

// runners

func (APIS *APIScan) FullScan(ip_add string, key string) {

	//init
	*APIS = APIScan{}

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%v?key=%v", ip_add, key)
	res, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}
		err = json.Unmarshal(bodyBytes, &APIS)
		if err != nil {
			fmt.Printf("\nproblem in json unmarshal\n")
			log.Fatal(err)
		}
	}
}

func (cs *CVESCAN) FillCve(targetIP string, cves []string, item *Cve_infos) {

	cs.IP = targetIP

	for _, d := range cves {
		item.Fetch_CVE_info(d)
		cs.CVES = append(cs.CVES, *item)
	}
}

func (cve *Cve_infos) Fetch_CVE_info(cve_id string) {
	// init
	*cve = Cve_infos{}

	url := fmt.Sprintf("https://cvedb.shodan.io/cve/%v", cve_id)
	res, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}

		err = json.Unmarshal(bodyBytes, &cve)
		if err != nil {
			log.Fatal(err)
		}
		cve.Reference = fmt.Sprintf("https://cvefeed.io/vuln/detail/%v", cve_id)
	}

}

func (Ipitem *IpInfos) Fetch_ip_info(ip_add string) {
	// init
	*Ipitem = IpInfos{}

	url := fmt.Sprintf("https://internetdb.shodan.io/%v", ip_add)
	res, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}

		err = json.Unmarshal(bodyBytes, &Ipitem)
		if err != nil {
			log.Fatal(err)
		}
	}

}

func (info *IpInfos) Cve_counter() {
	n := len(info.CVEs)
	info.Nb_CVEs = n
}
