package utils

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/predasec/goAssessor/runner"
	"github.com/olekukonko/tablewriter"
)

type Collection interface {
	*[]runner.IpInfos | *[]runner.CVESCAN | *[]runner.APIScan
}

func Iptabler(data *[]runner.IpInfos) {

	table := tablewriter.NewWriter(os.Stdout) //init table
	table.SetHeader([]string{"IP", "Ports", "Hostnames",
		"CPEs", "CVEs count°"})
	table.SetRowLine(true)
	for _, v := range *data {

		// convert ip to []string
		ipstr := make([]string, 1)
		ipstr[0] = v.IP
		uppip := strings.Join(ipstr, ", ")
		// convert ports[]int to ports[]string
		portstr := make([]string, len(v.Ports))
		for i, z := range v.Ports {
			portstr[i] = strconv.Itoa(z)
		}
		strports := strings.Join(portstr, ", ")

		// convert cvenb int to cvenb string
		cvestr := make([]string, 1)
		cvestr[0] = strconv.Itoa(v.Nb_CVEs)
		uppcves := strings.Join(cvestr, " ")

		// convert hostnames to hostnames[]string
		hoststr := make([]string, len(v.Hostnames))
		copy(hoststr, v.Hostnames)
		pphost := strings.Join(hoststr, " ")

		// convert cpes to cpes[]string
		cpestr := make([]string, len(v.CPES))
		for i, d := range v.CPES {
			d := strings.SplitN(d, ":", 3)
			cpestr[i] = d[2]
		}
		uppcpes := strings.Join(cpestr, " ")

		row := [][]string{
			{uppip,
				strports,
				pphost,
				uppcpes,
				uppcves,
			},
		}

		table.AppendBulk(row)
	}
	table.Render()

}

func CVETabler(data *[]runner.CVESCAN) {
	table := tablewriter.NewWriter(os.Stdout) //init table
	table.SetHeader([]string{"IP", "CVE ID", "CVSS", "CVSS Version",
		"EPSS", "Reference", "Is KEV?"})
	table.SetRowLine(true)
	for _, v := range *data {
		for _, d := range v.CVES {

			// convert kev to kev string
			kevstr := make([]string, 1)
			kevstr[0] = strconv.FormatBool(d.KEV)
			upkev := strings.Join(kevstr, " ")

			row := [][]string{
				{v.IP,
					d.CVE_id,
					strconv.FormatFloat(d.CVSS, 'f', 2, 64),
					strconv.Itoa(int(d.CVSS_version)),
					strconv.FormatFloat(d.EPSS, 'f', 2, 64),
					d.Reference,
					upkev},
			}

			table.AppendBulk(row)
		}
	}
	table.SetAutoMergeCellsByColumnIndex([]int{0})
	table.Render()
}

func FullscanTabler(data *[]runner.APIScan) {
	table := tablewriter.NewWriter(os.Stdout) //init table
	table.SetHeader([]string{"IP", "Total Ports", "ISP", "Port", "Product", "Version", "CVE ID", "CVSS", "CVSS Version", "EPSS", "Reference"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})
	for _, v := range *data {
		// ip
		IP := make([]string, 1)
		IP[0] = v.IP
		uppip := strings.Join(IP, ", ")
		// ports
		portSlice := make([]string, len(v.Ports))
		for i, d := range v.Ports {
			portSlice[i] = strconv.Itoa(d)
		}
		ports := strings.Join(portSlice, ", ")

		// isp
		isp := make([]string, 1)
		isp[0] = v.ISP
		uppisp := strings.Join(isp, ", ")
		// port
		for _, z := range v.Data {
			portstr := make([]string, 1)
			portstr[0] = strconv.Itoa(z.Port)
			uppport := strings.Join(portstr, ", ")
			// product
			var uppproduct string
			if z.Product == "" {
				uppproduct = "unknown product"
			} else {
				productstr := make([]string, 1)
				productstr[0] = z.Product
				uppproduct = strings.Join(productstr, ", ")
			}
			// version
			var uppversion string
			if z.Version == "" {
				uppversion = "unknown version"
			} else {
				version := make([]string, 1)
				version[0] = z.Version
				uppversion = strings.Join(version, ", ")
			}
			if z.Vulns != nil {
				// cve id
				for i, d := range z.Vulns {

					uppCVEId := i

					// cvss
					cvss := make([]string, 1)
					cvss[0] = strconv.FormatFloat(d.CVSS, 'f', 2, 64)
					uppcvss := strings.Join(cvss, ", ")

					// cvss version

					cvssversion := make([]string, 1)
					cvssversion[0] = strconv.Itoa(int(d.CVSS_version))
					uppcvssversion := strings.Join(cvssversion, ", ")

					// epss
					epss := make([]string, 1)
					epss[0] = strconv.FormatFloat(d.EPSS, 'f', 2, 64)
					uppepss := strings.Join(epss, ", ")

					// row
					row := [][]string{
						{
							uppip,
							ports,
							uppisp,
							uppport,
							uppproduct,
							uppversion,
							uppCVEId,
							uppcvss,
							uppcvssversion,
							uppepss,
							fmt.Sprintf("https://cvefeed.io/vuln/detail/%v", uppCVEId),
						},
					}

					table.AppendBulk(row)
				}
			} else {
				row := [][]string{
					{
						uppip,
						ports,
						uppisp,
						uppport,
						uppproduct,
						uppversion,
						"N/A",
						"N/A",
						"N/A",
						"N/A",
						"N/A",
					},
				}

				table.AppendBulk(row)
			}
		}
		table.SetAutoMergeCellsByColumnIndex([]int{0, 1, 2})
		table.Render()
	}
}

func ProcessCollection2CSV[V Collection](m V, FileName string) {
	file := fmt.Sprintf("%s.csv", FileName)
	csvFile, err := os.Create(file)
	if err != nil {
		log.Fatal("Failed to create the file: ", err)
	}

	csvwriter := csv.NewWriter(csvFile)

	switch data := any(m).(type) {
	case *[]runner.IpInfos:
		header := []string{"IP Address", "Open Ports", "Hostnames", "Platform Technologies", "Number of CVEs"}
		_ = csvwriter.Write(header)
		for _, record := range *data {
			row := []string{
				record.IP,
				strings.Join(intSliceToStringSlice(record.Ports), ", "),
				strings.Join(record.Hostnames, ", "),
				ConvertCPE(record.CPES),
				strconv.Itoa(record.Nb_CVEs),
			}
			_ = csvwriter.Write(row)
		}
	case *[]runner.CVESCAN:
		header := []string{"IP Address", "CVE ID", "CVSS", "CVSS Version", "EPSS", "Reference", "is KEV ?"}
		_ = csvwriter.Write(header)
		for _, record := range *data {
			for _, cve := range record.CVES {
				row := []string{
					record.IP,
					cve.CVE_id,
					strconv.FormatFloat(cve.CVSS, 'f', 2, 64),
					strconv.Itoa(int(cve.CVSS_version)),
					strconv.FormatFloat(cve.EPSS, 'f', 2, 64),
					cve.Reference,
					strconv.FormatBool(cve.KEV),
				}

				_ = csvwriter.Write(row)
			}
		}
	case *[]runner.APIScan:
		header := []string{"IP Address", "Total Ports", "ISP", "Port", "Product", "Version", "CVE ID", "CVSS", "CVSS Version", "EPSS", "Reference"}
		_ = csvwriter.Write(header)
		for _, record := range *data {
			for _, data := range record.Data {
				if data.Vulns != nil {
					for cveID, vuln := range data.Vulns {
						row := []string{
							record.IP,
							record.ISP,
							strings.Join(intSliceToStringSlice(record.Ports), " "),
							strconv.Itoa(data.Port),
							data.Product,
							data.Version,
							cveID,
							strconv.FormatFloat(vuln.CVSS, 'f', 2, 64),
							strconv.Itoa(int(vuln.CVSS_version)),
							strconv.FormatFloat(vuln.EPSS, 'f', 2, 64),
							fmt.Sprintf("https://cvefeed.io/vuln/detail/%v", cveID),
						}
						_ = csvwriter.Write(row)
					}
				} else {
					row := []string{
						record.IP,
						record.ISP,
						strings.Join(intSliceToStringSlice(record.Ports), " "),
						strconv.Itoa(data.Port),
						data.Product,
						data.Version,
						"N/A",
						"N/A",
						"N/A",
						"N/A",
						"N/A",
					}
					_ = csvwriter.Write(row)
				}
			}
		}
	default:
		log.Fatal("Unsupported type")
	}

	csvwriter.Flush()
	csvFile.Close()
}

func intSliceToStringSlice(ints []int) []string {
	strs := make([]string, len(ints))
	for i, v := range ints {
		strs[i] = strconv.Itoa(v)
	}
	return strs
}
