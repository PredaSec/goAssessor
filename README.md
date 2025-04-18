# goAssessor

----
goAssessor gathers information about public IPs, including open ports, CVEs, technologies, and more, using Shodan's APIs.
APIs used : 
- https://internetdb.shodan.io/
- https://developer.shodan.io/api
- https://cvedb.shodan.io/

## Install
---
```bash
go install github.com/predasec/goassessor@latest
```

## Usage
----
### Inputs 

goAssessor accepts both one target or list of targets (text file) :

```bash
goAssessor -target 8.8.8.8 -op ipscan # one target
goAssessor -list ips.txt -op ipscan # list of target

$ cat ips.txt
111.222.333.444
222.333.444.555
333.444.555.666
```
### Operations

IP scan : IP + Ports + Hostnames + CPEs + Number of CVEs :

``` bash
goAssessor -target x.x.x.x -op ipscan
```

CVE scan : IP + CVE ID + CVSS + CVSS Version + EPSS + Reference + Is KEV ? :

``` bash
goAssessor -target x.x.x.x -op cvescan
```

Full scan : IP + Ports + ISP + Port + Product + Version + CVE ID + CVSS + CVSS Version + EPSS + Reference :

``` bash
goAssessor -target x.x.x.x -op fullscan -key <Shodan-API-Key>
```
### Output

To extract the output as CSV just add `-convert2csv` appended by the filename.

## Acknowledgement
---
This was inspired by [iamunixtz/Lazy-Hunter](https://github.com/iamunixtz/Lazy-Hunter)

## Improvements
---
- Concurrency
- Other APIs
- More operations
- Better code x)
