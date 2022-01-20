## IOC Scraper

IOC Scraper utilises [IOCPARSER](https://iocparser.com/) service to fetch  IOCs from different vendor Blogs, PDFs, and CSV files. Parsing IOCs is time-consuming process, using current script one can automatically extract and aggregate IOCs easily.

## Features
- Defanged IOCs  : Supports extracting and defanging IOCs.
- Whitelist IOCs : Supports custom whitlisting of IOCs.
- Source Types   : Supports variety of sources such as Blogs, PDFs, CSV, and much more.

## Supported IOC Types
IOC Scraper supports a variety of IOC types.


| IOC TYPE                         | STATUS |
| -----------                   | ----------- |
| ASN	                        | Supported   |
| IPv4, IPv6	                | Supported   |
| URL, Domain	                | Supported   |
| Email	                        | Supported   |
| MD5, SHA1, SHA256, File Name	| Supported   |
| MAC Address	                | Supported   |
| MITRE ATT&CK IDs          	| Supported   |
| YARA Rules	                | Supported   |


## Installation


```bash
git clone https://www.github.com/chaitanyakrishna/iocscraper.git
pip3 install -f requirements.txt
```

## Usage

```
python IOC_Scraper.py -h
 ___ ___   ____   ____
|_ _/ _ \ / ___| / ___|  ___ _ __ __ _ _ __   ___ _ __
 | | | | | |     \___ \ / __| '__/ _` | '_ \ / _ \ '__|
 | | |_| | |___   ___) | (__| | | (_| | |_) |  __/ |
|___\___/ \____| |____/ \___|_|  \__,_| .__/ \___|_|
                                      |_|


usage: IOC_Scraper.py [-h] [-u URL] [-uL FILE_CONTAINING_URLS] [-t TIMEOUT]  [-th THREADNUMBER] -o OUTPUT

IOC_Scraper v1.0

Optional Arguments:
  -h, --help            show this help message and exit
  -u URL, --url         Single URL for Fetching IOCs
  -uL FILE_CONTAINING_URLS, --url-list FILE_CONTAINING_URLS File Containing URL, One URL in One Line.
  -t TIMEOUT, --timeout TIMEOUT HTTP Request Timeout. default=60
  -th THREADNUMBER, --thread THREADNUMBER Parallel HTTP Request Number. default=100

Required Arguments:
  -o OUTPUT, --output OUTPUT Output file name.


```
## Sample command line arguments
```
python iocscraper.py -u "http://targeturl.com" -o report

python iocscraper.py -uL urls.txt -o report
```

## Output

```

python IOC_Scraper.py -uL url_list.txt -o report
 ___ ___   ____   ____
|_ _/ _ \ / ___| / ___|  ___ _ __ __ _ _ __   ___ _ __
 | | | | | |     \___ \ / __| '__/ _` | '_ \ / _ \ '__|
 | | |_| | |___   ___) | (__| | | (_| | |_) |  __/ |
|___\___/ \____| |____/ \___|_|  \__,_| .__/ \___|_|
                                      |_|


====================================================================================================
[Date: 20-01-2022] [Time: 23:03:09] [INFO] Initiating IOC Scraper ...
====================================================================================================
[*] ProgressBar: 14/14 [Fethcing IOC from: thehackernews.com] [Errors: 0] ...  0] ...  ...
[Date: 20-01-2022] [Time: 23:03:13] [INFO] Removing Duplicates ...



====================================================================================================
[Date: 20-01-2022] [Time: 23:03:13] [INFO] Fetched IOCs from the following domains
====================================================================================================


1.  blog.aquasec.com
2.  nationalcybersecurity.com
3.  cofense.com
4.  thehackernews.com
5.  blog.sucuri.net
6.  threats.amnpardaz.com
7.  www.crowdstrike.com
8.  www.bleepingcomputer.com
9.  forensicitguy.github.io
10.  marcusedmondson.com
11.  rajhackingarticles.blogspot.com
12.  research.checkpoint.com
13.  www.reddit.com
14.  www.zerofox.com


====================================================================================================
[Date: 20-01-2022] [Time: 23:03:13] [INFO] Indicator of Compromise Stats
====================================================================================================


Domain           : 52
URL              : 26
IPv4             : 15
IPv6             : 0
ASN              : 0
FILE_HASH_MD5    : 24
FILE_HASH_SHA1   : 16
FILE_HASH_SHA256 : 3
MITRE_ATTACK     : 4
EMAIL            : 3
CVE              : 7
FILE_NAME        : 59
YARA_RULE        : 0
MAC_ADDRESS      : 0


====================================================================================================
[Date: 20-01-2022] [Time: 23:03:13] [INFO] Total IOCs: 209
====================================================================================================


```

## API Reference
- [API Reference](https://docs.iocparser.com/api-reference/parse-api)

## Authors

- [Chaitanya Krishna](https://www.linkedin.com/in/chaitanyakrishnaa/)

## Follow

[![Twitter URL](https://img.shields.io/twitter/url/https/twitter.com/anantharapu.svg?style=social&label=Follow%20%40anantharapu)](https://twitter.com/anantharapu)
## Acknowledgements

 - Service Provided by IOCParser- [@IOCParser](https://twitter.com/IOCParser)
