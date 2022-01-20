from datetime import time
import requests
import pandas as pd
import sys, json5 
import pyfiglet
from colorama import init
from colorama import Fore, Back, Style
init()

import os 
import concurrent.futures 
from datetime import datetime
import argparse

class IOC_Scraper:
    def __init__(self):
        self.api          = "https://api.iocparser.com/url"
        self.progress     = []
        self.errors       = [] 
        self.total        = 1
        self.domain_list  = set()

    def printer(self, log_text, log_type):
        """
        Will Write & Print Logs
        """
        datetime_text = datetime.now().strftime(f"{Fore.WHITE}[Date: %d-%m-%Y] [Time: %H:%M:%S]{Style.RESET_ALL} ")
        
        if log_type == "INFO":
            datetime_text += f'[{Fore.GREEN}{log_type}{Style.RESET_ALL}] '
            print(f'{datetime_text}{log_text}')
        elif log_type == 'ERROR':
            datetime_text += f'[{Fore.YELLOW}{log_type}{Style.RESET_ALL}] '
            print(f'{datetime_text}{log_text}')

    def get_arguments(self):
        banner = pyfiglet.figlet_format("IOC Scraper")
        print(banner+"\n")
        parser = argparse.ArgumentParser(description=f'{Fore.RED}IOC_Scraper v1.0')
        parser._optionals.title = f"{Fore.GREEN}Optional Arguments{Fore.YELLOW}"
        parser.add_argument("-u", "--url", dest="url", help="Single URL for Fetching IOCs",)
        parser.add_argument("-uL", "--url-list", dest="file_containing_urls", help="File Containing URL, One URL in One Line.")    
        parser.add_argument("-t", "--timeout", dest="timeout", help="HTTP Request Timeout. default=60", default=60)
        parser.add_argument("-th", "--thread", dest="ThreadNumber", help="Parallel HTTP Request Number. default=100", default=100)
        
        required_arguments = parser.add_argument_group(f'{Fore.RED}Required Arguments{Fore.GREEN}')
        required_arguments.add_argument("-o", "--output", dest="output", help="Output file name.", required=True)
        return parser.parse_args()

    def start(self):
        arguments = self.get_arguments()

        # Fetching timeout & ThreadNumber 
        self.timeout      = arguments.timeout
        self.ThreadNumber = arguments.ThreadNumber

        # Formating Output file name 
        self.output_filename = arguments.output
        if self.output_filename.split('.')[-1] == 'csv':
            self.output_filename = self.output_filename + datetime.now().strftime('%d-%m-%Y_%H_%M_%S') + ".csv"
        else:
            self.output_filename = self.output_filename.replace('.csv', '') + datetime.now().strftime('_%d-%m-%Y_%H_%M_%S') + ".csv"
    

        print("="*100)
        self.printer(f"{Fore.YELLOW}Initiating {Fore.GREEN}IOC Scraper{Fore.YELLOW} ...{Style.RESET_ALL}", "INFO")
        print("="*100)

        # Checking what type of Input is given : Single URL or URL List
        if arguments.url:
            url = arguments.url
            self.printer(f"{Fore.YELLOW}Fetching IOCs from URL: {Fore.GREEN}{url}{Style.RESET_ALL}", "INFO")
            self.get_ioc(url)

        elif arguments.file_containing_urls:
            file_containing_urls = arguments.file_containing_urls
            with open(file_containing_urls) as f:
                data_list = f.readlines()
            
            final_url_list = set()
            for raw_url in data_list:
                if raw_url != "\n":
                    final_url_list.add(raw_url.strip())

            self.total = len(final_url_list)

            # Multi-Threaded Implementation
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.ThreadNumber)
            futures = [executor.submit(self.get_ioc, url) for url in final_url_list]
            concurrent.futures.wait(futures)    
            
        else:
            self.printer(f"{Fore.RED}Please Provide either File Containing list or Single URL, type {sys.argv[0]} --help for more.", "ERROR")
            sys.exit()

        try:
        	self.sort_csv_on_the_basis_of_pyramid_of_pain()
        except:
        	pass 


    def get_ioc(self, url):
        payload = {"url": url}
        headers = {'Content-Type': 'application/json'}

        try:
            response = requests.request("POST", self.api, headers=headers, json=payload, timeout=self.timeout).json()
            # with open('test.json', 'w') as f:
            #     f.write(json5.dumps(response, indent=4))

            result      = response['data']

            result_meta = response['meta']
            url         = result_meta['url']
            title       = result_meta['title']
            description = result_meta['description']

            data_list = []

            for key, value in result.items():
                # print(f'{key}: {value}')
                if len(value) != 0:  
                    if key == "FILE_HASH_SHA1":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }
                            data_list.append(data_dict)
                    elif key == "DOMAIN":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }
                            data_list.append(data_dict)
                    elif key == "IPv6":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }
                            data_list.append(data_dict)
                    elif key == "YARA_RULE":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }
                            data_list.append(data_dict)               
                    elif key == "IPv4":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }   
                            data_list.append(data_dict)            
                    elif key == "EMAIL":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                } 
                            data_list.append(data_dict)              
                    elif key == "FILE_NAME": 
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }  
                            data_list.append(data_dict)            
                    elif key == "URL":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }   
                            data_list.append(data_dict)            
                    elif key == "MAC_ADDRESS":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }  
                            data_list.append(data_dict)             
                    elif key == "FILE_HASH_MD5":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }
                            data_list.append(data_dict)               
                    elif key == "CVE":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }    
                            data_list.append(data_dict)           
                    elif key == "FILE_HASH_SHA256":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                } 
                            data_list.append(data_dict)              
                    elif key == "ASN":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                } 
                            data_list.append(data_dict)              
                    elif key == "MITRE_ATT&CK":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }
                            data_list.append(data_dict)

                    elif key == "EMAIL":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }
                            data_list.append(data_dict)

                    elif key == "MAC_ADDRESS":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }
                            data_list.append(data_dict)

                    elif key == "MAC_ADDRESS":
                        for ioc in value:
                            data_dict = {
                                    "IOC Value"  : ioc,
                                    "IOC Type"   : key,
                                    "URL"        : url,
                                    "Title"      : title,
                                    "Description": description
                                }
                            data_list.append(data_dict)

            domain_name = url.replace('https://', '').replace('http://', '').split('/')[0]
            self.domain_list.add(domain_name)
            df = pd.DataFrame(data_list)    
            self.write_data_to_csv(self.output_filename, df)
            self.progress.append(1)
            print(f"\r{Fore.YELLOW}[*] ProgressBar: {Fore.WHITE}{len(self.progress)}/{self.total}{Fore.YELLOW} [Fethcing IOC from: {Fore.GREEN}{domain_name}{Fore.YELLOW}] [Errors: {Fore.RED}{len(self.errors)}{Fore.YELLOW}] ... {Style.RESET_ALL}", end="")
        except Exception as e:
            domain_name = url.replace('https://', '').replace('http://', '').split('/')[0]
            print()
            self.printer(f"{Fore.YELLOW}{domain_name}{Fore.RED} is not supported for Fetching IOC's, Please try manually to fetch the IOC's{Style.RESET_ALL}", "ERROR")
            # self.printer(f"{Fore.RED}Error: {e}{Style.RESET_ALL}", "ERROR")
            self.errors.append(1)
            self.progress.append(1)
            # domain_name = url.replace('https://', '').replace('http://', '').split('/')[0]
            self.domain_list.add(domain_name)
            print(f"\r{Fore.YELLOW}[*] ProgressBar: {Fore.WHITE}{len(self.progress)}/{self.total}{Fore.YELLOW} [Fethcing IOC from: {Fore.GREEN}{domain_name}{Fore.YELLOW}] [Errors: {Fore.RED}{len(self.errors)}{Fore.YELLOW}] ... {Style.RESET_ALL}", end="")

    def write_data_to_csv(self, filename, df):
        with open(filename, 'a', encoding='utf-8') as f:
            df.to_csv(f, header=f.tell() == 0, encoding='utf-8', index=False, line_terminator='\n') 

    def sort_csv_on_the_basis_of_pyramid_of_pain(self):
        """
        1. Domain
        2. URL
        3. IPv4
        4. IPv6  
        5. ASN 
        6. FILE_HASH_MD5
        7. FILE_HASH_SHA1
        8. FILE_HASH_SHA256
        9. MITRE_ATT&CK
        10. EMAIL
        11. CVE 
        12. FILE_NAME
        13. YARA_RULE 
        14. MAC_ADDRESS
        """
        df = pd.read_csv(self.output_filename)

        print()
        self.printer(f"{Fore.YELLOW}Removing {Fore.GREEN}Duplicates{Fore.YELLOW} ...{Style.RESET_ALL}", "INFO")
        IOC_Value_column_name = 'IOC Value'
        df = df.drop_duplicates(subset=IOC_Value_column_name, keep='first')

        # Removing Any Row whose Value is CSV Header
        df = df.drop(df[df['IOC Value']   == 'IOC Value'].index)
        df = df.drop(df[df['IOC Type']    == 'IOC Type'].index)
        df = df.drop(df[df['URL']         == 'URL'].index)
        df = df.drop(df[df['Title']       == 'Title'].index)
        df = df.drop(df[df['Description'] == 'Description'].index)     

        # Removing duplicates    

        df_Domain           = df.loc[df['IOC Type'] == 'DOMAIN']
        df_URL              = df.loc[df['IOC Type'] == 'URL']
        df_IPv4             = df.loc[df['IOC Type'] == 'IPv4']
        df_IPv6             = df.loc[df['IOC Type'] == 'IPv6']
        df_ASN              = df.loc[df['IOC Type'] == 'ASN']
        df_FILE_HASH_MD5    = df.loc[df['IOC Type'] == 'FILE_HASH_MD5']
        df_FILE_HASH_SHA1   = df.loc[df['IOC Type'] == 'FILE_HASH_SHA1']
        df_FILE_HASH_SHA256 = df.loc[df['IOC Type'] == 'FILE_HASH_SHA256']
        df_MITRE_ATTACK     = df.loc[df['IOC Type'] == 'MITRE_ATT&CK']
        df_EMAIL            = df.loc[df['IOC Type'] == 'EMAIL']
        df_CVE              = df.loc[df['IOC Type'] == 'CVE']
        df_FILE_NAME        = df.loc[df['IOC Type'] == 'FILE_NAME']
        df_YARA_RULE        = df.loc[df['IOC Type'] == 'YARA_RULE']
        df_MAC_ADDRESS      = df.loc[df['IOC Type'] == 'MAC_ADDRESS']

        print("\n\n")
        print("="*100)
        self.printer(f"{Fore.GREEN}Fetched IOCs from the following domains{Style.RESET_ALL}", "INFO")
        print("="*100)
        print("\n") 
        index = 1
        for domain in self.domain_list:
            print(f"{index}. ", domain)
            index += 1

        print("\n")
        print("="*100)
        self.printer(f"{Fore.GREEN}Indicator of Compromise Stats{Style.RESET_ALL}", "INFO")
        print("="*100)
        print("\n") 
        print(f"Domain           : {len(df_Domain)}")
        print(f"URL              : {len(df_URL)}")
        print(f"IPv4             : {len(df_IPv4)}")
        print(f"IPv6             : {len(df_IPv6)}")
        print(f"ASN              : {len(df_ASN)}")
        print(f"FILE_HASH_MD5    : {len(df_FILE_HASH_MD5)}")
        print(f"FILE_HASH_SHA1   : {len(df_FILE_HASH_SHA1)}")
        print(f"FILE_HASH_SHA256 : {len(df_FILE_HASH_SHA256)}")
        print(f"MITRE_ATTACK     : {len(df_MITRE_ATTACK)}")
        print(f"EMAIL            : {len(df_EMAIL)}")
        print(f"CVE              : {len(df_CVE)}")
        print(f"FILE_NAME        : {len(df_FILE_NAME)}")
        print(f"YARA_RULE        : {len(df_YARA_RULE)}")
        print(f"MAC_ADDRESS      : {len(df_MAC_ADDRESS)}")  

        print("\n") 
        print("="*100)
        self.printer(f"{Fore.YELLOW}Total IOCs: {Fore.GREEN}{len(df)}{Style.RESET_ALL}", "INFO")
        print("="*100)

        frames = [df_Domain, 
            df_URL, 
            df_IPv4,
            df_IPv6,  
            df_ASN, 
            df_FILE_HASH_MD5,
            df_FILE_HASH_SHA1,
            df_FILE_HASH_SHA256,
            df_MITRE_ATTACK,
            df_EMAIL,
            df_CVE, 
            df_FILE_NAME,
            df_YARA_RULE, 
            df_MAC_ADDRESS]
        IOC_df = pd.concat(frames)  
        os.remove(self.output_filename)
        IOC_df.to_csv(self.output_filename, index=False)

if __name__ == '__main__':
    test = IOC_Scraper()
    test.start()