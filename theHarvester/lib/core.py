# coding=utf-8

import random
import yaml


class Core:
    @staticmethod
    def version():
        return '3.1.0.dev1'

    @staticmethod
    def bing_key():
        with open('api-keys.yaml', 'r') as api_keys:
            keys = yaml.safe_load(api_keys)
            return keys['apikeys']['bing']['key']

    @staticmethod
    def hunter_key():
        with open('api-keys.yaml', 'r') as api_keys:
            keys = yaml.safe_load(api_keys)
            return keys['apikeys']['hunter']['key']

    @staticmethod
    def intelx_key():
        with open('api-keys.yaml', 'r') as api_keys:
            keys = yaml.safe_load(api_keys)
            return keys['apikeys']['intelx']['key']

    @staticmethod
    def security_trails_key():
        with open('api-keys.yaml', 'r') as api_keys:
            keys = yaml.safe_load(api_keys)
            return keys['apikeys']['securityTrails']['key']

    @staticmethod
    def shodan_key():
        with open('api-keys.yaml', 'r') as api_keys:
            keys = yaml.safe_load(api_keys)
            return keys['apikeys']['shodan']['key']

    @staticmethod
    def banner():
        print('\n\033[93m*******************************************************************')
        print("*  _   _                                            _             *")
        print(r"* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *")
        print(r"* | __|  _ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *")
        print(r"* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *")
        print(r"*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *")
        print('*                                                                 *')
        print(f'* theHarvester {Core.version()}                                          *')
        print('* Coded by Christian Martorella                                   *')
        print('* Edge-Security Research                                          *')
        print('* cmartorella@edge-security.com                                   *')
        print('*                                                                 *')
        print('******************************************************************* \n\n \033[0m')

    @staticmethod
    def get_supportedengines():
        supportedengines = {'baidu',
                            'bing',
                            'bingapi',
                            'censys',
                            'crtsh',
                            'cymon',
                            'dnsdumpster',
                            'dogpile',
                            'duckduckgo',
                            'google',
                            'google-certificates',
                            'hunter',
                            'intelx',
                            'linkedin',
                            'netcraft',
                            'securityTrails',
                            'threatcrowd',
                            'trello',
                            'twitter',
                            'vhost',
                            'virustotal',
                            'yahoo',
                            'all'
                            }
        return supportedengines

    @staticmethod
    def get_user_agent():
        # User-Agents from https://github.com/tamimibrahim17/List-of-user-agents
        user_agents = [
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1464.0 Safari/537.36',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) chromeframe/10.0.648.205',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_0) AppleWebKit/537.4 (KHTML, like Gecko) Chrome/22.0.1229.79 Safari/537.4',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1944.0 Safari/537.36',
            'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.13) Gecko/20101213 Opera/9.80 (Windows NT 6.1; U; zh-tw) Presto/2.7.62 Version/11.01',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.2 (KHTML, like Gecko) Chrome/22.0.1216.0 Safari/537.2',
            'Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
            'Mozilla/5.0 (X11; CrOS i686 3912.101.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; chromeframe/11.0.696.57)',
            'Mozilla/5.0 (Linux; U; Android 2.3; en-us) AppleWebKit/999+ (KHTML, like Gecko) Safari/999.9',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1664.3 Safari/537.36',
            'Opera/9.80 (X11; Linux i686; U; ja) Presto/2.7.62 Version/11.01',
            'Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36',
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
            'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 1.1.4322)',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24',
            'Opera/9.80 (Windows NT 5.1; U; cs) Presto/2.7.62 Version/11.01',
            'Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)',
            'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.93 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/19.77.34.5 Safari/537.1',
            'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.17 Safari/537.11',
            'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.8.36217; WOW64; en-US)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.0) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.36 Safari/536.5',
            'Mozilla/5.0 (X11; FreeBSD amd64) AppleWebKit/536.5 (KHTML like Gecko) Chrome/19.0.1084.56 Safari/1EA69',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
            'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.4 (KHTML, like Gecko) Chrome/22.0.1229.94 Safari/537.4',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2224.3 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36',
            'Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36 Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10',
            'Mozilla/5.0 (Linux; U; Android 2.3.5; zh-cn; HTC_IncredibleS_S710e Build/GRJ90) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.2; .NET CLR 1.1.4322; .NET4.0C; Tablet PC 2.0)',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1467.0 Safari/537.36',
            'Mozilla/5.0 (X11; CrOS i686 1660.57.0) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.46 Safari/535.19',
            'Mozilla/5.0 (Windows NT 6.1; U; de; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 11.01',
            'Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; Media Center PC 6.0; InfoPath.3; MS-RTC LM 8; Zune 4.7)',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.1.76908; WOW64; en-US)',
            'Opera/9.80 (X11; Linux x86_64; U; Ubuntu/10.10 (maverick); pl) Presto/2.7.62 Version/11.01',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.2; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)',
            'Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.0; Trident/4.0; FBSMTWB; .NET CLR 2.0.34861; .NET CLR 3.0.3746.3218; .NET CLR 3.5.33652; msn OptimizedIE8;ENUS)',
            'Opera/9.80 (Windows NT 5.1; U; en) Presto/2.9.168 Version/11.51',
            'Opera/9.80 (Windows NT 6.1; U; zh-tw) Presto/2.7.62 Version/11.01',
            'Opera/9.80 (Windows NT 5.1; U; MRA 5.5 (build 02842); ru) Presto/2.7.62 Version/11.00',
            'Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC_Pyramid Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
            'Opera/9.80 (Windows NT 6.1; U; cs) Presto/2.7.62 Version/11.01',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36',
            'Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00',
            'Opera/9.80 (Windows NT 5.1; U; ru) Presto/2.7.39 Version/11.00',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.3; .NET4.0C; .NET4.0E; .NET CLR 3.5.30729; .NET CLR 3.0.30729; MS-RTC LM 8)',
            'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.7.62 Version/11.01',
            'Mozilla/5.0 (Windows NT 6.1; U; nl; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 11.01',
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
            'Mozilla/5.0 (X11; CrOS i686 2268.111.0) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11',
            'Opera/9.80 (Windows NT 6.1; WOW64; U; pt) Presto/2.10.229 Version/11.62',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; Media Center PC 6.0; InfoPath.2; MS-RTC LM 8',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.14 (KHTML, like Gecko) Chrome/24.0.1292.0 Safari/537.14',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; yie8)',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36',
            'Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; de) Presto/2.9.168 Version/11.52',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.2 Safari/537.36',
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)',
            'Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.45 Safari/535.19',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.26 Safari/537.11',
            'Opera/9.80 (Windows NT 5.1; U; zh-tw) Presto/2.8.131 Version/11.10',
            'Opera/9.80 (Windows NT 6.1; U; en-US) Presto/2.7.62 Version/11.01',
            'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 3.0.04506.30)',
            'Mozilla/5.0 (Linux; U; Android 2.3.4; fr-fr; HTC Desire Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
            'Mozilla/5.0 (Windows NT 5.1) Gecko/20100101 Firefox/14.0 Opera/12.0',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.60 Safari/537.17',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3',
            'Opera/9.80 (X11; Linux i686; U; fr) Presto/2.7.62 Version/11.01',
            'Mozilla/4.0 (compatible; MSIE 8.0; X11; Linux x86_64; pl) Opera 11.00',
            'Opera/9.80 (X11; Linux i686; U; hu) Presto/2.9.168 Version/11.50',
            'Opera/9.80 (X11; Linux x86_64; U; bg) Presto/2.8.131 Version/11.10',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
            'Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14',
            'Opera/9.80 (X11; Linux i686; U; it) Presto/2.7.62 Version/11.00',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.11 Safari/535.19',
            'Opera/12.0(Windows NT 5.1;U;en)Presto/22.9.168 Version/12.00',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
            'Opera/9.80 (X11; Linux i686; U; es-ES) Presto/2.8.131 Version/11.11',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Zune 4.0; InfoPath.3; MS-RTC LM 8; .NET4.0C; .NET4.0E)',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.1; SV1; .NET CLR 2.8.52393; WOW64; en-US)',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13',
            'Opera/9.80 (Windows NT 5.1; U; it) Presto/2.7.62 Version/11.00',
            'Mozilla/5.0 (Linux; U; Android 2.3.3; ko-kr; LG-LU3000 Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
            'Opera/9.80 (Windows NT 6.0; U; pl) Presto/2.7.62 Version/11.01',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3',
            'Opera/9.80 (Windows NT 6.1; U; fi) Presto/2.7.62 Version/11.00',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3',
            'Opera/12.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.02',
            'Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.15 (KHTML, like Gecko) Chrome/24.0.1295.0 Safari/537.15',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36',
            'Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36',
            'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)',
            'Mozilla/5.0 (Linux; U; Android 2.3.3; en-us; HTC_DesireS_S510e Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36',
            'Opera/9.80 (Windows NT 6.0; U; pl) Presto/2.10.229 Version/11.62',
            'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)',
            'Mozilla/5.0 (Linux; U; Android 2.3.3; en-us; HTC_DesireS_S510e Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
            'Opera/9.80 (Windows NT 6.1; Opera Tablet/15165; U; en) Presto/2.8.149 Version/11.1',
            'Opera/9.80 (Windows NT 5.1; U; zh-sg) Presto/2.9.181 Version/12.00',
            'Opera/9.80 (Windows NT 6.1; U; en-GB) Presto/2.7.62 Version/11.00',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; de) Opera 11.01',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00',
            'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0;  rv:11.0) like Gecko',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.0 Safari/536.3',
            'Opera/9.80 (Windows NT 6.1; U; ko) Presto/2.7.62 Version/11.00',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; Media Center PC 6.0; InfoPath.3; MS-RTC LM 8; Zune 4.7',
            'Mozilla/5.0 (Windows NT 6.0; rv:2.0) Gecko/20100101 Firefox/4.0 Opera 12.14',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.517 Safari/537.36',
            'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727)',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.45 Safari/535.19',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36',
            'Opera/9.80 (Windows NT 6.1; U; zh-cn) Presto/2.6.37 Version/11.00',
            'Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14',
            'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
            'Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC Pyramid Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13',
            'Mozilla/5.0 (Windows NT 6.0; U; ja; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 11.00',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; chromeframe/11.0.696.57)',
            'Opera/9.80 (X11; Linux i686; U; ru) Presto/2.8.131 Version/11.11',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; chromeframe/13.0.782.215)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.22 (KHTML, like Gecko) Chrome/19.0.1047.0 Safari/535.22',
            'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; .NET CLR 2.7.58687; SLCC2; Media Center PC 5.0; Zune 3.4; Tablet PC 3.6; InfoPath.3)',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
            'Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1664.3 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36',
            'Mozilla/5.0 (X11; NetBSD) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36',
            'Mozilla/5.0 (Windows NT 5.1; U; en; rv:1.8.1) Gecko/20061208 Firefox/5.0 Opera 11.11',
            'Mozilla/5.0 (Macintosh; AMD Mac OS X 10_8_2) AppleWebKit/535.22 (KHTML, like Gecko) Chrome/18.6.872',
            'Mozilla/5.0 (X11; OpenBSD i386) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)',
            'Mozilla/5.0 (Linux; U; Android 4.0.3; de-ch; HTC Sensation Build/IML74K) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30',
            'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.0) yi; AppleWebKit/345667.12221 (KHTML, like Gecko) Chrome/23.0.1271.26 Safari/453667.1221',
            'Mozilla/1.22 (compatible; MSIE 10.0; Windows 3.1)',
            'Opera/9.80 (Windows NT 5.1; U;) Presto/2.7.62 Version/11.01',
            'Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16',
            'Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.21 (KHTML, like Gecko) Chrome/19.0.1042.0 Safari/535.21',
            'Mozilla/5.0 (Linux; U; Android 2.3.5; en-us; HTC Vision Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 7.0; InfoPath.3; .NET CLR 3.1.40767; Trident/6.0; en-IN)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1309.0 Safari/537.17',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1623.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/4E423F',
            'Opera/9.80 (Windows NT 6.1; U; zh-cn) Presto/2.7.62 Version/11.01',
            'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; SLCC1; .NET CLR 1.1.4322)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_5_8) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.151 Safari/535.19',
            'Opera/9.80 (Windows NT 6.1; U; sv) Presto/2.7.62 Version/11.01',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.62 Safari/537.36',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; Media Center PC 6.0; InfoPath.2; MS-RTC LM 8)',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1284.0 Safari/537.13',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Safari/535.19',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5',
            'Opera/9.80 (X11; Linux x86_64; U; fr) Presto/2.9.168 Version/11.50',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Zune 4.0; Tablet PC 2.0; InfoPath.3; .NET4.0C; .NET4.0E)',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; chromeframe/12.0.742.112)',
            'Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)',
            'Opera/12.0(Windows NT 5.2;U;en)Presto/22.9.168 Version/12.00',
            'Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36',
            'Opera/9.80 (X11; Linux x86_64; U; pl) Presto/2.7.62 Version/11.00',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36',
            'Opera/9.80 (Windows NT 6.0; U; en) Presto/2.8.99 Version/11.10',
            'Opera/9.80 (Windows NT 6.0; U; en) Presto/2.7.39 Version/11.00',
            'Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC_Pyramid Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari',
            'Mozilla/5.0 (Windows NT 5.1; U; pl; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 11.00',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.90 Safari/537.36',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; Media Center PC 6.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C)',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1866.237 Safari/537.36',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; de) Opera 11.51',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.6 Safari/537.11',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.6 Safari/537.11',
            'Opera/9.80 (Windows NT 6.1; U; pl) Presto/2.7.62 Version/11.00',
            'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.2; Trident/4.0; Media Center PC 4.0; SLCC1; .NET CLR 3.0.04320)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.45 Safari/535.19',
            'Mozilla/5.0 (X11; CrOS i686 4319.74.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.57 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/18.6.872.0 Safari/535.2 UNTRUSTED/1.0 3gpp-gba UNTRUSTED/1.0',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)',
            'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.16 Safari/537.36',
            'Opera/9.80 (Windows NT 6.1 x64; U; en) Presto/2.7.62 Version/11.00',
            'Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; T-Mobile myTouch 3G Slide Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
            'Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.21 (KHTML, like Gecko) Chrome/19.0.1041.0 Safari/535.21',
            'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1500.55 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1090.0 Safari/536.6',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.19 (KHTML, like Gecko) Ubuntu/11.10 Chromium/18.0.1025.142 Chrome/18.0.1025.142 Safari/535.19',
            'Mozilla/5.0 (Windows NT 5.1; U; de; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 11.00'
        ]
        return random.choice(user_agents)

    # TODO use this method when -b all is called to replace lines 383-635 in theHarvester.py
    # TODO and to find the best approach of getting the word, limit, and start etc vars from
    #      the arguments and importing libs that are needed.
    #
    # @staticmethod
    # def engine_all_search():
    #     print(('Full harvest on ' + word))
    #     all_emails = []
    #     all_hosts = []
    #     try:
    #         print('[*] Searching Baidu.')
    #         search = baidusearch.SearchBaidu(word, limit)
    #         search.process()
    #         all_emails = filter(search.get_emails())
    #         hosts = filter(search.get_hostnames())
    #         all_hosts.extend(hosts)
    #         db = stash.stash_manager()
    #         db.store_all(word, all_hosts, 'host', 'baidu')
    #         db.store_all(word, all_emails, 'email', 'baidu')
    #     except Exception:
    #         pass
    #
    #     print('[*] Searching Bing.')
    #     bingapi = 'no'
    #     search = bingsearch.SearchBing(word, limit, start)
    #     search.process(bingapi)
    #     emails = filter(search.get_emails())
    #     hosts = filter(search.get_hostnames())
    #     all_hosts.extend(hosts)
    #     db = stash.stash_manager()
    #     db.store_all(word, all_hosts, 'host', 'bing')
    #     all_emails.extend(emails)
    #     all_emails = sorted(set(all_emails))
    #     db.store_all(word, all_emails, 'email', 'bing')
    #
    #     print('[*] Searching Censys.')
    #     from discovery import censys
    #     search = censys.SearchCensys(word, limit)
    #     search.process()
    #     ips = search.get_ipaddresses()
    #     setips = set(ips)
    #     uniqueips = list(setips)  # Remove duplicates.
    #     all_ip.extend(uniqueips)
    #     hosts = filter(search.get_hostnames())
    #     sethosts = set(hosts)
    #     uniquehosts = list(sethosts)  # Remove duplicates.
    #     all_hosts.extend(uniquehosts)
    #     db = stash.stash_manager()
    #     db.store_all(word, uniquehosts, 'host', 'censys')
    #     db.store_all(word, uniqueips, 'ip', 'censys')
    #
    #     print('[*] Searching CRT.sh.')
    #     search = crtsh.SearchCrtsh(word)
    #     search.process()
    #     hosts = filter(search.get_hostnames())
    #     all_hosts.extend(hosts)
    #     db = stash.stash_manager()
    #     db.store_all(word, all_hosts, 'host', 'CRTsh')
    #
    #     # cymon
    #     print('\033[94m[*] Searching Cymon. \033[0m')
    #     from discovery import cymon
    #     # Import locally or won't work.
    #     search = cymon.search_cymon(word)
    #     search.process()
    #     all_ip = search.get_ipaddresses()
    #     db = stash.stash_manager()
    #     db.store_all(word, all_ip, 'ip', 'cymon')
    #
    #     print('\033[94m[*] Searching Dogpile. \033[0m')
    #     search = dogpilesearch.SearchDogpile(word, limit)
    #     search.process()
    #     emails = filter(search.get_emails())
    #     hosts = filter(search.get_hostnames())
    #     all_hosts.extend(hosts)
    #     all_emails.extend(emails)
    #     db = stash.stash_manager()
    #     db.store_all(word, all_hosts, 'email', 'dogpile')
    #     db.store_all(word, all_hosts, 'host', 'dogpile')
    #
    #     print('[*] Searching DuckDuckGo.')
    #     from discovery import duckduckgosearch
    #     search = duckduckgosearch.SearchDuckDuckGo(word, limit)
    #     search.process()
    #     emails = filter(search.get_emails())
    #     hosts = filter(search.get_hostnames())
    #     all_hosts.extend(hosts)
    #     all_emails.extend(emails)
    #     db = stash.stash_manager()
    #     db.store_all(word, all_hosts, 'email', 'duckduckgo')
    #     db.store_all(word, all_hosts, 'host', 'duckduckgo')
    #
    #     print('[*] Searching Google.')
    #     search = googlesearch.search_google(word, limit, start)
    #     search.process(google_dorking)
    #     emails = filter(search.get_emails())
    #     hosts = filter(search.get_hostnames())
    #     all_emails.extend(emails)
    #     db = stash.stash_manager()
    #     db.store_all(word, all_emails, 'email', 'google')
    #     all_hosts.extend(hosts)
    #     db = stash.stash_manager()
    #     db.store_all(word, all_hosts, 'host', 'google')
    #
    #     print('[*] Searching Google Certificate transparency report.')
    #     search = googlecertificates.SearchGoogleCertificates(word, limit, start)
    #     search.process()
    #     domains = filter(search.get_domains())
    #     all_hosts.extend(domains)
    #     db = stash.stash_manager()
    #     db.store_all(word, all_hosts, 'host', 'google-certificates')
    #
    #     print('[*] Searching Hunter.')
    #     from discovery import huntersearch
    #     # Import locally.
    #     try:
    #         search = huntersearch.SearchHunter(word, limit, start)
    #         search.process()
    #         emails = filter(search.get_emails())
    #         hosts = filter(search.get_hostnames())
    #         all_hosts.extend(hosts)
    #         db = stash.stash_manager()
    #         db.store_all(word, hosts, 'host', 'hunter')
    #         all_emails.extend(emails)
    #         all_emails = sorted(set(all_emails))
    #         db.store_all(word, all_emails, 'email', 'hunter')
    #     except Exception as e:
    #         if isinstance(e, MissingKey):
    #             print(e)
    #         else:
    #             pass
    #
    #     print('\033[94m[*] Searching Linkedin. \033[0m')
    #     search = linkedinsearch.SearchLinkedin(word, limit)
    #     search.process()
    #     people = search.get_people()
    #     db = stash.stash_manager()
    #     db.store_all(word, people, 'name', 'linkedin')
    #
    #     if len(people) == 0:
    #         print('\n[*] No users found.\n\n')
    #     else:
    #         print('\n[*] Users found: ' + str(len(people)))
    #         print('---------------------')
    #         for user in sorted(list(set(people))):
    #             print(user)
    #
    #     print('[*] Searching Netcraft.')
    #     search = netcraft.SearchNetcraft(word)
    #     search.process()
    #     hosts = filter(search.get_hostnames())
    #     all_hosts.extend(hosts)
    #     db = stash.stash_manager()
    #     db.store_all(word, all_hosts, 'host', 'netcraft')
    #
    #     print('[*] Searching PGP key server.')
    #     try:
    #         search = pgpsearch.SearchPgp(word)
    #         search.process()
    #         emails = filter(search.get_emails())
    #         hosts = filter(search.get_hostnames())
    #         sethosts = set(hosts)
    #         uniquehosts = list(sethosts)  # Remove duplicates.
    #         all_hosts.extend(uniquehosts)
    #         db = stash.stash_manager()
    #         db.store_all(word, all_hosts, 'host', 'PGP')
    #         all_emails.extend(emails)
    #         db = stash.stash_manager()
    #         db.store_all(word, all_emails, 'email', 'PGP')
    #     except Exception:
    #         pass
    #
    #     print('[*] Searching Threatcrowd.')
    #     try:
    #         search = threatcrowd.SearchThreatcrowd(word)
    #         search.process()
    #         hosts = filter(search.get_hostnames())
    #         all_hosts.extend(hosts)
    #         db = stash.stash_manager()
    #         db.store_all(word, all_hosts, 'host', 'threatcrowd')
    #     except Exception:
    #         pass
    #
    #     print('[*] Searching Trello.')
    #     from discovery import trello
    #     # Import locally or won't work.
    #     search = trello.search_trello(word, limit)
    #     search.process()
    #     emails = filter(search.get_emails())
    #     all_emails.extend(emails)
    #     info = search.get_urls()
    #     hosts = filter(info[0])
    #     trello_info = (info[1], True)
    #     all_hosts.extend(hosts)
    #     db = stash.stash_manager()
    #     db.store_all(word, hosts, 'host', 'trello')
    #     db.store_all(word, emails, 'email', 'trello')
    #
    #     try:
    #         print('[*] Searching Twitter.')
    #         search = twittersearch.search_twitter(word, limit)
    #         search.process()
    #         people = search.get_people()
    #         db = stash.stash_manager()
    #         db.store_all(word, people, 'name', 'twitter')
    #         print('\nUsers from Twitter:')
    #         print('-------------------')
    #         for user in people:
    #             print(user)
    #     except Exception:
    #         pass
    #
    #     print('\n[*] Virtual hosts:')
    #     print('------------------')
    #     for l in host_ip:
    #         search = bingsearch.SearchBing(l, limit, start)
    #         search.process_vhost()
    #         res = search.get_allhostnames()
    #         for x in res:
    #             x = re.sub(r'[[\<\/?]*[\w]*>]*', '', x)
    #             x = re.sub('<', '', x)
    #             x = re.sub('>', '', x)
    #             print((l + '\t' + x))
    #             vhost.append(l + ':' + x)
    #             full.append(l + ':' + x)
    #     vhost = sorted(set(vhost))
    #
    #     print('[*] Searching VirusTotal.')
    #     search = virustotal.search_virustotal(word)
    #     search.process()
    #     hosts = filter(search.get_hostnames())
    #     all_hosts.extend(hosts)
    #     db = stash.stash_manager()
    #     db.store_all(word, all_hosts, 'host', 'virustotal')
    #
    #     print('[*] Searching Yahoo.')
    #     search = yahoosearch.search_yahoo(word, limit)
    #     search.process()
    #     hosts = search.get_hostnames()
    #     emails = search.get_emails()
    #     all_hosts.extend(filter(hosts))
    #     all_emails.extend(filter(emails))
    #     db = stash.stash_manager()
    #     db.store_all(word, all_hosts, 'host', 'yahoo')
    #     db.store_all(word, all_emails, 'email', 'yahoo')
