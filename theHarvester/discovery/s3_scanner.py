import re
import requests


class s3_scanner:

    def __init__(self, host):
        self.host = host
        self.results = ""
        self.totalresults = ""
        self.fingerprints = ['www.herokucdn.com/error-pages/no-such-app.html', '<title>Squarespace - No Such Account</title>', "<p> If you're trying to publish one, <a href=\"https://help.github.com/pages/\">read the full documentation</a> to learn how to set up <strong>GitHub Pages</strong> for your repository, organization, or user account. </p>","<p> If you\'re trying to publish one, <a href=\"https://help.github.com/pages/\">read the full documentation</a> to learn how to set up <strong>GitHub Pages</strong> for your repository, organization, or user account. </p>","<span class=\"title\">Bummer. It looks like the help center that you are trying to reach no longer exists.</span>","<head> <title>The page you\'re looking for could not be found (404)</title> <style> body { color: #666; text-align: center; font-family: \"Helvetica Neue\", Helvetica, Arial, sans-serif; margin: 0; width: 800px; margin: auto; font-size: 14px; } h1 { font-size: 56px; line-height: 100px; font-weight: normal; color: #456; } h2 { font-size: 24px; color: #666; line-height: 1.5em; } h3 { color: #456; font-size: 20px; font-weight: normal; line-height: 28px; } hr { margin: 18px 0; border: 0; border-top: 1px solid #EEE; border-bottom: 1px solid white; } </style> </head>"]

    def __check_http(self, bucket_url):
        check_response = self.session.head(
            S3_URL, timeout=3, headers={'Host': bucket_url})

#       if not ARGS.ignore_rate_limiting\
#              and (check_response.status_code == 503 and check_response.reason == 'Slow Down'):
#            self.q.rate_limited = True
            # Add it back to the bucket for re-processing.
#           self.q.put(bucket_url)
        if check_response.status_code == 307:  # valid bucket, lets check if its public
            new_bucket_url = check_response.headers['Location']
            bucket_response = requests.request(
                'GET' if ARGS.only_interesting else 'HEAD', new_bucket_url, timeout=3)

            if bucket_response.status_code == 200\
                    and (not ARGS.only_interesting or
                             (ARGS.only_interesting and any(keyword in bucket_response.text for keyword in KEYWORDS))):
                print(f"Found bucket '{new_bucket_url}'")
                self.__log(new_bucket_url)

    def do_s3(self):
        try:
            print('\t Searching takeovers for ' + self.host)
            r = requests.get('https://' + self.host, verify=False)
            for x in self.fingerprints:
                take_reg = re.compile(x)
                self.temp = take_reg.findall(r.text)
                if self.temp != []:
                        print('\t\033[91m Takeover detected! - ' + self.host + '\033[1;32;40m')
        except Exception as e:
                print(e)

    def process(self):
        self.do_take()
