import re
import requests


class take_over:

    def __init__(self, host):
        self.host = host
        self.results = ""
        self.totalresults = ""
        self.fingerprints = ["<title>Squarespace - Domain Not Claimed</title>",
        'www.herokucdn.com/error-pages/no-such-app.html',
        '<title>Squarespace - No Such Account</title>',
        "<p> If you're trying to publish one, <a href=\"https://help.github.com/pages/\">read the full documentation</a> to learn how to set up <strong>GitHub Pages</strong> for your repository, organization, or user account. </p>",
        "<p> If you\'re trying to publish one, <a href=\"https://help.github.com/pages/\">read the full documentation</a> to learn how to set up <strong>GitHub Pages</strong> for your repository, organization, or user account. </p>",
        "<span class=\"title\">Bummer. It looks like the help center that you are trying to reach no longer exists.</span>",
        "<head> <title>The page you\'re looking for could not be found (404)</title> <style> body { color: #666; text-align: center; font-family: \"Helvetica Neue\", Helvetica, Arial, sans-serif; margin: 0; width: 800px; margin: auto; font-size: 14px; } h1 { font-size: 56px; line-height: 100px; font-weight: normal; color: #456; } h2 { font-size: 24px; color: #666; line-height: 1.5em; } h3 { color: #456; font-size: 20px; font-weight: normal; line-height: 28px; } hr { margin: 18px 0; border: 0; border-top: 1px solid #EEE; border-bottom: 1px solid white; } </style> </head>",
        'The specified bucket does not exist',
        'Bad Request: ERROR: The request could not be satisfied',
        'Fastly error: unknown domain:',
        "There isn't a Github Pages site here.",
        'No such app',
        'Unrecognized domain',
        'Sorry, this shop is currently unavailable.',
        "Whatever you were looking for doesn't currently exist at this address",
        'The requested URL was not found on this server.',
        'This UserVoice subdomain is currently available!',
        'Do you want to register *.wordpress.com?',
        'Help Center Closed']

    def do_take(self):
        try:
            print('\t Searching takeovers for ' + self.host)
            r = requests.get('https://' + self.host, verify=False)
            for x in self.fingerprints:
                take_reg = re.compile(x)
                self.temp = take_reg.findall(r.text)
                if self.temp != []:
                        print(f'\t\033[91m Takeover detected! - {self.host} \033[1;32;40m')
        except Exception as e:
                print(e)

    def process(self):
        self.do_take()
