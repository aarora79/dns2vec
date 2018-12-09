from __future__ import print_function

from argparse import ArgumentParser
from bs4 import BeautifulSoup
import json
import requests
import sys
import pandas as pd

class SiteReview(object):
    def __init__(self):
        self.baseurl = "https://sitereview.bluecoat.com/resource/lookup"
        self.headers = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}

    def sitereview(self, url):
        self.url = url
        payload = {"url": url, "captcha":""}
        
        try:
            # print(self.baseurl)
            self.req = requests.post(
                self.baseurl,
                headers=self.headers,
                data=json.dumps(payload),
            )
        except requests.ConnectionError:
            sys.exit("[-] ConnectionError: " \
                     "A connection error occurred")
        return BeautifulSoup(self.req.content.decode("UTF-8"), "lxml")

    def check_response(self, response):
        if self.req.status_code != 200:
            sys.exit("[-] HTTP {} returned".format(self.req.status_code))
        else:
            idx = 1 if len(response.categorization.contents) > 1 else 0
            category = response.categorization.contents[idx]
            for child in category.children:
                if child.name == "name":
                    self.category = child.string
            self.date = None

def main(filepath):
    domains = []
    categories = []
    with open(filepath) as fp:  
       lines = fp.readlines()
       lines = [line.strip() for line in lines]
    
       for l in lines:
           s = SiteReview()
           response = s.sitereview(l)
           s.check_response(response)
           domains.append(l)
           categories.append(s.category)
           print("{}, {}".format(l, s.category))
    df = pd.DataFrame({'domain': domains, 'category': categories})
    df.to_csv('domain_categories.csv', index=False)


if __name__ == "__main__":
    p = ArgumentParser()
    p.add_argument("urlfile", help="File name of file containing list of URLs, one on each line.", default="metadatafp")
    args = p.parse_args()

    main(args.urlfile)
