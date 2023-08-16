#!/usr/bin/env python

import webbrowser
import sys

"""
How to use me:
Pass arguments to the script:  ./compare.py 220 220r
or not, and we prompt for model numbers only, we glue the url together and open the browser.
"""

def create_end_url(models: list) -> str:
    return ',pa-'.join(models)

def get_models() -> list:
    frwls = []
    print("[q or enter to exit]")
    while True:  
        model = input("Enter model number: ")
        if model.lower() == "q" or model == "":
            return frwls
        frwls.append(model)

def main():
    frwls = sys.argv[1:]
    if not frwls:
        frwls = get_models()
    models = create_end_url(frwls)

    url = fr"https://www.paloaltonetworks.com/products/product-comparison?chosen=pa-{models}"

    print(url)
    webbrowser.open(url)

if __name__ == "__main__":
    main()
