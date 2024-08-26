#!/usr/bin/env python

import webbrowser
import sys
import os
import argparse

# 32 uses an inconsistent url, no space like the others.  Mistake on someone's part
models_dict = { 'All': lambda: list(models_dict.keys()),
                '2': '(2 vcpu, 4.5 gb),(2 vcpu, 5.5 gb),(2 vcpu, 6.5 gb)',
                '2_4': '(2 vcpu, 4.5 gb)', 
                '2_5': '(2 vcpu, 5.5 gb)', 
                '2_6': '(2 vcpu, 6.5 gb)', 
                '4': '(4 vcpu, 9 gb)', 
                '8': '(8 vcpu, 16 gb)', 
                '16': '(16 vcpu, 56 gb)',
                '22': '(22 vcpu, 56 gb)',
                '32': '(32vcpu, 56 gb)',
                'cn' : 'cn-series (cn-ngfw: 1 vcpu, 2g; cn-mgmt: 2 vcpu, 2g)'
          }


base_url = "https://www.paloaltonetworks.com/products/product-comparison"

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def argue_with_me() -> None:
    """
    This is called if there are arguments passed to the script via cli
    """
    parser = argparse.ArgumentParser(description='Gathers and generates the compare firewall URL and opens the browser to display models.  Does not validate if model types or numbers are correct.  That is on you.')
    parser.add_argument('-m', '--m_type', type=str, help='Model Type (pa, vm, cn)', required=True)
    parser.add_argument('-n', '--m_number', nargs='+', help='Model Number (415 or 2_4 or 2_4 2_6 [using spaces])', required=False)
    parser.add_argument('-a', '--all', action='store_true', help='All VM Models', required=False)
    args = parser.parse_args()
    m_type = args.m_type
    m_type = m_type.lower()
    all = args.all
    m_number = args.m_number
    if m_type == 'vm' and all: 
        m_number = models_dict['All']()[2:]  # all VMs except the 0 index key, since it covers all of the 2vCPU, so it would be redundant
    if m_type == 'cn':
        m_number = models_dict['cn']
    elif m_type == 'pa' and all:
        print("\n\nModel type can't be PA when asking for all models.  Exiting.\n\n")
        sys.exit()
    return m_type, m_number # type: ignore

def create_end_url(m_type: str, m_number: list) -> str:
    """
    Used to determine what type of model type is passed, and then unpack 
    the model numbers.  
    Depending on the model type, we build the specific URL for the comparison
    and return the url.
    """
    models_list = []
    if m_type == 'vm':
        for model in m_number:
            models_list.append(models_dict.get(model, models_dict.get('2')))
        models = ','.join(models_list)
        url = fr"{base_url}?chosen={m_type}-series {models}"
    elif m_type == 'pa':
        models = ',pa-'.join(m_number)
        url = fr"{base_url}?chosen={m_type}-{models}"
    elif m_type == 'cn':
        url = fr"{base_url}?chosen={models_dict['cn']}"
    else:
        print(f"Improper model type ->{m_type}<- (pa, vm, cn only).  Exiting...")
        sys.exit()
    return url

def dialog_get_models() -> tuple:
    """
    Generates a dialog to ask the user if they want a PA version or a 
    VM version firewall. 
    If blank or PA: User can enter simple model numbers (220, 1410)
    If VM: Dictionary above is displayed, and the user enters the values
    shown (2_4, 2_5).
    Returns -> tuple(str, list)
    """
    m_number = []
    m_type = input("Enter model type (pa, vm, cn) [pa]: ")
    m_type = m_type.lower()
    if m_type == '':
        m_type = 'pa'
    print("[q or enter to exit]", end='\n\n')
    if m_type == 'vm':
        for v in (models_dict.keys()):
                print(f"-  {v}")
    if m_type == 'cn':
        return m_type, m_number
    while True:
        model = input("Enter model number: ")
        if model.lower() == "all":
            m_number = models_dict['All']()[2:]
            break
        if model.lower() == "q" or model == "":
            break
        m_number.append(model)
    m_number = list(set(m_number))  # de-duplicate / limit to unique values
    return m_type, m_number


def main():
    clear()
    if len(sys.argv) > 1:
        m_type, m_number = argue_with_me() # type: ignore
    else:
        m_type, m_number = dialog_get_models()

    url = create_end_url(m_type, m_number)
    print(url)
    webbrowser.open(url)

if __name__ == "__main__":
    main()
