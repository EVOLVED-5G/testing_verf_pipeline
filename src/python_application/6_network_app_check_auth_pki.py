
from dis import dis
import requests
import json
import configparser
import redis
import os
from termcolor import colored


def check_auth_to_aef(capif_ip, invokerId):

    print(colored("Going to check auth to AEF","yellow"))

    #url = "https://python_aef:8085/check-authentication"
    url = "https://{}:8087/check-authentication".format(capif_ip)

    payload = {
        "apiInvokerId": invokerId,
        "supportedFeatures": "fff"

    }

    files = {}
    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print(colored("''''''''''REQUEST'''''''''''''''''","blue"))
        print(colored(f"Request: to {url}","blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))
        response = requests.request("POST", url, headers=headers, json=payload, files=files, cert=('dummy.crt', 'private.key'), verify=False)
        response.raise_for_status()
        response_payload = json.loads(response.text)
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        print(colored(f"Response to: {response.url}","green"))
        print(colored(f"Response Headers: {response.headers}","green"))
        print(colored(f"Response: {response.json()}","green"))
        print(colored(f"Response Status code: {response.status_code}","green"))
        print(colored("Success to obtain auth of AEF","green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        return response_payload
    except requests.exceptions.HTTPError as err:
        print(err.response.text)
        message = json.loads(err.response.text)
        status = err.response.status_code
        raise Exception(message, status)


if __name__ == '__main__':


    config = configparser.ConfigParser()
    config.read('credentials.properties')

    username = config.get("credentials", "invoker_username")
    password = config.get("credentials", "invoker_password")
    role = config.get("credentials", "invoker_role")
    description = config.get("credentials", "invoker_description")
    cn = config.get("credentials", "invoker_cn")

    # capif_ip = config.get("credentials", "capif_ip")
    # capif_port = config.get("credentials", "capif_port")

    capif_ip = os.getenv('CAPIF_HOSTNAME')
    capif_port = os.getenv('CAPIF_PORT')

    capif_callback_ip = config.get("credentials", "capif_callback_ip")
    capif_callback_port = config.get("credentials", "capif_callback_port")

    with open('demo_values.json', 'r') as demo_file:
        demo_values = json.load(demo_file)


    try:
        if 'invokerID' in demo_values:
            invokerID = demo_values['invokerID']
            capif_access_token = demo_values['capif_access_token']
            ccf_discover_url = demo_values['ccf_discover_url']
            demo_ip = demo_values['demo_ipv4_addr_0']
            discovered_apis = check_auth_to_aef(demo_ip, invokerID)
            demo_values["ca_service"] = discovered_apis["ca_service"]
            #r.set("jwt_token", discovered_apis["access_token"])
            print(colored("Invoker Authorized to use AEF","yellow"))
            print(colored(json.dumps(discovered_apis, indent=2),"yellow"))

    except Exception as e:
        status_code = e.args[0]
        if status_code == 401:
            print("API Invoker is not authorized")
        elif status_code == 403:
            print("API Invoker does not exist. API Invoker id not found")
        else:
            print(e)

    with open('demo_values.json', 'w') as outfile:
        json.dump(demo_values, outfile)