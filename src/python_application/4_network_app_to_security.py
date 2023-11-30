from dis import dis
from email import charset
import requests
import json
import configparser
import redis
import os
from termcolor import colored
# Get environment variables
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.environ.get('REDIS_PORT')

def register_security_service(capif_ip, api_invoker_id, jwt_token, ccf_url, demo_values):


    #url = "https://{}/{}{}".format(capif_ip, ccf_url, api_invoker_id)
    url = "https://{}/capif-security/v1/trustedInvokers/{}".format(capif_ip, api_invoker_id)

    with open('security_info.json', "rb") as f:
        payload = json.load(f)

    count = 0
    for profile in payload["securityInfo"]:
        profile["aefId"] = demo_values[f"aef_id_{count}"]
        profile["apiId"] = demo_values[f"api_id_{count}"]
        count += 1

    print(payload)


    files = {}
    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print(colored("''''''''''REQUEST'''''''''''''''''","blue"))
        print(colored(f"Request: to {url}","blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

        response = requests.put(url, json=payload, cert=('dummy.crt', 'private.key'), verify='ca.crt')
        response.raise_for_status()
        response_payload = response.json()

        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        print(colored(f"Response to: {response.url}","green"))
        print(colored(f"Response Headers: {response.headers}","green"))
        print(colored(f"Response: {response.json()}","green"))
        print(colored(f"Response Status code: {response.status_code}","green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))

        return response_payload
    except requests.exceptions.HTTPError as err:
        print(err.response.text)
        message = json.loads(err.response.text)
        status = err.response.status_code
        raise Exception(message, status)

def get_security_service(capif_ip, api_invoker_id, jwt_token, ccf_url):

    #url = "https://{}/{}{}".format(capif_ip, ccf_url, api_invoker_id)
    url = "https://{}/capif-security/v1/trustedInvokers/{}".format(capif_ip, api_invoker_id)

    #payload = open('security_info.json', "rb")
    files = {}
    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print(colored("''''''''''REQUEST'''''''''''''''''","blue"))
        print(colored(f"Request: to {url}","blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

        response = requests.request("GET", url, headers=headers, files=files, cert=('dummy.crt', 'private.key'), verify='ca.crt')
        response.raise_for_status()
        response_payload = json.loads(response.text)

        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        print(colored(f"Response to: {response.url}","green"))
        print(colored(f"Response Headers: {response.headers}","green"))
        print(colored(f"Response: {response.json()}","green"))
        print(colored(f"Response Status code: {response.status_code}","green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))

        return response_payload
    except requests.exceptions.HTTPError as err:
        print(err.response.text)
        message = json.loads(err.response.text)
        status = err.response.status_code
        raise Exception(message, status)


def get_security_token(capif_ip, api_invoker_id, jwt_token, ccf_url, aef_id, api_name):

  
    url = "https://{}/capif-security/v1/securities/{}/token".format(capif_ip, api_invoker_id)

    with open('token_request.json', "rb") as f:
        payload = json.load(f)

    payload["client_id"] = api_invoker_id
    payload["scope"] = "3gpp#"+aef_id+":"+api_name
    # data ={
    #     "grant_type": "client_credentials",
    #     "client_id": "29f1107e089f5a95ae57826d85f4ef",
    #     "client_secret": "string",
    #     "scope": "3gpp#ec2b554166ca9c7b6c75250956f302:dummy-aef"
    # }

    #payload_dict = json.dumps(data)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    try:
        print(colored("''''''''''REQUEST'''''''''''''''''","blue"))
        print(colored(f"Request: to {url}","blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

        response = requests.post(url, headers=headers, data=payload, cert=('dummy.crt', 'private.key'), verify='ca.crt')
        print(response.request.body)
        response.raise_for_status()
        response_payload = json.loads(response.text)

        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        print(colored(f"Response to: {response.url}","green"))
        print(colored(f"Response Headers: {response.headers}","green"))
        print(colored(f"Response: {response.json()}","green"))
        print(colored(f"Response Status code: {response.status_code}","green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))

        return response_payload
    except requests.exceptions.HTTPError as err:
        print(err.response.text)
        message = json.loads(err.response.text)
        status = err.response.status_code
        raise Exception(message, status)


if __name__ == '__main__':

    with open('demo_values.json', 'r') as demo_file:
        demo_values = json.load(demo_file)

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

    invokerID = ""
    capif_access_token = ""
    ccf_discover_url = ""

    try:
        if 'invokerID' in demo_values:

            invokerID = demo_values['invokerID']
            capif_access_token = demo_values['capif_access_token']
            ccf_discover_url = demo_values['ccf_discover_url']
            security_information = register_security_service(capif_ip, invokerID, capif_access_token, ccf_discover_url, demo_values)
            print(colored(json.dumps(security_information, indent=2),"yellow"))
            print(colored("Register Security context","yellow"))
    except Exception as e:
        status_code = e.args[0]
        if status_code == 401:
            print("API Invoker is not authorized")
        elif status_code == 403:
            print("API Invoker does not exist. API Invoker id not found")
        else:
            print(e)


    try:
        if 'aef_id_1' in demo_values and 'api_name_1' in demo_values:
            token = get_security_token(capif_ip, invokerID, capif_access_token, ccf_discover_url, demo_values['aef_id_1'], demo_values['api_name_1'])
            print(colored(json.dumps(token, indent=2),"yellow"))
            demo_values["network_app_service_token"] = token["access_token"]
            print(colored("Obtained Security Token","yellow"))

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