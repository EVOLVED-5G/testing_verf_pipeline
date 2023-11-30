from dis import dis
import requests
import json
import configparser
import redis
import os
from termcolor import colored
# Get environment variables
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.environ.get('REDIS_PORT')


def events_service_apis(capif_addr, api_invoker_id):
    print(colored("Discover Service","yellow"))
    #url = "https://{}/{}{}".format(capif_addr, ccf_url, api_invoker_id)
    # url = "https://capif.apps.ocp-epg.hi.inet/capif-events/v1/"+api_invoker_id+"/subscriptions"
    url = "https://"+capif_addr+"/capif-events/v1/"+api_invoker_id+"/subscriptions"
    with open('events.json', "rb") as f:
        payload = json.load(f)
    files = {}
    headers = {
        'Content-Type': 'application/json'
    }
    try:
        print(colored("''''''''''REQUEST'''''''''''''''''","blue"))
        print(colored(f"Request: to {url}","blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))
        response = requests.request("POST", url, headers=headers, json=payload, cert=('dummy.crt', 'private.key'), verify='ca.crt')
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
    # r = redis.Redis(
    #     host=REDIS_HOST,
    #     port=REDIS_PORT,
    #     decode_responses=True,
    # )

    with open('demo_values.json', 'r') as demo_file:
        demo_values = json.load(demo_file)

    config = configparser.ConfigParser()
    config.read('credentials.properties')
    username = config.get("credentials", "invoker_username")
    password = config.get("credentials", "invoker_password")
    role = config.get("credentials", "invoker_role")
    description = config.get("credentials", "invoker_description")
    cn = config.get("credentials", "invoker_cn")
    capif_ip = os.getenv('CAPIF_HOSTNAME')
    capif_port = os.getenv('CAPIF_PORT')
    capif_callback_ip = config.get("credentials", "capif_callback_ip")
    capif_callback_port = config.get("credentials", "capif_callback_port")
    try:
        if 'invokerID' in demo_values:
            invokerID = demo_values['invokerID']
            # capif_access_token = r.get('capif_access_token')
            # ccf_discover_url = r.get('ccf_discover_url')
            discovered_apis = events_service_apis(capif_ip, invokerID)
    except Exception as e:
        status_code = e.args[0]
        if status_code == 401:
            print("API Invoker is not authorized")
        elif status_code == 403:
            print("API Invoker does not exist. API Invoker id not found")
        else:
            print(e)