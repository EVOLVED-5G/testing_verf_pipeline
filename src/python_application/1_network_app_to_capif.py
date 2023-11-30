from dis import dis
import requests
import json
import configparser
import redis
import os
from termcolor import colored


from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL.crypto import (dump_certificate_request, dump_privatekey, load_publickey, PKey, TYPE_RSA, X509Req, dump_publickey)


def create_csr(csr_file_path):
    private_key_path = "private.key"

    # create public/private key
    key = PKey()
    key.generate_key(TYPE_RSA, 2048)

    # Generate CSR
    req = X509Req()
    req.get_subject().CN = config.get("credentials", "invoker_cn")
    req.get_subject().O = 'Telefonica I+D'
    req.get_subject().OU = 'Innovation'
    req.get_subject().L = 'Madrid'
    req.get_subject().ST = 'Madrid'
    req.get_subject().C = 'ES'
    req.get_subject().emailAddress = 'inno@tid.es'
    req.set_pubkey(key)
    req.sign(key, 'sha256')

    with open(csr_file_path, 'wb+') as f:
        f.write(dump_certificate_request(FILETYPE_PEM, req))
        csr_request = dump_certificate_request(FILETYPE_PEM, req)
    with open(private_key_path, 'wb+') as f:
        f.write(dump_privatekey(FILETYPE_PEM, key))

    return csr_request


def register_network_app_to_capif(capif_ip, capif_port, username, password, role, description, cn):

    print(colored("Registering API Invoker to CAPIF","yellow"))
    url = "http://{}:{}/register".format(capif_ip, capif_port)

    payload = dict()
    payload['username'] = username
    payload['password'] = password
    payload['role'] = role
    payload['description'] = description
    payload['cn'] = cn

    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print(colored("''''''''''REQUEST'''''''''''''''''","blue"))
        print(colored(f"Request: to {url}","blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"Request Body: {json.dumps(payload)}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

        response = requests.request("POST", url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        response_payload = json.loads(response.text)
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        print(colored(f"Response to: {response.url}","green"))
        print(colored(f"Response Headers: {response.headers}","green"))
        print(colored(f"Response: {response.json()}","green"))
        print(colored(f"Response Status code: {response.status_code}","green"))
        print(colored("Invoker registered successfuly", "green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        return response_payload['id'], response_payload['ccf_onboarding_url'], response_payload['ccf_discover_url'],
    except requests.exceptions.HTTPError as err:
        raise Exception(err.response.text, err.response.status_code)


def get_capif_token(capif_ip, capif_port, username, password, role):

    print(colored("Invoker Get CAPIF auth","yellow"))
    url = "http://{}:{}/getauth".format(capif_ip, capif_port)

    payload = dict()
    payload['username'] = username
    payload['password'] = password
    payload['role'] = role

    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print(colored("''''''''''REQUEST'''''''''''''''''","blue"))
        print(colored(f"Request: to {url}","blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"Request Body: {json.dumps(payload)}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

        response = requests.request("POST", url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        response_payload = json.loads(response.text)

        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        print(colored(f"Response to: {response.url}","green"))
        print(colored(f"Response Headers: {response.headers}","green"))
        print(colored(f"Response: {response.json()}","green"))
        print(colored(f"Response Status code: {response.status_code}","green"))
        print(colored("Access Token obtained","green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
    
        ca_root_file = open('ca.crt', 'wb+')
        ca_root_file.write(bytes(response_payload['ca_root'], 'utf-8'))
        return response_payload['access_token']
    except requests.exceptions.HTTPError as err:
        raise Exception(err.response.text, err.response.status_code)


def onboard_network_app_to_capif(capif_ip, capif_callback_ip, capif_callback_port, jwt_token, ccf_url):

    print(colored("Onboarding network application to CAPIF","yellow"))
    url = 'https://{}/{}'.format(capif_ip, ccf_url)

    csr_request = create_csr("cert_req.csr")

    json_file = open('invoker_details.json', 'rb')
    payload_dict = json.load(json_file)
    payload_dict['onboardingInformation']['apiInvokerPublicKey'] = csr_request.decode("utf-8")
    payload_dict['notificationDestination'] = payload_dict['notificationDestination'].replace("X", capif_callback_ip)
    payload_dict['notificationDestination'] = payload_dict['notificationDestination'].replace("Y", capif_callback_port)
    payload = json.dumps(payload_dict)

    headers = {
        'Authorization': 'Bearer {}'.format(jwt_token),
        'Content-Type': 'application/json'
    }

    try:
        print(colored("''''''''''REQUEST'''''''''''''''''","blue"))
        print(colored(f"Request: to {url}","blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"Request Body: {json.dumps(payload)}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

        response = requests.request("POST", url, headers=headers, data=payload, verify='ca.crt')
        response.raise_for_status()
        response_payload = json.loads(response.text)
        certification_file = open('dummy.crt', 'wb')
        certification_file.write(bytes(response_payload['onboardingInformation']['apiInvokerCertificate'], 'utf-8'))
        certification_file.close()

        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        print(colored(f"Response to: {response.url}","green"))
        print(colored(f"Response Headers: {response.headers}","green"))
        print(colored(f"Response: {response.json()}","green"))
        print(colored(f"Response Status code: {response.status_code}","green"))
        print(colored("Success onboard invoker","green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        return response_payload['apiInvokerId']
    except requests.exceptions.HTTPError as err:
        raise Exception(err.response.text, err.response.status_code)





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

    if os.path.exists("demo_values.json"):
        os.remove("demo_values.json")

    demo_values = {}

    try:
        if 'network_app_id' not in demo_values:
            network_app_id, ccf_onboarding_url, ccf_discover_url = register_network_app_to_capif(capif_ip, capif_port, username, password, role, description, cn)
            demo_values['network_app_id'] = network_app_id
            demo_values['ccf_onboarding_url'] = ccf_onboarding_url
            demo_values['ccf_discover_url'] = ccf_discover_url
            print(colored(f"NetworkAppID: {network_app_id}\n","yellow"))
    except Exception as e:
        status_code = e.args[0]
        if status_code == 409:
            print("User already registed. Continue with token request\n")
        else:
            print(e)

    try:
        if 'capif_access_token' not in demo_values and 'network_app_id' in demo_values:
            capif_access_token = get_capif_token(capif_ip, capif_port, username, password, role)
            demo_values['capif_access_token'] = capif_access_token
            print(colored(f"Capif Token: {capif_access_token}\n","yellow"))
    except Exception as e:
        status_code = e.args[0]
        if status_code == 401:
            print("Bad credentials. User not found\n")
        else:
            print(e)
        capif_access_token = None

    try:
        if 'invokerID' not in demo_values:
            capif_access_token = demo_values['capif_access_token']
            ccf_onboarding_url = demo_values['ccf_onboarding_url']
            invokerID = onboard_network_app_to_capif(capif_ip, capif_callback_ip, capif_callback_port, capif_access_token, ccf_onboarding_url)
            demo_values['invokerID'] = invokerID
            print("ApiInvokerID: {}\n".format(invokerID))
    except Exception as e:
        status_code = e.args[0]
        if status_code == 401:
            capif_access_token = get_capif_token(capif_ip, capif_port, username, password, role)
            demo_values['capif_access_token'] = capif_access_token
            ccf_onboarding_url = demo_values['ccf_onboarding_url']
            print("New Capif Token: {}\n".format(capif_access_token))
            invokerID = onboard_network_app_to_capif(capif_ip, capif_callback_ip, capif_callback_port, capif_access_token, ccf_onboarding_url)
            data_invoker = [{"invokerID": invokerID}]
            demo_values['invokerID'] = invokerID
            print(colored(f"ApiInvokerID: {invokerID}\n","yellow"))
        elif status_code == 403:
            print("Invoker already registered.")
            print("Chanage invoker public key in invoker_details.json\n")
        else:
            print(e)

    with open('demo_values.json', 'a') as outfile:
        json.dump(demo_values, outfile)