# Dummy Network Application

## Architecture

| Container             | Folder                | Description                                      |
|-----------------------|-----------------------|--------------------------------------------------|
| python_app            | python_application    | Python Application (communication example with CAPIF) |
| redis_db              | -                     | DB to store info exchanged with CAPIF            |
| nef_callback_server   | nef_callback_server   | Server implementing NEF callback endpoints       |
| capif_callback_server | capif_callback_server | Server implementing CAPIF callback endpoints     |

## Development status

| Development Task                    | Subtask                            | Status |
|-------------------------------------|------------------------------------|--------|
| Communication with CAPIF (v. 3.0)   | Register                           | ✅      |
|                                     | Invoker Management API             | ✅      |
|                                     | Discover Service API               | ✅      |
|                                     | Security API                       | ✅      |
| Communication with NEF (v. 2.0.0)   | Monitoring Event API               | ✅      |
|                                     | Session With QoS API               | ✅      |
|                                     | Connection Monitoring API          | ✅      |
| Communication with TSN              | [GET] /profile API                 | ✅      |
|                                     | [GET] /profile?name=<profile_name> | ✅      |
|                                     | [POST] /apply                      | ✅      |
|                                     | [POST] /clear                      | ✅      |
| Use of CAPIF SDK libraries          | -                                  | ✅      |
| Use of NEF SDK libraries            | -                                  | ✅      |
| Use of TSN SDK libraries            | -                                  | ✅      |
| TLS Communication with CAPIF        | -                                  | ✅      |
| TLS Communication with NEF          | -                                  | ✅      |
| TLS Communication with TSN          | -                                  | ❌      |
| Callback server for NEF responses   | -                                  | ✅      |
| Callback server for CAPIF responses | -                                  | ✅      |
| Callback server for TSN responses   | -                                  | ❌      |
| Communication with dummy_aef        | -                                  | ✅      |


## Container management
Pre-condition:
- Deploy CAPIF, NEF and TSN stack (locally or on another server)

All configuration of the network application is defined as environment variables 
in env_to_copy.dev

If CAPIF, NEF and TSN are running on the same host as dummy network application,
then leave the configuration as it is. 
Otherwise, according to the architecture followed edit the variables:
- NEF_IP and TSN_IP (setting it as the IP / server name of the host that NEF is deployed)
- NEF_CALLBACK_IP & CAPIF_CALLBACK_URL (setting them as the IP / server name of the host that dummy network application is deployed)

**For communication with dummy_aef, demo-network is created.

```shell
# Deploy and run containers
./run.sh

# Access Redis cli (to see NEF access token, responses and callbacks)
./redis_cli.sh

## Inside redis cli, execute the following command 
## to see the redis variables where the info is stored
keys *

## Inside redis cli, execute the following command 
## to see the content of a redis variable
get *key*


# Stop containers
./stop.sh

# Stop and Remove containers
./cleanup_docker_containers.sh
```

## Use Python Application

```shell
cd src/
# Access Python Application
./terminal_to_python_app.sh

# Inside the container
# Test Network Application with CAPIF and NEF
python3 0_network_app_to_nef.py

# Test Network Application with CAPIF and TSN
python3 0_network_app_to_tsn.py

# Test Network Application with CAPIF and dummy_aef
# IMPORTANT: to test with dummy_aef, do not deploy NEF or/and TSN. It must be tested on its own
python3 1_network_app_to_capif.py
python3 2_network_app_to_events.py
python3 3_network_app_discover_service.py
python3 4_network_app_to_security.py
#In dummy_aef execute 5_aef_service_oauth.py
python3 5_network_app_to_service_oauth.py
#In dummy_aef execute 6_aef_security.py
python3 6_network_app_check_auth_pki.py
#In dummy_aef execute 7_aef_service_pki.py
python3 7_network_app_to_service_pki.py

# Outside container, for clean-up
(
sudo rm ./python_application/capif_onboarding/*
sudo rm ./python_application/demo_values.json
sudo rm ./python_application/ca.crt
sudo rm ./python_application/cert_req.csr
sudo rm ./python_application/dummy.crt
sudo rm ./python_application/private.key
sudo rm ./python_application/ca_service.crt
sudo rm .env
)
```