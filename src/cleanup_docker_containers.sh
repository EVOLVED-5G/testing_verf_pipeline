#!/bin/bash

docker compose down --rmi all --remove-orphans || true

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
