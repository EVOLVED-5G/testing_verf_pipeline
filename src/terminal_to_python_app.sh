#!/bin/bash

docker exec -it $(docker ps -q -f "name=python_app") bash