#!/bin/bash

docker exec -it $(docker ps -q -f "name=redis_db") redis-cli