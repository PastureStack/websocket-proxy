#!/bin/bash

go clean
go build

PLATFORM_HOME=${PASTURESTACK_HOME:-${CATTLE_HOME:-/var/lib/pasturestack}}
./websocket-proxy -jwt-public-key-file="$PLATFORM_HOME/api.crt" -listen-address="localhost:8080" -platform-address="localhost:8081"
