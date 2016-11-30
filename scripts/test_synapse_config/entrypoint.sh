#!/bin/bash

set -ex

python -m synapse.app.homeserver --config-path /conf/homeserver.yaml --generate-keys

# Wait on db
# we don't have nc, just use curl
while ! curl --connect-timeout 1 http://syn-postgres:5432 -s -S 2>&1 | grep "Empty reply"; do
  sleep 1
done

sleep 1

exec python -m synapse.app.homeserver --config-path /conf/homeserver.yaml
