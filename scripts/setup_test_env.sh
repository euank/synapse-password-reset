#!/bin/bash

SOURCE=$( cd $( dirname "${BASH_SOURCE[0]}" ) && pwd )

set -e
set -x

# skopeo inspect docker://postgres:latest | jq '.Digest' -r
POSTGRES_DIGEST=sha256:3aa888ee9bf0f0e408e23d05bfe1243cd61d3c39a44eb439ba228a4b35e6add6
# skopeo inspect docker://euank/synapse:latest | jq '.Digest' -r
SYNAPSE_DIGEST=sha256:0fc235a8dcaf7b777e4e92eb4ea66397aa0241ab89a2f34900c5980260cc3327

# skopeo inspect docker://euank/synapse-backregister:latest | jq '.Digest' -r
BACKREGISTER_DIGEST=sha256:73df961d62aed083e9787ed11221f46c09362bf6f7046d04d76b3f179a5bfd38

pg_image="postgres@${POSTGRES_DIGEST}"
syn_image="euank/synapse@${SYNAPSE_DIGEST}"
br_image="euank/synapse-backregister@${BACKREGISTER_DIGEST}"

docker network create synapse &>/dev/null && sleep 1 || true

if ! docker images --digests | grep $POSTGRES_DIGEST &>/dev/null; then
  docker pull $pg_image
fi
if ! docker images --digests | grep $SYNAPSE_DIGEST &>/dev/null; then
  docker pull $syn_image
fi
if ! docker images --digests | grep $BACKREGISTER_DIGEST &>/dev/null; then
  docker pull $br_image
fi

if [[ "$(docker ps --filter name=syn-postgres -q)" == "" ]]; then
  docker rm -f syn-postgres || true &>/dev/null
  docker run -p 5433:5432 \
    -e POSTGRES_USER=synapse -e POSTGRES_PASSWORD=synapse \
    --net=synapse -d --name=syn-postgres $pg_image
fi

if [[ "$(docker ps --filter name=syn-synapse -q)" == "" ]]; then
  docker rm -f syn-synapse || true &>/dev/null
  docker run -p 8080:8080 --net=synapse -d -v "${SOURCE}/test_synapse_config/":/conf/ --name=syn-synapse $syn_image /conf/entrypoint.sh
fi

while ! curl -s http://localhost:8080; do
  sleep 1
done

# Run backregister

if [[ "$(docker ps --filter name=syn-br -q)" == "" ]]; then
docker run --name=syn-br \
  -e SYNAPSE_SERVER=http://syn-synapse:8080 \
  -e SYNAPSE_SECRET=secret \
  -p 8082:8000 \
  --net=synapse -d \
  $br_image
fi

while ! curl -s http://localhost:8082; do
  sleep 1
done

echo "Setup test matrix environment. Available on port 8080"
echo "Registration page available on port 8082"
