#!/usr/bin/env bash

# Synapse password reset
# Copyright (C) 2016 Euan Kemp
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

SOURCE=$( cd $( dirname "${BASH_SOURCE[0]}" ) && pwd )

set -e
set -x

# skopeo inspect docker://postgres:latest | jq '.Digest' -r
POSTGRES_DIGEST=sha256:3aa888ee9bf0f0e408e23d05bfe1243cd61d3c39a44eb439ba228a4b35e6add6
# skopeo inspect docker://euank/synapse:latest | jq '.Digest' -r
SYNAPSE_DIGEST=sha256:0fc235a8dcaf7b777e4e92eb4ea66397aa0241ab89a2f34900c5980260cc3327

# skopeo inspect docker://euank/synapse-backregister:latest | jq '.Digest' -r
BACKREGISTER_DIGEST=sha256:9c77fc658ffc3220491c68d229b0f5e860d7d45d5cf10a479a0c3aa93404e173

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
  docker run -p 8080:8080 \
    --net=synapse -d \
    -v "${SOURCE}/test_synapse_config/":/conf/ \
    -v "${SOURCE}/test_synapse_config/logconfig.yaml":/base-conf/log.config \
    --name=syn-synapse \
    $syn_image /conf/entrypoint.sh
fi

while ! curl -s http://localhost:8080; do
  sleep 1
done

# Run backregister

if [[ "$(docker ps --filter name=syn-br -q)" == "" ]]; then
  docker rm -f syn-br || true &>/dev/null
  docker run --name=syn-br \
  -e SYNAPSE_SERVER=http://syn-synapse:8080 \
  -e SYNAPSE_SECRET=registration-secret \
  -p 8082:8000 \
  --net=synapse -d \
  $br_image
fi

while ! curl -s http://localhost:8082; do
  sleep 1
done

echo "Setup test matrix environment. Available on port 8080"
echo "Registration page available on port 8082"
