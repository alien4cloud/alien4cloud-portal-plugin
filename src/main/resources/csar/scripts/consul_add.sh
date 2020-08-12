#!/bin/bash

echo Adding to Consul ${url} for ${name}

if [ -z "${certificate}" -o -z "${key}" ]
then
   curl -X PUT -d"${data}" ${url}/v1/kv/artemis/CU/${name}
else
   curl -k --cert ${certificate} --key ${key} -X PUT -d"${data}" ${url}/v1/kv/artemis/CU/${name}
fi
