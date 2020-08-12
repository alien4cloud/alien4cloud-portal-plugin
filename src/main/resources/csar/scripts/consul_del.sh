#!/bin/bash

echo Removing ${name} from Consul ${url}
if [ -z "${certificate}" -o -z "${key}" ]
then
   curl -X DELETE ${url}/v1/kv/artemis/CU/${name}
else
   curl -k --cert ${certificate} --key ${key} -X DELETE ${url}/v1/kv/artemis/CU/${name}
fi
