# send2cmdb

Python scripts for sending provider, service and images to CMDB.


The "examples" directory contains example data in json format and 3 shell scripts with examples of use.

In order to write to CMDB, you need IAM token and your IAM user has to be in the cmdb-dev-admins group.

For obtaining the IAM token define the client for your IAM user and pass your credentials to the parameters:

* --oidc-client-id
* --oidc-client-secret
* --oidc-username
* --oidc-password
