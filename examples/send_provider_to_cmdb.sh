python send_provider_to_cmdb.py \
  --cmdb-read-url 'http://10.200.132.165:8080/cmdb' \
  --cmdb-write-url 'http://10.200.132.165:8080/cmdb-crud' \
  --oidc-token-url 'http://10.200.132.40:8080/token' \
  --oidc-client-id '***client-id***' \
  --oidc-client-secret '***client-secret***' \
  --oidc-username '***user***' \
  --oidc-password '***password***' \
  --provider-id 'PSNC' \
  <provider.json
