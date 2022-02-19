# Client jwt
import os
import requests
import json


# login_url = 'http://localhost:4000/login'
# service_url = 'http://localhost:4001/users'
login_url = 'http://192.168.100.48/auth/login'
# service_url = 'http://192.168.100.48/api/users'
# service_url = 'http://localhost:5000/file/list'
service_url = 'http://192.168.100.202:5000/fs'


if os.name == 'nt':
	from requests_negotiate_sspi import HttpNegotiateAuth
	# auth=HttpNegotiateAuth(username='test',password='test')
	auth=HttpNegotiateAuth()
else:
	from requests_ntlm import HttpNtlmAuth
	auth=HttpNtlmAuth('test','test')


r = requests.get(login_url, auth=auth)

print(r)
print(r.text)
js = json.loads(r.text)
user = js['username']
token = js['token']
print(f'connected to login servier.')
print(f'client user: {user}')
print(f'client token: {token}')


headers = {"Authorization": f"Bearer {token}"}
r = requests.get(service_url, headers=headers)
print(f'connected to server with jwt.')
print(r.text)