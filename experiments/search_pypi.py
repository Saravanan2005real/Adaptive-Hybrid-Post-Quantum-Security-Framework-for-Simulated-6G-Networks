import urllib.request
import json
import xmlrpc.client

client = xmlrpc.client.ServerProxy('https://pypi.org/pypi')
results = client.search({'name': 'kyber'})
for hit in results:
    print(hit['name'])
