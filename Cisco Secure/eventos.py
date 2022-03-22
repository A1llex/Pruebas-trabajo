from ast import If, IfExp
import json
import requests
from requests.auth import HTTPBasicAuth
from pprint import pprint as pp


client_ID = '2be0d43ade16fa93ed67'
api_Key = 'e624dd38-a305-405e-98d8-c615b2831b13'
api_endpoint ='api.amp.cisco.com'
api_version = 'v1'
resource = 'events'
#ID Eventos

#"description": "A threat was found on this system."
threat_Detected_id = 1090519054

#"description": "Suspicious behavior that indicates possible compromise of the computer"
cloud_IOC_id =1107296274

#Busqueda por tipos requeridos en tarea 
payload = ( ('event_type%5B%5D', f"{threat_Detected_id}") , ('event_type%5B%5D', f"{cloud_IOC_id}"))

#https://2be0d43ade16fa93ed67:e624dd38-a305-405e-98d8-c615b2831b13@api.amp.cisco.com/v1/events?event_type%5B%5D=1090519054&event_type%5B%5D=1107296274
api_url = f"https://{client_ID}:{api_Key}@{api_endpoint}/{api_version}/{resource}"

b64 = HTTPBasicAuth(client_ID, api_Key)
headers = {
    'accept':'application/json' ,
    'content-type':'application/json',
    'accept-Encoding':'gzip',
    'Authorization':f"Basic {b64}"
}

response = requests.get(api_url,params=payload,headers=headers,verify=False)

print(response.url)
print(response.status_code)
pp(response.json)

if response.status_code != 200:
    print("Algo salio mal")
    ("exit")

#Despues filtrar solo los high y critical


