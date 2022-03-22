import pandas as pd
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
payload = ( ('event_type%5B%5D', f"{threat_Detected_id}") , 
            ('event_type%5B%5D', f"{cloud_IOC_id}"))

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

eventos = response.json

if(eventos['metadata']['results']['current_item_count'] < 1):
    print("no hay eventos")

eventos_data = {"Eventos":["Threat Detected","Cloud IOC"],"Severidad":[],"data" :[]}

ev_High = 0
for data in eventos['data']:
    if data['severity'] == "High" :
        ev_High+=1
        eventos_data['data'].append({
                            "Hostname" :data['computer']['hostname'],
                            "File name":data['file']['file_name'],
                            "File Path":data['file']['file_path'],                            
                            "Detection":data['detection'],
                            "Disposition": data['file']['disposition'],
                            "Type Event" : data['event_type'],
                            "Severity":data['severity'],
                            "SHA256": data['file']['identity']['sha256']
                            })
eventos_data['Severidad'].append({"High":ev_High})

ev_Crit = 0
for data in eventos['data']:
    if data['severity'] == "Critical" :
        ev_Crit +=1
        eventos_data['data'].append({
                            "Hostname" :data['computer']['hostname'],
                            "File name":data['file']['file_name'],
                            "File Path":data['file']['file_path'],                            
                            "Detection":data['detection'],
                            "Disposition": data['file']['disposition'],
                            "Type Event" : data['event_type'],
                            "Severity":data['severity'],
                            "SHA256": data['file']['identity']['sha256']
                            })
eventos_data['Severidad'].append({"Critical":ev_Crit})

print(eventos_data)
print(len(eventos_data['data']))


dataframe = pd.DataFrame(eventos_data['data'])
dataframe.to_csv('prueba.csv') # relative position



