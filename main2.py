
import sys
import threading 
import time 
from base64 import b64encode
import requests
from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException
import urllib3
import arrow 
import json
import mysql.connector
from mysql.connector import Error
import logging 

logging.basicConfig(level=logging.INFO,filename="/var/log/asset/asset.log",filemode="w",format="%(asctime)s - %(levelname)s - %(message)s")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

wazuh_alert_file_path = '/var/ossec/logs/alerts/alerts.json'

# database connection
DB_HOSTNAME = 'localhost'
DB_USERNAME= 'pythonscript'
DB_PASSWORD =  '@PythonScript8.#'
DB_NAME = 'mmcy'

# wazuh server api 
WAZUH_SERVER_IP = "192.168.128.95"
WAZUH_SERVER_PORT = "55000"
WAZUH_SERVER_USERNAME ="wazuh-wui"
WAZUH_SERVER_PASSWORD = "1c3Kwfh*UoyLVHkHn+Y+rlB66fgKAv4d"


def readFile(id,target):
        hardware_info = None
        try:
                with open(wazuh_alert_file_path,'r',encoding='latin-1') as file:
                        for line in file:
                                entry = json.loads(line.strip())
                                if entry.get('agent',{}).get('id') == id and entry.get('data',{}).get(target) != None:
                                   if  target == 'LocalDisk':
                                      hardware_info = entry.get('data',{}).get(target,{}).get('Size')
                                   else:
                                     hardware_info = entry.get('data',{}).get(target)
                                   #print(hardware_info)
                                   
        except FileNotFoundError:
                logging.error(f"Error: The file {file_path} does not exist")
        except json.JSONDecodeError:
                logging.error(f"Error: Failed to decode JSON from the file.")
        except Exception as e:
                logging.error(f"An unexpected error occurred: {e}")

        return  hardware_info

def getModel(id,target):
        return readFile(id,target)

def getVendor(id,target):
        return readFile(id,target)

def getLocalDisk(id,target):
        
        result = readFile(id,target)
        try:
           result = int(float(result))
           result = f"{result /(1024 **3):.2f} GB"
        except:
          pass
        return result

def getHostname(id,target):
        return readFile(id,target)

def getUsername(id,target):
        
        return readFile(id,target)

def getSerialNumber(id,target):
        return readFile(id,target)

def getDiskUsage(id,target):
    return readFile(id,target)

def getRamUsage(id,target):
    return readFile(id,target) 

def getCpuUsage(id,target):
    return readFile(id,target) 

def getNetworkUsage(id,target):
    return readFile(id, target) 

def getPatchInfo(id,target):
    return readFile(id,target) 

def getMonitor(id,target):
    return readFile(id, target)

def getKeyboard(id, target):
    return readFille(id, target)

def getMouse(id, target):
    return readFile(id, target) 

def getHeadSet(id, target):
    return readFile(id, target)

def getDockingStation(id, target):
     return readFile(id, target) 

def getUsbDrive(id, target):
    return readFile(id, target)

def getBitlocker(id, target):
    return readFile(id, target)

def getAccount(id, target):
    return readFile(id, target)

def getVPN(id, target):
   return readFile(id, target)

def getLicensed(id, target):
   return readFile(id, target) 

  

def getHardware(host,token, agent_id):

    hardware_info = {
             "processor":None,
             "memory":None
    
}

    headers = {  
                'Authorization': f'Bearer {token}',  
                 'Content-Type': 'application/json'  
                }  
    
    url = f"{host}/syscollector/{agent_id}/hardware/?pretty=true" 

    response = requests.get(url, headers=headers,verify=False) 
    if response.status_code == 200:  
        data = response.json()['data']['affected_items'][0]  

        if 'board_serial' in data:
            hardware_info['serial_number'] = data['board_serial'] 

        if 'cpu' in data:
            hardware_info['processor'] =  f"{data['cpu']['name']}, cores: {data['cpu']['cores']}"

        if 'ram' in data:
            hardware_info['memory'] =  f"{(data['ram']['total']/1024)/1024:.2f} GB"

        if 'scan' in data:
            now = arrow.now()
            hardware_info['scan_time'] = arrow.get(data['scan']['time']).humanize(now)  if data['scan']['time'] is not None else None
             
    return hardware_info
    


def FieldValue(data):
    
     print(data)
     fValue = { }
     fields = ["username","hostname","serialNumber","hardwareModel","hardwareVendor","memory","processor","localDisk","platform","department"]
     for index, value in enumerate(data):
        fValue[fields[index]] =  value
        
     return fValue

def parseSqlData(data):
    
    fields = ["username", "hostname","serialNumber","hardwareModel","hardwareVendor","memory","processor","localDisk","platform","department"]
    fValue = {}
    for index, value in enumerate(data[1:-1]):
       fValue[fields[index]] = value
           
    return fValue

def insert_asset(connection,data):
   
   print("Please show me") 
   cursor = connection.cursor()
   print("Really")
   new_data = FieldValue(data)
   serialNumber = data[2]
   print(serialNumber)
   print(new_data)
   cursor.execute("select * from MMCYASSET WHERE serialNumber = %s",(serialNumber,))
   existing_data = cursor.fetchone()
   print(existing_data)
   print("Got it")
   if existing_data:
      # update only the columns that have new values
      parsed_data = parseSqlData(existing_data)
      update_fields =  []
      update_values =  []

      for column, new_value in new_data.items():
          print(new_value)
          if parsed_data[column] != new_value:
             update_fields.append(f"{column}= %s")
             update_values.append(new_value)
            
          
      if update_fields:
          update_query = f"update MMCYASSET SET {', '.join(update_fields)} WHERE serialNumber = {serialNumber}"
          print(update_query)
          cursor.execute(update_query,update_values)
 
   else:
       # Insert new record

       insert_query = """
      
       insert into MMCYASSET(username,hostname,serialNumber,hardwareModel,hardwareVendor,memory,processor,localDisk,platform,department,timestamp)
       values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
       """
   
       try:
           cursor.execute(insert_query,data)
           connection.commit()
           logging.info(f"{data[0]} laptop pushed to database") 
           print(f"{data[0]} laptop pushed to database")
       except Error as e:
           logging.error(f"The Error {e} occured")
           print(f"The Error {e} occured data {data}!!")


def create_connection():
  
   connection = None 
   try:
     connection = mysql.connector.connect(
                  host=DB_HOSTNAME,
                  user=DB_USERNAME,
                  password=DB_PASSWORD,
                  database=DB_NAME,
                  ssl_disabled=True
                 )
     
   except Error as e:
       logging.error(f"the Error:{e} occured")

   return connection 

    
def  saveToDb(data):
   print("I am here not there")
   connection = create_connection()
   print("Not problem with connection")
   if data[2] != "Unknown":
       print("Going there")
       insert_asset(connection,data)
   else:
       print(data)

def agentInfoList(agent_data):
    agent_data_list = []
    #print(f"data:{agent_data}, type:{type(agent_data)}")
    #print("Error in the list ...")    
    if isinstance(agent_data.get('department'),list):
         if len(agent_data['department']) > 1:
              agent_data['department'] = agent_data['department'][1]
         else:
             agent_data['department'] = agent_data['department'][0]

    #agent_data_list.insert(0,agent_data.get('id',None))
    agent_data_list.insert(1,agent_data.get('username',None))
    agent_data_list.insert(2,agent_data.get('hostname',None))
    agent_data_list.insert(3,agent_data.get('serial_number',None))
    agent_data_list.insert(4,agent_data.get('hardware_model',None))
    agent_data_list.insert(5,agent_data.get('hardware_vendor',None))
    agent_data_list.insert(6,agent_data.get('memory',None))
    agent_data_list.insert(7,agent_data.get('processor',None))
    agent_data_list.insert(8,agent_data.get('local_disk',None))
    agent_data_list.insert(9,agent_data.get('platform',None))
    agent_data_list.insert(10,agent_data.get('department',None))
    print(tuple(agent_data_list))
    return tuple(agent_data_list)


def parseAgent(host,data,token):
    headers = {  
                'Authorization': f'Bearer {token}',  
                 'Content-Type': 'application/json'  
                }  
    
    agent = {
        "id":None,
        "username": None,
        "department":None,
        "processor":None,
        "memory": None,
        "serial_number":None,
        "hardware_model":None,
        "hardware_vendor":None,
        "hostname": None,
        "local_disk":None,
        "platform": None

    }

    agent['id'] = data.get('id',"Unknown")
    agent['username'] = data.get('name',"Unknown") 
    agent['hostname'] =  data['os']['name'] if 'os' in data else "Unknown"   
    agent['platform'] = data['os']['name'] if 'os' in data else "Unknown"
    agent['status'] = data.get('status',"Unknown") 
    agent['lastKeepAlive'] = arrow.get(data['lastKeepAlive']).humanize(arrow.now()) if 'lastKeepAlive' in data else "Unknown" 
    agent['joined_date'] = arrow.get(data['dateAdd']).humanize(arrow.now()) if 'dateAdd' in data else "Unknown" 
    agent['department'] = data['group'] if 'group' in data else "Unknown"  
    hw_info = getHardware(host,token,agent['id']) 
    agent['memory'] = hw_info.get('memory', "Unknown") 
    agent['processor'] = hw_info.get('processor', "Unknown") 
    agent['scan_time'] = hw_info.get('scan_time', "Unknown") 
    agent['serial_number'] = getSerialNumber(data.get('id'),'SerialNumber') or "Unknown" 
    agent['hardware_model'] = getModel(data.get('id'),'Model') or "Unknown"
    agent['hardware_vendor'] = getVendor(data.get('id'),'Manufacturer') or "Unknown"
    agent['hostname']  = getHostname(data.get('id'),'Hostname') or "Unknown" 
    agent['username'] = getUsername(data.get('id'),'Username') or "Unknown"
    agent['local_disk'] = getLocalDisk(data.get('id'),'LocalDisk') or  "Unknown"
    agent['id'] = str(int(agent.get('id')))
    #print(agent)
    print(f"{agent['platform']},{agent['hostname']}")
    return agent
   
def getAgentinfo(token,host):
        agents = {}
        headers = {  
                'Authorization': f'Bearer {token}',  
                 'Content-Type': 'application/json'  
                }  
        url = f"{host}/agents/?pretty=true"
    
        try:
        
            response = requests.get(url, headers=headers,verify=False)  
            # check for specific HTTP status codes 
  
            agents_data = response.json()['data']['affected_items']
            print(len(agents_data))
            for agent in agents_data:
                agent_data = parseAgent(host,agent,token)
                print(f"Hey,I got you,{agent_data}")
                 
                saveToDb(agentInfoList(agent_data))

        except Exception as e:
            logging.error(f"An error occured: {e}") 

        return agents 

def authenticate(username,password,host):
        """Authenticate with Wazuh API and return the JWT token."""  
        url = f"{host}/security/user/authenticate"  
        basic_auth = f"{username}:{password}".encode() 
   
        login_headers = {
                       'Content-Type': "Application/json",
                        'Authorization': f'Basic {b64encode(basic_auth).decode()}'
                 }  
        try:
            
            # the program will wait 10 second waiting for response from the server else aborted
            response = requests.post(url, headers=login_headers,verify=False)  
            # Raise an HTTPError for bad response (4xx and 5xx codes) 
            response.raise_for_status
            # check for specific HTTP status codes 

            if response.status_code == 200:  
                token = response.json()['data']['token']
                return token
            
            elif response.status_code == "401":
                logging.error("Invalid username or password")

            else:  
                logging.error("Unexpected status code received: {response.status_code}")

        except HTTPError as http_err:
            # handle HTTP errors (e.g., 4xx or 5xx)
            if response.status_code == 401:
                logging.error("Authentication failed: Invalid username or password.")

            elif response.status_code == 403:
                logging.error("Forbidden: You don't have permission to access this resource") 

            elif response.status_code == 404:
                logging.error("Not Found: The requested resource does not exist")

            else:

                logging.error(f"HTTP error occured: {http_err}") 

        # catch errors when the server is down or unreachable 
        except ConnectionError:
            logging.error(f"Failed to connect to wazuh server: {host}. The server might be down") 

        # handles when the server is to slow or not responding
        except Timeout:
            logging.error("Request to Wazuh server timed out. The server might be too slow or not responding")

        # catche any other request-related errors 
        except RequestException as err:
            logging.error(f"An unexpected error occured: {err}")

        except Exception as e:
            logging.error(f"An error occured: {response}") 

        return None 

def main():
   
    host = f"https://{WAZUH_SERVER_IP}:{WAZUH_SERVER_PORT}" 
    token = authenticate(WAZUH_SERVER_USERNAME,WAZUH_SERVER_PASSWORD,host)
    print("Hello there!")
    if token is None:
         sys.exit(1)
         print("Token is None")
         return 
    agents_data = getAgentinfo(token,host)

   
if __name__== "__main__":

   main()




