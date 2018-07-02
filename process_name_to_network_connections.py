import os
import sys
import logging
import requests
import datetime
import ConfigParser

# Note date and time when envoked
start = datetime.datetime.now()

# Force UTF-8 Encoding
reload(sys)
sys.setdefaultencoding('utf-8')

# If LOGS directory doesn't exist, create it
if not os.path.exists('LOGS'):
    os.makedirs('LOGS')

# Configure logging
logFormat = '%(asctime)s: %(levelname)s: %(name)s: %(message)s'
datefmt = '%Y-%m-%d %H:%M:%S'
logging.basicConfig(filename='LOGS/process_name.log',level=logging.INFO,format=logFormat,datefmt=datefmt)
logger = logging.getLogger(__name__)

# Log when the script was started
logger.info('Started querying at: {}'.format(start))

def end ():
    end = datetime.datetime.now()
    logger.info('Ended at: {}'.format(end))
    logger.info('Elapsed time: {}'.format(end-start))

def genOutput(guid,hostname,local_ip,local_port,remote_ip,remote_port,protocol='N/A',direction='-'):
    # Create CSV if one doesn't exist and write headers
    if not os.path.exists('{}_connectivity.csv'.format(process_name)):
        logger.info('{}_connectivity.csv doesn\'t exist writing it now'.format(process_name))
        with open('{}_connectivity.csv'.format(process_name),'w') as f:
            f.write('Protocol,Source IP,Source Port,Directoin,Destination IP,Destination Port,Hostname,GUID\n')

    # Write the connection informaiton to CSV
    with open('{}_connectivity.csv'.format(process_name),'a') as f:
        f.write('{},{},{},{},{},{},{},{}\n'.format(protocol,local_ip,local_port,direction,remote_ip,remote_port,hostname,guid))

    # Message format for the console
    message = '  {} {}:{} {} {}:{}'

    # Print the message to the console
    print message.format(protocol,local_ip,local_port,direction,remote_ip,remote_port)

def isSHA256Unique(process_name_sha256,file_path,file_name):
    # Store unique process SHA256s and associated file name and file path
    if process_name_sha256 not in file_identities:
        file_identities[process_name_sha256] = {'file_names':[],'file_paths':[]}
    # Store unique file path
    if file_path not in file_identities[process_name_sha256]['file_paths']:
        file_identities[process_name_sha256]['file_paths'].append(file_path)
    # Store unique file name
    if file_name not in file_identities[process_name_sha256]['file_names']:
        file_identities[process_name_sha256]['file_names'].append(file_name)
    # Store unique process SHA256s in GUID specific container
    if process_name_sha256 not in guid_file_identities:
        guid_file_identities.append(process_name_sha256)

def isRemoteIPUnique(remote_ip,remote_port):
    # Store unique remote IP and create structure to store ports
    if remote_ip not in remote_ips:
        remote_ips[remote_ip] = {'ports':[]}
    # Store unique remote port 
    if remote_port not in remote_ips[remote_ip]['ports']:
        remote_ips[remote_ip]['ports'].append(remote_port)
    # Store unique remote IP for GUID
    if remote_ip not in guid_ips:
        guid_ips.append(remote_ip)

# Specify the config file
configFile = 'api.cfg'

# Read the config file to get settings
config = ConfigParser.RawConfigParser()
config.read(configFile)

client_id = config.get('AMPE', 'client_id')
client_id = str.rstrip(client_id)

api_key = config.get('AMPE', 'api_key')
api_key = str.rstrip(api_key)

# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage:\n %s powershell.exe' % sys.argv[0])

# Store the command line parameter
process_name = sys.argv[1]

# Global containers for output
computer_guids = {}
remote_ips = {}
file_identities = {}

# Creat session object
s = requests.Session()
s.auth = (client_id, api_key)

# Define URL and parameters
url = 'https://api.amp.cisco.com/v1/computers/activity'
q = process_name
payload = {'q': q}

# Query activity API endpoint
r = s.get(url, params=payload)

# Log the URL being queried
logger.info('Querying: {}'.format(r.url))

# Write JSON to file if log level is set to DEBUG
if logging.getLogger().isEnabledFor(logging.DEBUG):
    with open('activity.json','w') as f:
        f.write(r.text)

# Decode JSON response
query = r.json()

# Name data section of JSON
data = query['data']

# Store unique connector GUIDs
for entry in data:
    if entry['connector_guid'] not in computer_guids:
        connector_guid = entry['connector_guid']
        hostname = entry['hostname']
        computer_guids[connector_guid] = {'hostname':hostname}

# Log number of computers found with process name
logger.info('Computers Found: {}'.format(len(computer_guids)))
print 'Computers Found: {}'.format(len(computer_guids))

# Query trajectory for each GUID
for guid in computer_guids:

    # Print the hostname and GUID that is about to be queried
    print 'Processing: {} - {}'.format(computer_guids[guid]['hostname'],guid)

    # Log the GUID and hostname of the computer about to be queried
    logger.info('Proessing: {} - {}'.format(guid,computer_guids[guid]['hostname']))
    url = 'https://api.amp.cisco.com/v1/computers/{}/trajectory'.format(guid)
    
    # Query trajectory API endpoint for the GUID
    r = s.get(url)

    # Write JSON to file if log level is set to DEBUG
    if logging.getLogger().isEnabledFor(logging.DEBUG):
        with open('trajectory_{}.json'.format(guid),'w') as f:
            f.write(r.text)

    # Decode JSON response
    query = r.json()

    # GUID specific container for SHA256s
    guid_file_identities = []

    # GUID specific container for IPs
    guid_ips = []

    # Name events section of JSON
    events = query['data']['events']

    # Parse trajectory events to find the SHA256 of the process name
    for event in events:
        # Verify file and file name information exists in the event and it matches the process name
        if 'file' in event and 'file_name' in event['file'] and event['file']['file_name'] == process_name:
            file_name = event['file']['file_name']
            file_path = event['file']['file_path']
            process_name_sha256 = event['file']['identity']['sha256']
            # Store unique process SHA256s and associated file name and file path
            isSHA256Unique(process_name_sha256,file_path,file_name)

        # Parse DFC events for SH256 of the process name
        if event['event_type'] == 'DFC Threat Detected':
            network_info = event['network_info']
            # Verify parent process information exists in the event and it matches the process name
            if 'parent' in network_info and network_info['parent']['file_name'] == process_name:
                file_name = network_info['parent']['file_name']
                file_path = 'N/A'
                process_name_sha256 = network_info['parent']['identity']['sha256']
                # Store unique process SHA256s and associated file name and file path
                isSHA256Unique(process_name_sha256,file_path,file_name)

    # Log the number of SHA256s found in the GUID trajectory
    if len(guid_file_identities) is 1:
        logger.info('GUID: {} - {} had {} SHA256 for {}'.format(guid,
                                                               computer_guids[guid]['hostname'],
                                                               len(guid_file_identities),
                                                               process_name))
    else:
        logger.info('GUID: {} - {} had {} SHA256s for {}'.format(guid,
                                                                computer_guids[guid]['hostname'],
                                                                len(guid_file_identities),
                                                                process_name))

    # Note why the GUID exists in activity but the process couldn't be found in trajectory
    if len(guid_file_identities) is 0:
        logger.info('This means the 500 most recent trajecotry events did not contain {}'.format(process_name))

    # Re-parse trajectory events for network events
    for event in events:
        event_type = event['event_type']

        # Parse NFM (Network Flow Monitor) events
        if event_type == 'NFM':
            network_info = event['network_info']
            # Verify parent process information exists in the event and it matches a SHA256 we care about
            if 'parent' in network_info and network_info['parent']['identity']['sha256'] in guid_file_identities:
                local_ip = network_info['local_ip']
                local_port = network_info['local_port']
                remote_ip = network_info['remote_ip']
                remote_port = network_info['remote_port']
                direction = network_info['nfm']['direction']
                protocol = network_info['nfm']['protocol']

                # Store unique remote IP and create structure to store remote port
                isRemoteIPUnique(remote_ip,remote_port)

                # Create output for outgoing connection
                if direction == 'Outgoing connection from':
                    genOutput(guid,computer_guids[guid]['hostname'],local_ip,local_port,remote_ip,remote_port,protocol,'->')
                # Create output for incoming connection
                if direction == 'Incoming connection from':
                    genOutput(guid,computer_guids[guid]['hostname'],local_ip,local_port,remote_ip,remote_port,protocol,'<-')

        # Parse DFC (Device Flow Correlation) events
        if event_type == 'DFC Threat Detected':
            network_info = event['network_info']
            # Verify parent process information exists in the event and it matches a SHA256 we care about
            if 'parent' in network_info and network_info['parent']['identity']['sha256'] in guid_file_identities:
                local_ip = network_info['local_ip']
                local_port = network_info['local_port']
                remote_ip = network_info['remote_ip']
                remote_port = network_info['remote_port']
                sha256 = network_info['parent']['identity']['sha256']

                # Store unique remote IP and create structure to store remote port
                isRemoteIPUnique(remote_ip,remote_port)

                # Create output for communication between two hosts (DFC events do not indicate direction)
                genOutput(guid,computer_guids[guid]['hostname'],local_ip,local_port,remote_ip,remote_port)
    
    # If no remote IPs are found print to conolse
    if len(guid_ips) is 0:
        print '  No communication observed'

    # Log the number of remote IPs the computer has been observed communicating with
    logger.info('GUID: {} - {} has observed {} communicate with {} IPs'.format(guid,
                                                                               computer_guids[guid]['hostname'],
                                                                               process_name,
                                                                               len(guid_ips)))

# Output stats related to the query
computer_message = 'Computers with {}: {}'.format(process_name,len(computer_guids))
sha256_message = 'Unique SHA256s for {}: {}'.format(process_name,len(file_identities))
ip_message = 'IPs {} has been observed communicating with: {}'.format(process_name,len(remote_ips))
logger.info(computer_message)
logger.info(sha256_message)
logger.info(ip_message)
print computer_message
print sha256_message
print ip_message

# Calculate and log elapsed time
end()