import os
import sys
import logging
import datetime
import ConfigParser
import requests

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
logging.basicConfig(filename='LOGS/process_name.log', level=logging.INFO, format=logFormat, datefmt=datefmt)
logger = logging.getLogger(__name__)

# Log when the script was started
logger.info('Started querying at: %s', start)

def end():
    """ Calclate and log the elapsed run time """
    end = datetime.datetime.now()
    logger.info('Ended at: %s', end)
    logger.info('Elapsed time: %s', end-start)

def genOutput(connection):
    """ Generate the ouput of the script
        Writes a CSV with the process name
        Prints basic conneciton info to the console
    """
    # Create CSV if one doesn't exist and write headers
    if not os.path.exists('{}_connectivity.csv'.format(process_name)):
        logger.info('%s_connectivity.csv doesn\'t exist writing it now', process_name)
        with open('{}_connectivity.csv'.format(process_name), 'w') as f:
            f.write('Event Type,Protocol,Source IP,Source Port,Directoin,Destination IP,Destination Port,Hostname,GUID\n')

    # Loop to retry writing the file if it open in Excel and can't
    for attempt in range(3):
        try:
            # Write the connection informaiton to CSV
            with open('{}_connectivity.csv'.format(process_name), 'a') as f:
                f.write('{event_type},{protocol},{local_ip},{local_port},{direction},'
                        '{remote_ip},{remote_port},{hostname},{guid}\n'.format(**connection))
        except IOError as error_message:
            logger.error(error_message)
            if error_message[0] == 13:
                if attempt == 2:
                    logger.error('Failed to open the %s_connectivity.csv 3 times and quit', process_name)
                    end()
                    sys.exit('Failed 3 times.\nExiting.')
                print ' {}'.format(error_message)
                raw_input(' Check if the file is open in Excel.\nPress enter to continue')
        else:
            break

    # Output some of the connection info to the console
    print '  {protocol} {local_ip}:{local_port} {direction} {remote_ip}:{remote_port}'.format(**connection)


def isSHA256Unique(process_name_sha256, file_path, file_name):
    """ Checks if a SHA256 is unique
        Stores the SHA256, Filename, and Filepath globally
        Stores the unique SHA256 for the specific GUID
        The GUID SHA256 is used when reprocessing the trajectory events
    """
    # Store unique process SHA256s and associated file name and file path
    if process_name_sha256 not in file_identities:
        file_identities[process_name_sha256] = {'file_names':[], 'file_paths':[]}
    # Store unique file path
    if file_path not in file_identities[process_name_sha256]['file_paths']:
        file_identities[process_name_sha256]['file_paths'].append(file_path)
    # Store unique file name
    if file_name not in file_identities[process_name_sha256]['file_names']:
        file_identities[process_name_sha256]['file_names'].append(file_name)
    # Store unique process SHA256s in GUID specific container
    if process_name_sha256 not in guid_file_identities:
        guid_file_identities.append(process_name_sha256)

def isRemoteIPUnique(remote_ip, remote_port):
    """ Checks if the Remote IP and Remote Port pair is unique
        Stores the unique Remote IP and all the unique ports it connected on globally
        Stores the unique Remote IP for the specific GUID
        The GUID Remote IP is used when reprocessing the trajectory events
    """
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
logger.info('Queried: %s', r.url)

# Exit if 401 response
if r.status_code // 100 != 2:
    error = r.json()['errors'][0]['details'][0]
    logger.error('Recieved %s - %s', r.status_code, error)
    end()
    sys.exit(error)

# Write JSON to file if log level is set to DEBUG
if logging.getLogger().isEnabledFor(logging.DEBUG):
    with open('activity.json', 'w') as file:
        file.write(r.text)

# Decode JSON response
query = r.json()

# Name data section of JSON
data = query['data']

# Write a warning in the log that the maximum number of hosts has been found for a single query
if len(data) >= 500:
    logger.warning('Querying for %s has returned %s hosts. This is too many and will '
                   'not provide a complete overview of the environment!', process_name, len(data))

# Store unique connector GUIDs
for entry in data:
    if entry['connector_guid'] not in computer_guids:
        connector_guid = entry['connector_guid']
        hostname = entry['hostname']
        computer_guids[connector_guid] = {'hostname':hostname}

# Log number of computers found with process name
logger.info('Computers Found: %s', len(computer_guids))
print 'Computers Found: {}'.format(len(computer_guids))

# Query trajectory for each GUID
for guid in computer_guids:

    # Print the hostname and GUID that is about to be queried
    print 'Processing: {} - {}'.format(computer_guids[guid]['hostname'], guid)

    # Log the GUID and hostname of the computer about to be queried
    logger.info('Proessing: %s - %s', guid, computer_guids[guid]['hostname'])
    url = 'https://api.amp.cisco.com/v1/computers/{}/trajectory'.format(guid)

    # Query trajectory API endpoint for the GUID
    r = s.get(url)

    # Write JSON to file if log level is set to DEBUG
    if logging.getLogger().isEnabledFor(logging.DEBUG):
        with open('trajectory_{}.json'.format(guid), 'w') as file:
            file.write(r.text)

    # Decode JSON response
    query = r.json()

    # GUID specific container for SHA256s and IPs
    guid_file_identities = []
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
            isSHA256Unique(process_name_sha256, file_path, file_name)

        # Parse DFC events for SH256 of the process name
        if event['event_type'] == 'DFC Threat Detected':
            network_info = event['network_info']
            # Verify parent process information exists in the event and it matches the process name
            if 'parent' in network_info and network_info['parent']['file_name'] == process_name:
                file_name = network_info['parent']['file_name']
                file_path = 'N/A'
                process_name_sha256 = network_info['parent']['identity']['sha256']
                # Store unique process SHA256s and associated file name and file path
                isSHA256Unique(process_name_sha256, file_path, file_name)

    # Log the number of SHA256s found in the GUID trajectory
    if len(guid_file_identities) is 1:
        logger.info('GUID: %s - %s had %s SHA256 for %s', guid,
                    computer_guids[guid]['hostname'],
                    len(guid_file_identities),
                    process_name)
    else:
        logger.info('GUID: %s- %s had %s SHA256s for %s', guid,
                    computer_guids[guid]['hostname'],
                    len(guid_file_identities),
                    process_name)

    # Note why the GUID exists in activity but the process couldn't be found in trajectory
    if len(guid_file_identities) is 0:
        logger.info('This means the 500 most recent trajecotry events did not contain %s', process_name)

    # Re-parse trajectory events for network events
    for event in events:
        event_type = event['event_type']
        # Container to store the information about the connection that will be written to file
        connection = {'event_type':'',
                      'protocol':'N/A',
                      'local_ip':'',
                      'local_port':'',
                      'direction':'-',
                      'remote_ip':'',
                      'remote_port':'',
                      'hostname':computer_guids[guid]['hostname'],
                      'guid':guid
                     }

        # Parse NFM (Network Flow Monitor) events
        if event_type == 'NFM':
            network_info = event['network_info']
            # Verify parent process information exists in the event and it matches a SHA256 we care about
            if 'parent' in network_info and network_info['parent']['identity']['sha256'] in guid_file_identities:
                direction = network_info['nfm']['direction']
                connection['event_type'] = 'NFM'
                connection['protocol'] = network_info['nfm']['protocol']
                connection['local_ip'] = network_info['local_ip']
                connection['local_port'] = network_info['local_port']
                connection['remote_ip'] = network_info['remote_ip']
                connection['remote_port'] = network_info['remote_port']

                # Store unique remote IP and port
                isRemoteIPUnique(connection['remote_ip'], connection['remote_port'])

                # Create output for outgoing connection
                if direction == 'Outgoing connection from':
                    connection['direction'] = '->'
                    genOutput(connection)

                # Create output for incoming connection
                if direction == 'Incoming connection from':
                    connection['direction'] = '<-'
                    genOutput(connection)

        # Parse DFC (Device Flow Correlation) events
        if event_type == 'DFC Threat Detected':
            network_info = event['network_info']
            # Verify parent process information exists in the event and it matches a SHA256 we care about
            if 'parent' in network_info and network_info['parent']['identity']['sha256'] in guid_file_identities:
                connection['event_type'] = 'DFC'
                connection['local_ip'] = network_info['local_ip']
                connection['local_port'] = network_info['local_port']
                connection['remote_ip'] = network_info['remote_ip']
                connection['remote_port'] = network_info['remote_port']

                # Store unique remote IP and port
                isRemoteIPUnique(connection['remote_ip'], connection['remote_port'])

                # Create output for communication between two hosts (DFC events do not indicate direction)
                # genOutput(guid, computer_guids[guid]['hostname'], local_ip, local_port, remote_ip, remote_port)
                genOutput(connection)

    # If no remote IPs are found print to conolse
    if len(guid_ips) is 0:
        print '  No communication observed'

    # Log the number of remote IPs the computer has been observed communicating with
    logger.info('GUID: %s - %s has observed %s communicating with %s IPs', guid,
                computer_guids[guid]['hostname'],
                process_name,
                len(guid_ips))

# Output stats related to the query
computer_message = 'Computers with {}: {}'.format(process_name, len(computer_guids))
sha256_message = 'Unique SHA256s for {}: {}'.format(process_name, len(file_identities))
ip_message = 'IPs {} has been observed communicating with: {}'.format(process_name, len(remote_ips))
logger.info(computer_message)
logger.info(sha256_message)
logger.info(ip_message)
print computer_message
print sha256_message
print ip_message

# Calculate and log elapsed time
end()
