import webbrowser
import boto3
import string
import logging
import json
import os
from time import time, sleep
from botocore.exceptions import ClientError

SSO_REGION  = os.environ['SSO_REGION']
AWS_ROLE    = os.environ['AWS_ROLE']
START_URL   = os.environ['START_URL']

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

sh = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
sh.setFormatter(formatter)
logger.addHandler(sh)

# Open browser SSO to prompt user to grant access to script for SSO
def get_sso_access_token():
    session = boto3.Session()
    start_url = START_URL
    sso_oidc = session.client('sso-oidc', region_name=SSO_REGION )
    client_creds = sso_oidc.register_client(
        clientName='aws_account_iterator',
        clientType='public',
    )
    device_authorization = sso_oidc.start_device_authorization(
        clientId = client_creds['clientId'],
        clientSecret = client_creds['clientSecret'],
        startUrl = start_url,
    )

    print(f"Verification code: {device_authorization['userCode']}")

    webbrowser.open(device_authorization['verificationUriComplete'], autoraise=True)
    for n in range(1, device_authorization['expiresIn'] // device_authorization['interval'] + 1):
        sleep(device_authorization['interval'])
        try:
            token = sso_oidc.create_token(
                grantType='urn:ietf:params:oauth:grant-type:device_code',
                deviceCode=device_authorization['deviceCode'],
                clientId=client_creds['clientId'],
                clientSecret=client_creds['clientSecret'],
            )
            break
        except sso_oidc.exceptions.AuthorizationPendingException:
            pass
    access_token = token['accessToken']
    return access_token

# Use access token granted from above to return array of dictionaries containing accountName and accountID
# for each account user has access to through SSO
def get_sso_all_accounts(access_token: string):
    session = boto3.Session()
    sso = session.client('sso', region_name=SSO_REGION)
    all_accounts_info = sso.list_accounts(
        accessToken=access_token,
        maxResults=100
    )['accountList']
    
    account_list = []
    for account in all_accounts_info:
        account_info = {
            'accountName': account['accountName'],
            'accountId': account['accountId'],
        }
        account_list.append(account_info)
    return account_list

# Use account list and access token from above to return array containing account name and access ID/KEY/TOKEN
def get_all_account_credentials(access_token ,account_list):
    session = boto3.Session()
    sso = session.client('sso', region_name=SSO_REGION)
    account_creds = []
    for account in account_list:
        creds = sso.get_role_credentials(
            roleName=AWS_ROLE,
            accountId=account['accountId'],
            accessToken=access_token
        )['roleCredentials']
        new_account = {
            'accountName': account['accountName'],
            'accountId': account['accountId'],
            'credentials' : creds
        }
        account_creds.append(new_account)
    return account_creds


def get_account_credentials(access_token ,accountId):
    session = boto3.Session()
    sso = session.client('sso', region_name=SSO_REGION)

    creds = sso.get_role_credentials(
        roleName=AWS_ROLE,
        accountId=accountId,
        accessToken=access_token
    )['roleCredentials']
    
    return creds

def get_account_roles(access_token, account_id):
    session = boto3.Session()
    sso = session.client('sso', region_name=SSO_REGION)
    response = sso.list_account_roles(
        accessToken=access_token,
        maxResults=50,
        accountId=account_id
    )

    print(response['roleList'])

def get_resources_for_account(account_creds, region):

    session = boto3.Session(aws_access_key_id=account_creds['accessKeyId'],
                            aws_secret_access_key=account_creds['secretAccessKey'],
                            aws_session_token=account_creds['sessionToken'],
                            region_name=region)
    
    # these could be added as params to the get_resources_for_account function
    # so that this was a little more reusable for different resource types
    client_params = {'client':'s3', 'function':'list_buckets', 'function_params':{}, 'resource_key':'Buckets'}
    
    nextToken = ''

    client = session.client(client_params['client'])
    response = getattr(client, client_params['function'])(**client_params['function_params'])
    
    for item in response[client_params['resource_key']]:
        logger.info(f"\t\tItem: {item}")

    return response[client_params['resource_key']]

def get_resources():

    # Can be used to get a list of regions a service is available in
    #s = boto3.Session()
    #regions = s.get_available_regions('ec2')

    # For this example, s3 present in all regions so the output is a little funny but shows how the region iteration works
    regions = ['ap-southeast-2', 'us-east-1']

    access_token = get_sso_access_token()
    account_list = get_sso_all_accounts(access_token)

    logger.info(account_list)

    results = {}

    for account in account_list:
        try:
            logger.info(f"Checking account: {account['accountName']}")
            account_creds = get_account_credentials(access_token, account['accountId'])

            for region in regions:
                logger.info(f"\tChecking region: {region}")
                try:
                    resources = get_resources_for_account(account_creds, region)
                except ClientError as e:
                    logger.warning(f"Region not available: {region} - Error: {e['Error']['Code']} - Desc: {e['Error']['Description']}")


                if len(resources) > 0:
                    resource_data = []
                    for resource in resources:
                        resource_data.append(resource['Name'])
                    results.setdefault(account['accountName'],{})[region] = resource_data

        except ClientError as e:
            logger.warning(f"No credentials available for account: {account['accountId']} - Error: {e['Error']['Code']} - Desc: {e['Error']['Description']}")

    print(json.dumps(results, indent=2))

if __name__ == '__main__':
    get_resources()