import os
import json
from weakref import ref
import boto3
import logging
import requests
import datetime
from boto3.dynamodb.conditions import Key

# set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# set up AWS resources
session = boto3.Session()
s3 = session.resource('s3')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('etsy-oauth')
BASE_URL = 'https://api.etsy.com/v3/application'

class etsy():
    def __init__(self, api_keystring='', access_token='', refresh_token='', shop_id='', user_id=''):
        '''
        Initialize Etsy object.
        '''
        self.api_keystring = api_keystring
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.shop_id = shop_id
        self.user_id = user_id
        self.oauth_url = 'https://api.etsy.com/v3/public/oauth/token'
        self.base_url = 'https://api.etsy.com/v3/application'
        self.headers = {
            'x-api-key': self.api_keystring,
            'Authorization' : f'Bearer {self.access_token}'
        }

    def _http_req(self, method, suffix, body=None):
        '''
        Execute HTTP API requests for Etsy REST API.
        '''
        resp = requests.request(
            method=method,
            url=self.base_url + suffix,
            headers=self.headers,
            data=json.dumps(body)
        )
        
        logger.info(f'STATUS_CODE:{resp.status_code} | URL:{self.base_url + suffix}')
        
        if resp.status_code == 401 and resp.json().get('error') == 'invalid_token':
            self._refresh_token()
            logger.info('Retrying API call after Token Refresh...')
            resp = requests.request(
                method=method,
                url=self.base_url + suffix,
                headers=self.headers,
                data=json.dumps(body)
            )

        if resp.status_code == 200: 
            return resp.json() 
        else:
            raise ConnectionError(
                "Could Not Connect. Status Code: {0}".format(resp.status_code)
            )

    def _refresh_token(self):
        '''
        Update Etsy Oauth tokens after epiration.
        '''
        logger.info('NEW METHOD | Attempting to update Access and Refresh tokens...')
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'grant_type': 'refresh_token',
            'client_id': self.api_keystring,
            'refresh_token': self.refresh_token
        }
        resp = requests.post(self.oauth_url, headers=headers, data=data)
        if resp.status_code == 200:
            logger.info('NEW METHOD | Sucessfully updated Access and Refresh tokens...')
            self.set_access_token(resp.json().get('access_token'))
            self.set_refresh_token(resp.json().get('refresh_token'))
            self.set_headers()
        
    def set_access_token(self, access_token):
        '''
        Update Access Token.
        '''
        self.access_token = access_token
    
    def set_refresh_token(self, refresh_token):
        '''
        Update Refresh Token.
        '''
        self.refresh_token = refresh_token

    def set_headers(self):
        '''
        Update HTTP Headers.
        '''
        self.headers = {
            'x-api-key': self.api_keystring,
            'Authorization' : f'Bearer {self.access_token}'
        }
    
    def get_access_token(self):
        '''
        Retrieve Access Token.
        '''
        return self.access_token

    def get_refresh_token(self):
        '''
        Retrieve Refresh Token.
        '''
        return self.refresh_token

    def get_shop_trans(self):
        '''
        Retrieve Etsy shop transactions.
        '''
        logger.info('NEW METHOD | Retrieving shop transactions...')
        path = f'/shops/{self.shop_id}/transactions'
        resp = self._http_req('GET', path)
        return resp



def db_table_query(query_key):
    '''
    Query table for current key info.
    '''
    response = table.query(KeyConditionExpression=Key('oauth_key_type').eq(query_key))
    token = response['Items'][0].get('oauth_key_value')
    return token

# set contants 
def update_constants():
    '''
    Update and set global constants from DynamoDB.
    '''
    global BUCKET, API_KEYSTRING, SHOP_ID, USER_ID, ETSY_ACCESS_TOKEN, ETSY_REFRESH_TOKEN
    BUCKET = db_table_query('ETSY_BUCKET')
    API_KEYSTRING = db_table_query('ETSY_API_KEYSTRING')
    SHOP_ID = db_table_query('ETSY_SHOP_ID')
    USER_ID = db_table_query('ETSY_USER_ID')
    ETSY_ACCESS_TOKEN = db_table_query('ETSY_ACCESS_TOKEN')
    ETSY_REFRESH_TOKEN = db_table_query('ETSY_REFRESH_TOKEN')


def db_table_query(query_key):
    '''
    Query table for current key info.
    '''
    response = table.query(KeyConditionExpression=Key('oauth_key_type').eq(query_key))
    token = response['Items'][0].get('oauth_key_value')
    return token


def db_update_table(update_key_valu, update_key_type):
    '''
    Update table with new key info.
    '''
    logger.info(f'Updating {update_key_type}...')
    table.put_item(Item={'oauth_key_value': update_key_valu, 'oauth_key_type': update_key_type})


def refresh_token():
    '''
    Update Etsy Oauth tokens after epiration.
    '''
    timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    url = 'https://api.etsy.com/v3/public/oauth/token'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'refresh_token',
        'client_id': API_KEYSTRING,
        'refresh_token': ETSY_REFRESH_TOKEN
    }
    logger.info('OLD METHOD | Refreshing token...')
    resp = requests.post(url, headers=headers, data=data)
    if resp.status_code == 200:
        new_access_token = resp.json().get('access_token')
        new_refresh_token = resp.json().get('refresh_token')
        db_update_table(new_access_token, 'ETSY_ACCESS_TOKEN')
        db_update_table(new_refresh_token, 'ETSY_REFRESH_TOKEN')
        db_update_table(timestamp, 'ETSY_LAST_UPDATED')
        update_constants()
        return True
    else:
        return False


def get_shop_trans():
    '''
    Query for recent Etsy transactions. 
    '''
    # set up url and request
    url = BASE_URL + f'/shops/{SHOP_ID}/transactions'
    headers = {
        'x-api-key': API_KEYSTRING,
        'Authorization' : f'Bearer {ETSY_ACCESS_TOKEN}'
    }
    logger.info('OLD METHOD | Retrieving shop transactions...')
    resp = requests.get(url, headers=headers)

    # if resp requires new token
    if resp.status_code == 401 and resp.json().get('error') == 'invalid_token':
        if refresh_token():
            # re-fetch after getting new token
            headers = {
                'x-api-key': API_KEYSTRING,
                'Authorization' : f'Bearer {ETSY_ACCESS_TOKEN}'
            }
            resp = requests.get(url, headers=headers)
    
    # if no errors, return latest transactions
    if resp.status_code == 200:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        obj = s3.Object(BUCKET, 'etsy/' + f'etsy_trans_{timestamp}.json')
        obj.put(Body=json.dumps(resp.json(), indent=4))
        return resp.json()
    else:
        return {}

def process_trans(trans):
    '''
    Process latest transactions and compare against last queried.
    '''
    if not trans:
        return []
    
    new_trans = []
    for tran in trans:
        # get last queried time and then update it with now()
        timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        queried_timestamp = db_table_query('ETSY_LAST_QUERIED')
        table.put_item(Item={'oauth_key_value': timestamp, 'oauth_key_type': 'ETSY_LAST_QUERIED'})
        
        # process timestamps
        paid_time = datetime.datetime.fromtimestamp(tran.get('paid_timestamp'))
        queried_time = datetime.datetime.strptime(queried_timestamp, '%Y-%m-%dT%H:%M:%S')
        
        # new order not caught with previous query
        if paid_time > queried_time:
            obj = s3.Object(BUCKET, 'etsy/' + f'etsy_trans_{timestamp}.json')
            obj.put(Body=json.dumps(tran, indent=4))
        
        new_trans.append(tran)
    return new_trans

def handler(event, context):
    '''
    Routine polling Etsy for new orders while maintaining Oauth API keys in DynamoDB table.
    '''

    # OLD METHOD | Retrieve Latest Etsy Update
    update_constants()
    # trans = get_shop_trans()
    # process_trans(trans.get('results', []))

    # NEW METHOD | Retrieve Latest Etsy Update
    etsy_api = etsy(
        api_keystring=API_KEYSTRING,
        access_token=ETSY_ACCESS_TOKEN,
        refresh_token=ETSY_REFRESH_TOKEN,
        shop_id=SHOP_ID,
        user_id=USER_ID
    )
    trans2 = etsy_api.get_shop_trans()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    db_update_table(etsy_api.get_access_token(), 'ETSY_ACCESS_TOKEN')
    db_update_table(etsy_api.get_refresh_token(), 'ETSY_REFRESH_TOKEN')
    db_update_table(timestamp, 'ETSY_LAST_UPDATED')
    obj = s3.Object(BUCKET, 'etsy/' + f'etsy_new_trans_{timestamp}.json')
    obj.put(Body=json.dumps(trans2, indent=4))
