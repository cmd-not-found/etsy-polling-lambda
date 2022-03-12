import os
import json
import boto3
import requests
import datetime
from boto3.dynamodb.conditions import Key

# set up AWS resources
session = boto3.Session()
s3 = session.resource('s3')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('etsy-oauth')

def db_table_query(query_key):
    '''
    Query table for current key info.
    '''
    response = table.query(KeyConditionExpression=Key('oauth_key_type').eq(query_key))
    token = response['Items'][0].get('oauth_key_value')
    return token

# set contants 
def update_constants():
    global BUCKET, API_KEYSTRING, BASE_URL, SHOP_ID, USER_ID, ETSY_ACCESS_TOKEN, ETSY_REFRESH_TOKEN
    BUCKET = db_table_query('ETSY_BUCKET')
    API_KEYSTRING = db_table_query('ETSY_API_KEYSTRING')
    BASE_URL = 'https://api.etsy.com/v3/application'
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
    resp = requests.get(url, headers=headers)

    # if resp requires new token
    if resp.status_code == 401 and resp.json().get('error') == 'invalid_token':
        if refresh_token():
            # re-fetch after getting new token
            resp = requests.get(url, headers=headers)
    
    # if no errors, return latest transactions
    if resp.status_code == 200:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        obj = s3.Object('etsy/' + os.environ.get('BUCKET'), f'etsy_trans_{timestamp}.json')
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
            obj = s3.Object('etsy/' + os.environ.get('BUCKET'), f'etsy_trans_{timestamp}.json')
            obj.put(Body=json.dumps(tran, indent=4))
        
        new_trans.append(tran)
    return new_trans

def handler(event, context):
    '''
    Routine polling Etsy for new orders while maintaining Oauth API keys in DynamoDB table.
    '''

    # Retrieve Latest Etsy Update
    update_constants()
    trans = get_shop_trans()
    process_trans(trans.get('results', []))
    # Query Etsy for Orders
    # add receipt to S3 bucket
    # timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    # obj = s3.Object('etsy/' + os.environ.get('BUCKET'), f'etsy_receipt_{timestamp}.json')
    # res = obj.put(Body=json.dumps(data, indent=4))
