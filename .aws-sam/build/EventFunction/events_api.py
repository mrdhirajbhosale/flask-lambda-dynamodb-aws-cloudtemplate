import json
import logging
from enum import Enum
import boto3
from boto3.dynamodb.conditions import Key, And, Attr
from functools import reduce
from flask_lambda import FlaskLambda
from flask import request
from flask_cors import CORS
import event_json_encoder

app = FlaskLambda(__name__)
CORS(app)
ddb = boto3.resource('dynamodb')
table = ddb.Table('Event-dev')
logging.getLogger().setLevel(logging.INFO)
logging.info('Loading event api lambda function')

@app.route('/events', methods=['POST'])
def get_events():
    try:
        logging.info("is even type valid : {}".format(str(request)))
        print(request.headers['UserID'])
        UserID = request.headers['UserID']
        if request.json:
            events = table.query(
                                IndexName='UserID-EventDate-index',
                                KeyConditionExpression= Key("UserID").eq(UserID),
                                Limit=20,
                                ScanIndexForward=False,
                                ExclusiveStartKey=request.json['LastEvaluatedKey']
                            )
            lastEvaluatedKey = events['LastEvaluatedKey']
            events = json.loads(json.dumps(events['Items'], cls=event_json_encoder.EventJSONEncoder))
            response = ResponseCodes.SUCCESS.value
            response['count'] = table.scan(FilterExpression=Key('UserID').eq(UserID))['Count']
            response['data'] = events
            response['LastEvaluatedKey'] = lastEvaluatedKey 
            return json_response(response)
        else:
            events = table.query(
                                IndexName='UserID-EventDate-index',
                                KeyConditionExpression= Key("UserID").eq(UserID),
                                Limit=20,
                                ScanIndexForward=False
                            )
            if events:
                print(events['LastEvaluatedKey'])
                lastEvaluatedKey = events['LastEvaluatedKey']
                events = json.loads(json.dumps(events['Items'], cls=event_json_encoder.EventJSONEncoder))
                response = ResponseCodes.SUCCESS.value
                response['data'] = events
                response['count'] = table.scan(FilterExpression=Key('UserID').eq(UserID))['Count']
                response['LastEvaluatedKey'] = lastEvaluatedKey
                return json_response(response)
            else:
               return json_response(ResponseCodes.EVENT_NOT_FOUND.value)
    except Exception as e:
        logging.error(e)
        return json_response(ResponseCodes.FAIL.value)

@app.route('/events', methods=['PUT'])
def put_event():
    try:
        UserID = request.headers['UserID']
        if request.json  and 'LastEvaluatedKey' in request.json.keys():
            logging.info("is even type valid : {}".format(str(request)))
            logging.getLogger().setLevel(logging.INFO)
            event = request.json
            event['UserID'] = UserID
            table.put_item(Item=event)
            return json_response(ResponseCodes.SUCCESS_PUT_EVENT.value)
        else:
            return json_response(ResponseCodes.EMPTY_PAYLOAD.value)
    except Exception as e:
        logging.error(e)
        return json_response(ResponseCodes.FAIL.value)

@app.route('/events/<id>', methods=['GET'])
def get_event(id):
    try:
        UserID = request.headers['UserID']
        logging.info("is even type valid : {}".format(str(request)))
        key = {'EventID': id}
        event = json.loads(json.dumps(table.get_item(Key=key).get('Item'), cls=event_json_encoder.EventJSONEncoder))
        if event:
            response = ResponseCodes.SUCCESS.value
            response['data'] = event
            return json_response(response)
        else:
            return json_response(ResponseCodes.EVENT_NOT_FOUND.value)
    except Exception as e:
        logging.error(e)
        return json_response(ResponseCodes.FAIL.value)

@app.route('/events/<id>', methods=['PATCH'])
def patch_event(id):
    try:
        UserID = request.headers['UserID']
        if request.json:
            logging.info("is even type valid : {}".format(str(request)))
            key = {'EventID': id}
            attribute_updates = {key: {'Value': value, 'Action': 'PUT'} for key, value in request.json.items()}
            table.update_item(Key=key, AttributeUpdates=attribute_updates)
            return json_response(ResponseCodes.SUCCESS_UPDATE_EVENT.value)
        else:
            return json_response(ResponseCodes.EMPTY_PAYLOAD.value)
    except Exception as e:
        logging.error(e)
        return json_response(ResponseCodes.FAIL.value)

@app.route('/events/<id>', methods=[ 'DELETE'])
def delete_event(id):
    try:
        UserID = request.headers['UserID']
        logging.info("is even type valid : {}".format(str(request)))
        key = {'EventID': id}
        table.delete_item(Key=key)
        return json_response(ResponseCodes.SUCCESS_DELETE_EVENT.value)
    except Exception as e:
        logging.error(e)
        return json_response(ResponseCodes.FAIL.value)

@app.route('/events/search', methods=['POST'])
def search_events():
    try:
        logging.info("is even type valid : {}".format(str(request)))
        UserID = request.headers['UserID']
        if request.json and 'LastEvaluatedKey' not in request.json.keys():
            filters = request.json
            response = ResponseCodes.SUCCESS.value
            events = table.query( IndexName= 'UserID-EventDate-index',
                                  KeyConditionExpression= Key("UserID").eq(UserID),
                                  FilterExpression = request.json('FilterExpression'),
                                  ExpressionAttributeNames= request.json('ExpressionAttributeNames'),
                                  ExpressionAttributeValues= request.json('ExpressionAttributeValues'),
                                  Limit=20,
                                  ScanIndexForward= False
                                )
            response['data'] = json.loads(json.dumps(events['Items'], cls=event_json_encoder.EventJSONEncoder))
            filters['UserID'] = UserID
            response['LastEvaluatedKey'] = events['LastEvaluatedKey']
            if events:
                return json_response(response)
            else:
                return json_response(ResponseCodes.EVENT_NOT_FOUND.value)
        if request.json and 'LastEvaluatedKey' in request.json.keys():
            lastEvaluatedKey = request.json.pop('LastEvaluatedKey')
            filters = request.json
            response = ResponseCodes.SUCCESS.value
            events = table.query( IndexName='UserID-EventDate-index',
                                  KeyConditionExpression= Key("UserID").eq(UserID),
                                  Limit=20,
                                  FilterExpression = request.json('FilterExpression'),
                                  ExpressionAttributeNames= request.json('ExpressionAttributeNames'),
                                  ExpressionAttributeValues= request.json('ExpressionAttributeValues'),
                                  ScanIndexForward=False,
                                  ExclusiveStartKey=lastEvaluatedKey
                                )
            filters['UserID'] = UserID
            response['data'] = json.loads(json.dumps(events['Items'], cls=event_json_encoder.EventJSONEncoder))
            response['LastEvaluatedKey'] = events['LastEvaluatedKey']
            if events:
                return json_response(response)
            else:
                return json_response(ResponseCodes.EVENT_NOT_FOUND.value)
        else:
            return json_response(ResponseCodes.EMPTY_PAYLOAD.value)
    except Exception as e:
        logging.error(e)
        return json_response(ResponseCodes.FAIL.value)

def json_response(data, response_code=200):
    return json.dumps(data), response_code

class ResponseCodes(Enum):
    SUCCESS = {"code": "10000", "message": "Success"}
    SUCCESS_PUT_EVENT = {"code": "10000", "message": "Event created successfully"}
    SUCCESS_DELETE_EVENT = {"code": "10000", "message": "Event deleted successfully"}
    SUCCESS_UPDATE_EVENT = {"code": "10000", "message": "Event updated successfully"}
    FAIL = {"code": "10100", "message": "Fail"}
    EMPTY_PAYLOAD = {"code": "10102", "message": "Empty payload"}
    EVENT_NOT_FOUND = {"code": "10400", "message": "Event not found"}
