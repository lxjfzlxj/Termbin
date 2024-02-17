from flask import Flask, request, jsonify, make_response
from flask_restful import Resource, Api
from datetime import datetime
import hashlib
import uuid

app = Flask(__name__)
api = Api(app)
name = 'http://127.0.0.1:18080'
    
data = {}

def get_char(num):
    if num < 26:
        return chr(ord('A') + num)
    elif num < 52:
        return chr(ord('a') + num - 26)
    else:
        return chr(ord('0') + num - 52)

def get_short(id):
    short = ""
    num = 0
    mod = 62 ** 4
    for c in id:
        if str.isdigit(c):
            num = (num * 16 + int(c)) % mod
        else:
            num = (num * 16 + ord(c) - ord('a') + 10) % mod
    for i in range(4):
        short += get_char(num % 62)
        num //= 62
    return short

class CreateResource(Resource):
    def post(self):
        bytes = request.files['c'].read()
        print('[Debug]Create a new clipboard, content: %s' % bytes.decode())
        md5 = hashlib.md5()
        md5.update(bytes)
        id = str(uuid.uuid4())
        short = get_short(id)
        data[id] = dict(date = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f %Z'), digest = md5.hexdigest(), short = short, size = len(bytes), url = name + '/' + short, status = 'created', uuid = id, content = bytes.decode())
        return make_response('''
date: %s
digest: %s
short: %s
size: %d
url: %s
status: %s
uuid: %s
'''
% (data[id]['date'], data[id]['digest'], data[id]['short'], data[id]['size'], data[id]['url'], data[id]['status'], data[id]['uuid']), 200)
        
class RUDResource(Resource):
    def delete(self, id):
        if not id in data:
            response = make_response('Failed: Cannot find the UUID\n', 404)
        else:
            response = make_response('deleted %s\n' % id, 200)
            del data[id]
        return response
    
    def put(self, id):
        if not id in data:
            response = make_response('Failed: Cannot find the UUID\n', 404)
        else:
            response = make_response('%s updated\n' % data[id]['url'], 200)
            bytes = request.files['c'].read()
            print('[Debug]Update the clipboard, content: %s' % bytes.decode())
            md5 = hashlib.md5()
            md5.update(bytes)
            data[id]['content'] = bytes.decode()
            data[id]['digest'] = md5.hexdigest()
        return response
    
    def get(self, id):
        if not id in data:
            response = make_response('Failed: Cannot find the UUID\n', 404)
        else:
            response = make_response(data[id]['content'], 200)
        return response
            
api.add_resource(CreateResource, '/')
api.add_resource(RUDResource, '/<id>')