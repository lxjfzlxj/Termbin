from flask import Flask, request, jsonify, make_response
from flask_restful import Resource, Api
from datetime import datetime
import hashlib
import uuid
from models import add, Clipboard, AuthorStatus, get_session

app = Flask(__name__)
api = Api(app)
name = 'http://127.0.0.1:18080'


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
        with get_session() as session:
            bytes = request.files['c'].read()
            print('[Debug] Create a new clipboard, content: %s' % bytes.decode())
            md5 = hashlib.md5()
            md5.update(bytes)
            id = str(uuid.uuid4())
            short = get_short(id)
            new_board = Clipboard(date = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f %Z'), digest = md5.hexdigest(), short = short, size = len(bytes), url = name + '/' + short, uuid = id, content = bytes.decode(), status = AuthorStatus.all)
            try:
                session.add(new_board)
                session.commit()
            except BaseException as e:
                print('[Error] %s' % e)
                status = 'failed'
            else:
                status = 'created'
            return make_response('''
date: %s
digest: %s
short: %s
size: %d
url: %s
status: %s
uuid: %s
''' % (new_board.date, new_board.digest, new_board.short, new_board.size, new_board.url, status, new_board.uuid), 200 if status == 'created' else 403)
        
class RUDResource(Resource):
    def delete(self, id):
        with get_session() as session:
            board = session.query(Clipboard).filter_by(**dict(uuid = id)).first()
            if board is None:
                response = make_response('Failed: Cannot find the UUID\n', 404)
            else:
                response = make_response('deleted %s\n' % id, 200)
                session.delete(board)
                session.commit()
            return response
    
    def put(self, id):
        with get_session() as session:
            board = session.query(Clipboard).filter_by(**dict(uuid = id)).first()
            if board is None:
                response = make_response('Failed: Cannot find the UUID\n', 404)
            else:
                response = make_response('%s updated\n' % board.url, 200)
                bytes = request.files['c'].read()
                print('[Debug]Update the clipboard, content: %s' % bytes.decode())
                md5 = hashlib.md5()
                md5.update(bytes)
                board.content = bytes.decode()
                board.digest = md5.hexdigest()
                session.commit()
            return response
    
    def get(self, id):
        with get_session() as session:
            board = session.query(Clipboard).filter_by(**dict(uuid = id)).first()
            if board is None:
                response = make_response('Failed: Cannot find the UUID\n', 404)
            else:
                response = make_response(board.content, 200)
            return response
          
api.add_resource(CreateResource, '/')
api.add_resource(RUDResource, '/<id>')