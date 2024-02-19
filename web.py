import flask
from flask import Flask, request, make_response
from flask_restful import Resource, Api
from datetime import datetime, timedelta
import hashlib
import uuid
from models import Clipboard, Visibility, get_session, User
import os
import base64
import hmac


app = Flask(__name__)
api = Api(app)
name = 'http://127.0.0.1:5000'
app.secret_key = os.urandom(50)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days = 1)
salt = b'!@#$%^&*()'


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
    # def get(self):
    #     u = session.get('user')
    #     if u:
    #         print('success')
    #     else:
    #         session['user'] = '1'
    #         print('login')
            
    def post(self):
        username = flask.session.get('username')
        with get_session() as session:
            bytes = request.files['c'].read()
            print('[Log] Create a new clipboard, content: %s' % bytes.decode())
            md5 = hashlib.md5()
            md5.update(bytes)
            id = str(uuid.uuid4())
            short = get_short(id)
            board_dict = dict(date = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f %Z'), digest = md5.hexdigest(), short = short, size = len(bytes), url = name + '/' + short, uuid = id, content = bytes.decode(), visibility = Visibility.all)
            if username is not None:
                board_dict['author'] = username
            new_board = Clipboard(**board_dict)
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
        username = flask.session.get('username')
        with get_session() as session:
            board = session.query(Clipboard).filter_by(**dict(uuid = id)).first()
            if board is None:
                response = make_response('Failed: Cannot find the UUID\n', 404)
            else:
                if board.author is not None and username != board.author:
                    return make_response('Failed: no permission to update\n', 403)
                response = make_response('deleted %s\n' % id, 200)
                session.delete(board)
                session.commit()
            return response
    
    def put(self, id):
        username = flask.session.get('username')
        with get_session() as session:
            board = session.query(Clipboard).filter_by(**dict(uuid = id)).first()
            if board is None:
                response = make_response('Failed: Cannot find the UUID\n', 404)
            else:
                if board.author is not None and username != board.author:
                    return make_response('Failed: no permission to update\n', 403)
                response = make_response('%s updated\n' % board.url, 200)
                bytes = request.files['c'].read()
                print('[Log] Update the clipboard, content: %s' % bytes.decode())
                md5 = hashlib.md5()
                md5.update(bytes)
                board.content = bytes.decode()
                board.digest = md5.hexdigest()
                session.commit()
            return response
    
    def get(self, id):
        username = flask.session.get('username')
        with get_session() as session:
            board = session.query(Clipboard).filter_by(**dict(uuid = id)).first()
            if board is None:
                response = make_response('Failed: Cannot find the UUID\n', 404)
            else:
                if board.visibility == Visibility.author_only and username != board.author or board.visibility == Visibility.someone_only and username != board.author and username != board.someone:
                    return make_response('Failed: no permission to view the clipboard\n', 403)
                response = make_response(board.content, 200)
            return response


class BoardVisibilityResource(Resource):
    def put(self, id):
        username = flask.session.get('username')
        with get_session() as session:
            board = session.query(Clipboard).filter_by(**dict(uuid = id)).first()
            if board is None:
                return make_response('Failed: Cannot find the UUID\n', 404)
            if board.author is not None and username != board.author:
                return make_response('Failed: no permission to update\n', 403)
            new_status = request.form.get('status')
            print(new_status)
            if getattr(Visibility, str(new_status), None) is None:
                return make_response('Failed: invalid visibility format\n', 403)
            if new_status == 'someone_only':
                someone = request.form.get('someone')
                if someone is None:
                    return make_response('Failed: someone not found\n', 403)
                board.someone = someone
            else:
                board.someone = None
            board.visibility = Visibility[new_status]
            session.commit()
            return make_response('the visibility of %s updated: %s\n' % (board.url, board.visibility.name), 200)

            
class UserResource(Resource):
    def post(self):
        header = request.headers.get('Authorization')
        if not (header and header.startswith('Basic')):
            return make_response('Failed: username and password not found\n', 403)
        b64 = header.replace('Basic ', '', 1)
        up = base64.b64decode(b64).decode()
        username, password = up.split(':', 1)
        if len(username) == 0 or len(password) == 0:
            return make_response('Failed: username or password cannot be empty\n', 403)
        print('[Log] Register: username = %s password = %s' % (username, password))
        with get_session() as session:
            cnt = session.query(User).filter_by(username = username).count()
            if cnt > 0:
                return make_response('Failed: The username already exists\n', 403)
            password = hmac.new(salt, password.encode(), digestmod = 'SHA1').hexdigest()
            new_user = User(username = username, password = password)
            session.add(new_user)
            session.commit()
        return make_response('register successfully\n', 200)


class SessionResource(Resource):
    def get(self):
        username = flask.session.get('username')
        if username is None:
            return make_response('not logged in\n', 200)
        else:
            return make_response('Hello, %s\n' % username, 200)
    
    def post(self):
        header = request.headers.get('Authorization')
        if not (header and header.startswith('Basic')):
            return make_response('Failed: username and password not found\n', 403)
        b64 = header.replace('Basic ', '', 1)
        up = base64.b64decode(b64).decode()
        username, password = up.split(':', 1)
        print('[Log] Login: username = %s password = %s' % (username, password))
        with get_session() as session:
            user = session.query(User).filter_by(username = username).first()
            password = hmac.new(salt, password.encode(), digestmod = 'SHA1').hexdigest()
            if user.password != password:
                return make_response('Failed: incorrect password\n', 403)
            flask.session['username'] = username
        return make_response('login successfully\n', 200)

          
api.add_resource(CreateResource, '/')
api.add_resource(RUDResource, '/<id>')
api.add_resource(UserResource, '/user')
api.add_resource(SessionResource, '/session')
api.add_resource(BoardVisibilityResource, '/<id>/visibility')