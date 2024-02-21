import flask
from flask import Flask, request, make_response, jsonify
from flask_restful import Resource, Api
from datetime import datetime, timedelta
import hashlib
import uuid
from models import Clipboard, Visibility, get_session, User, SelfDestruction
import os
import base64
import hmac
import time
import random

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

def duplicate_check(session, short):
    check1 = (session.query(Clipboard).filter_by(short = short).count() == 0)
    check2 = (session.query(Clipboard).filter_by(uuid = short).count() == 0)
    check3 = (session.query(Clipboard).filter_by(alias = short).count() == 0)
    return check1 and check2 and check3

def find_clipboard(session, url):
    board = session.query(Clipboard).filter_by(uuid = url).first()
    if board is not None:
        return board
    board = session.query(Clipboard).filter_by(short = url).first()
    if board is not None:
        return board
    board = session.query(Clipboard).filter_by(alias = url).first()
    return board

def get_short(session):
    while True:
        short = ""
        for i in range(4):
            short += get_char(random.randint(0, 61))
        if duplicate_check(session, short):
            return short
        
def my_make_response(msg, code):
    if request.headers.get('User-Agent')[:5] == 'curl/':
        return make_response(msg, code)
    else:
        return jsonify(msg = msg, code = code)
        
def create_clipboard(alias = None):
    print(alias)
    username = flask.session.get('username')
    with get_session() as session:
        bytes = request.files['c'].read()
        print('[Log] Create a new clipboard, content: %s' % bytes.decode())
        md5 = hashlib.md5()
        md5.update(bytes)
        id = str(uuid.uuid4())
        short = get_short(session)
        board_dict = dict(date = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f %Z'), digest = md5.hexdigest(), short = short, size = len(bytes), url = name + '/' + short, uuid = id, content = bytes.decode(), author = username, visibility = Visibility.all, alias = alias)
        sunset = request.form.get('sunset')
        if sunset is not None:
            board_dict['expiration_time'] = int(time.time() + int(sunset))
        new_board = Clipboard(**board_dict)
        try:
            session.add(new_board)
            session.commit()
        except BaseException as e:
            print('[Error] %s' % e)
            status = 'failed'
        else:
            status = 'created'
        if request.headers.get('User-Agent')[:5] == 'curl/':
            return make_response('''
date: %s
digest: %s
short: %s
size: %d
url: %s
status: %s
uuid: %s
''' % (new_board.date, new_board.digest, new_board.short, new_board.size, new_board.url, status, new_board.uuid), 200 if status == 'created' else 403)
        else:
            return jsonify(code = 200, msg = 'created', data = dict(date = new_board.date, digest = new_board.digest, short = new_board.short, size = new_board.size, url = new_board.url, uuid = new_board.uuid))
    

class CreateResource(Resource):
    # def get(self):
    #     u = session.get('user')
    #     if u:
    #         print('success')
    #     else:
    #         session['user'] = '1'
    #         print('login')
            
    def post(self):
        return create_clipboard()


class RUDResource(Resource):
    def post(self, id):
        with get_session() as session:
            if find_clipboard(session, id) is not None:
                return my_make_response('Failed: This alias conflicts with some uuid/short/alias. Please change a new one.\n', 403)
        return create_clipboard(id)
    
    def delete(self, id):
        username = flask.session.get('username')
        with get_session() as session:
            board = find_clipboard(session, id)
            if board is None:
                response = my_make_response('Failed: Cannot find the UUID\n', 404)
            else:
                if board.author is not None and username != board.author:
                    return my_make_response('Failed: no permission to update\n', 403)
                response = my_make_response('deleted %s\n' % id, 200)
                session.delete(board)
                session.commit()
            return response
    
    def put(self, id):
        username = flask.session.get('username')
        with get_session() as session:
            board = find_clipboard(session, id)
            if board is None:
                response = my_make_response('Failed: Cannot find the UUID\n', 404)
            else:
                if board.author is not None and username != board.author:
                    return my_make_response('Failed: no permission to update\n', 403)
                response = my_make_response('%s updated\n' % board.url, 200)
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
            board = find_clipboard(session, id)
            if board is None:
                response = my_make_response('Failed: Cannot find the UUID\n', 404)
            else:
                if board.visibility == Visibility.author_only and username != board.author or board.visibility == Visibility.someone_only and username != board.author and username != board.someone:
                    return my_make_response('Failed: no permission to view the clipboard\n', 403)
                if board.expiration_time is not None and int(time.time()) > board.expiration_time:
                    return my_make_response('expired\n', 403)
                if board.someone == username:
                    if board.self_destruction == SelfDestruction.destroyed:
                        return my_make_response('Failed: have burnt after reading\n', 200)
                    elif board.self_destruction == SelfDestruction.undestroyed:
                        board.self_destruction = SelfDestruction.destroyed
                if request.headers.get('User-Agent')[:5] == 'curl/':
                    response = make_response(board.content, 200)
                else:
                    response = jsonify(code = 200, data = dict(content = board.content), msg = 'success\n')
            session.commit()
            return response


class BoardVisibilityResource(Resource):
    def get(self, id):
        username = flask.session.get('username')
        with get_session() as session:
            board = find_clipboard(session, id)
            if board is None:
                return my_make_response('Failed: Cannot find the UUID\n', 404)
            if board.author is not None and username != board.author:
                return my_make_response('Failed: no permission to view the information\n', 403)
            dic = {}
            response = 'visibility: %s\n' % board.visibility.name
            dic['visibility'] = board.visibility.name
            if board.visibility == Visibility.someone_only:
                response += 'someone: ' + board.someone + '\n'
                dic['someone'] = board.someone
            if request.headers.get('User-Agent')[:5] == 'curl/':
                return make_response(response, 200)
            else:
                return jsonify(code = 200, msg = 'success', data = dic)
    
    def put(self, id):
        username = flask.session.get('username')
        with get_session() as session:
            board = find_clipboard(session, id)
            if board is None:
                return my_make_response('Failed: Cannot find the UUID\n', 404)
            if board.author is not None and username != board.author:
                return my_make_response('Failed: no permission to update\n', 403)
            new_status = request.form.get('status')
            if getattr(Visibility, str(new_status), None) is None:
                return my_make_response('Failed: invalid visibility format\n', 403)
            if new_status == 'someone_only':
                someone = request.form.get('someone')
                if someone is None:
                    return my_make_response('Failed: someone not found\n', 403)
                elif someone == board.author:
                    return my_make_response('Failed: \'someone\' cannot be the same as the author\n', 403)
                board.someone = someone
            else:
                board.someone = None
                board.self_destruction = None
            board.visibility = Visibility[new_status]
            session.commit()
            return my_make_response('the visibility of %s updated: %s\n' % (board.url, board.visibility.name), 200)


class BoardSelfDestructionResource(Resource):
    def get(self, id):
        username = flask.session.get('username')
        with get_session() as session:
            board = find_clipboard(session, id)
            if board is None:
                return my_make_response('Failed: Cannot find the UUID\n', 404)
            if board.author is not None and username != board.author:
                return my_make_response('Failed: no permission to view the information\n', 403)
            if board.self_destruction == None:
                return my_make_response('disabled\n', 200)
            else:
                if request.headers.get('User-Agent')[:5] == 'curl/':
                    return make_response('enabled\nstatus:%s\n' % board.self_destruction.name, 200)
                else:
                    return jsonify(code = 200, msg = 'success', data = dict(status = board.self_destruction.name))
    
    def put(self, id):
        username = flask.session.get('username')
        with get_session() as session:
            board = find_clipboard(session, id)
            if board is None:
                return my_make_response('Failed: Cannot find the UUID\n', 404)
            if board.author is not None and username != board.author:
                return my_make_response('Failed: no permission to update\n', 403)
            if board.visibility != Visibility.someone_only:
                return my_make_response('Failed: the clipboard should have visibility [someone_only]\n', 403)
            new_status = request.form.get('status')
            if new_status == 'true':
                board.self_destruction = SelfDestruction.undestroyed
            elif new_status == 'false':
                board.self_destruction = None
            else:
                return my_make_response('Failed: invalid request format\n', 403)
            session.commit()
            return my_make_response('[Burn After Reading] %s\n' % ('enabled' if new_status == 'true' else 'disabled'), 200)

            
class UserResource(Resource):
    def post(self):
        header = request.headers.get('Authorization')
        if not (header and header.startswith('Basic')):
            return my_make_response('Failed: username and password not found\n', 403)
        b64 = header.replace('Basic ', '', 1)
        up = base64.b64decode(b64).decode()
        username, password = up.split(':', 1)
        if len(username) == 0 or len(password) == 0:
            return my_make_response('Failed: username or password cannot be empty\n', 403)
        print('[Log] Register: username = %s password = %s' % (username, password))
        with get_session() as session:
            cnt = session.query(User).filter_by(username = username).count()
            if cnt > 0:
                return my_make_response('Failed: The username already exists\n', 403)
            password = hmac.new(salt, password.encode(), digestmod = 'SHA1').hexdigest()
            new_user = User(username = username, password = password)
            session.add(new_user)
            session.commit()
        return my_make_response('register successfully\n', 200)


class SessionResource(Resource):
    def get(self):
        username = flask.session.get('username')
        if username is None:
            if request.headers.get('User-Agent')[:5] == 'curl/':
                return make_response('not logged in\n', 200)
            else:
                return jsonify(code = 200, msg = 'success', data = dict(logged_in = False))
        else:
            if request.headers.get('User-Agent')[:5] == 'curl/':
                return make_response('Hello, %s\n' % username, 200)
            else:
                return jsonify(code = 200, msg = 'success', data = dict(logged_in = True, username = username))
    
    def post(self):
        header = request.headers.get('Authorization')
        if not (header and header.startswith('Basic')):
            return my_make_response('Failed: username and password not found\n', 403)
        b64 = header.replace('Basic ', '', 1)
        up = base64.b64decode(b64).decode()
        username, password = up.split(':', 1)
        print('[Log] Login: username = %s password = %s' % (username, password))
        with get_session() as session:
            user = session.query(User).filter_by(username = username).first()
            password = hmac.new(salt, password.encode(), digestmod = 'SHA1').hexdigest()
            if user.password != password:
                return my_make_response('Failed: incorrect password\n', 403)
            flask.session['username'] = username
        return my_make_response('login successfully\n', 200)

          
api.add_resource(CreateResource, '/')
api.add_resource(RUDResource, '/<id>')
api.add_resource(UserResource, '/user')
api.add_resource(SessionResource, '/session')
api.add_resource(BoardVisibilityResource, '/<id>/visibility')
api.add_resource(BoardSelfDestructionResource, '/<id>/self-destruction')