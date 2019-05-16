# coding=utf-8
from flask import Flask, jsonify, request, render_template
from flask_jwt_extended import (
    JWTManager, verify_jwt_in_request, create_access_token,
    get_jwt_claims, jwt_required, current_user, get_jwt_identity, get_current_user, create_refresh_token,
    jwt_refresh_token_required, fresh_jwt_required, get_raw_jwt, decode_token, get_jti
)
from functools import wraps
import datetime
from collections import defaultdict
from jwt import PyJWT
from calendar import timegm

import rsa

app = Flask(__name__)


pubkey, privkey = rsa.newkeys(2048)

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['JWT_IDENTITY_CLAIM'] = 'test'
app.config['JWT_USER_CLAIMS'] = 'jwt'
app.config['JWT_ALGORITHM'] = 'RS512'
app.config['JWT_PRIVATE_KEY'] = privkey.save_pkcs1()
app.config['JWT_PUBLIC_KEY'] = pubkey.save_pkcs1()


jwt = JWTManager(app)


class UserObject:
    def __init__(self, username, roles):
        self.username = username
        self.roles = roles

    def __repr__(self):
        return self.username

def check_role(role=0):
    def admin_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt_claims()
            if claims['roles'] != role:
                return jsonify(msg='Admins only!'), 403
            else:
                return fn(*args, **kwargs)
        return wrapper
    return admin_required

blacklist = set()
user_login = defaultdict()

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


@jwt.user_claims_loader
def add_claims_to_access_token(user):
    return {'roles': user.roles, 'aud':user.username}

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.username

@jwt.invalid_token_loader
def invalid_token(reason):
    return  jsonify({'code':-100, 'msg':u'无效的token'}), 403

@jwt.user_loader_callback_loader
def user_loader(user):
    return UserObject(user, roles=1)

@jwt.expired_token_loader
def token_expired():
    py_jwt = PyJWT()
    print(py_jwt.decode(jwt=request.headers['Authorization'].split()[-1], verify=False)['type'])
    return jsonify({'code':-1000})

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', None)
    password = request.form.get('password', None)

    if username in user_login.keys():
        now = timegm(datetime.datetime.utcnow().utctimetuple())
        if now > user_login[username]:
            pass
        else:
            return jsonify({'code':'-1','data':{}, 'msg':'has login'})

    # Create an example UserObject
    user = UserObject(username=username, roles=1)

    now = datetime.datetime.utcnow()
    exp = datetime.timedelta(minutes=2)

    user_login[username] = timegm( (now+exp).utctimetuple())
    access_token = create_access_token(identity=user, expires_delta=datetime.timedelta(minutes=2))
    refresh_token = create_refresh_token(identity=user, expires_delta=datetime.timedelta(minutes=4))
    ret = {'code':'0','data':{'access_token': access_token, 'refresh_token':refresh_token}}

    return jsonify(ret), 200


@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    new_token = create_access_token(identity=current_user, fresh=False, expires_delta=datetime.timedelta(minutes=2))
    new_fresh = create_refresh_token(identity=current_user,  expires_delta=datetime.timedelta(minutes=4))
    ret = {'code':'0','data':{'access_token': new_token, 'refresh_token':new_fresh}}
    return jsonify(ret), 200

@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # print(decode_token(request.headers['Authorization'].split()[-1]))
    return jsonify({'code':'0','secret_message':get_jwt_identity(), 'time':datetime.datetime.now()})

@app.route('/protected-fresh', methods=['GET'])
@fresh_jwt_required
def protected_fresh():
    username = get_jwt_identity()
    return jsonify(fresh_logged_in_as=username), 200

@app.route('/logout', methods=['DELETE'])
@jwt_required
def logout():
    print(get_jwt_identity())
    jti = get_raw_jwt()
    print(jti)
    blacklist.add(jti)
    print(blacklist)
    return jsonify({"msg": "Successfully logged out"}), 200

@app.route('/')
def index():
    py_jwt = PyJWT()
    print(py_jwt.decode(jwt=request.headers['Authorization'].split()[-1], key='super-secret',
                  verify=False, algorithms="HS256",identity_claim_key='identity',
                user_claims_key="user_claims"))
    return render_template('test.html')


if __name__ == '__main__':
    app.run('192.168.25.73')