from flask import Flask,request,jsonify, make_response
#from flask_sqlalchemy import SQLAlchemy
import jwt
import hashlib
import uuid
from pymongo import MongoClient
import json
import sqlite3
import datetime
from functools import wraps
app=Flask(__name__)
#db=SQLAlchemy(app)
app.config["SECRET_KEY"]="ionixxtechnologiesprivatekey@sachinandram"
#app.config['SQLALCHEMY_DATABASE_URI']="sqlite:////mnt/c/Users/antho/Documents/api/userhub.db"
def apps(name,password):
    try:
        client = MongoClient("localhost",27017)
        db=client.Auth
    except:
        return False
    if db.users.find({"app-name":name}).count() != 0:
        return False
    temp=password+str(app.config['SECRET_KEY'])
    pwd=hashlib.sha256(temp.encode())
    pid=str(uuid.uuid4())
    secret_key=str(uuid.uuid1())
    credentials={"_id":pid,"secret-key":secret_key,"app-name":name,"password":str(pwd.hexdigest()),"admin":False}
    pid=db.users.insert(credentials)
    return pid

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']
        if not token:
            return jsonify({"message":"token-required","access":"denied"})
        try:
            data=jwt.decode(token,app.config['SECRET_KEY'])
        except:
            return jsonify({"message":"Invalid token"})
        try:
            client = MongoClient("localhost",27017)
            db=client.Auth
        except:
            return jsonify({"message":"Database denied connection","error":401})
        k=db.users.find({"app-name":data['id']})
        if k.count()==0:
            return jsonify({"message":"User dosent exists","status":0})
        current_user=k[0]
        return f(current_user,*args,**kwargs)
    return decorated
        
@app.route('/app',methods=['GET'])
@token_required
def getusers(current_user):
    if not current_user['admin']:
        return jsonify({"message":"access-denied"})
    try:
        client = MongoClient("localhost",27017)
        db=client.Auth
    except:
        return jsonify({"message":"Database denied connection","error":401})
    k=db.users.find()
    l=[]
    for i in k:
        dic={"name":i["app-name"],"client_id":i["_id"],"secret_key":i["secret-key"]}
        l.append(dic)
    return json.dumps(l)

@app.route('/app/<app_name>',methods=['GET'])
@token_required
def getuser(current_user,app_name):
    if not current_user['admin']:
        return jsonify({"message":"access-denied"})
    try:
        client = MongoClient("localhost",27017)
        db=client.Auth
    except:
        return jsonify({"message":"Database denied connection","error":401})
    k=db.users.find({"app-name":app_name})
    if k.count()==1:
        k=k[0]
        return jsonify({"name":k["app-name"],"client_id":k["_id"],"secret_key":k["secret-key"]})
    else:
        return jsonify({"message":"User dosent exists"})

@app.route('/app',methods=['POST'])
@token_required
def create_app(current_user):
    if not current_user['admin']:
        return jsonify({"message":"access-denied"})
    data=request.get_json()
    new_user=apps(data['name'],data['password'])
    if new_user != False:
        return jsonify({"message":"User created","id":new_user})
    else:
        return jsonify({"message":"Database denied connection/User already exists","Error":"401"})

@app.route('/app/<app_name>',methods=['DELETE'])
@token_required
def delete_app(current_user,app_name):
    if not current_user['admin']:
        return jsonify({"message":"access-denied"})
    try:
        client = MongoClient("localhost",27017)
        db=client.Auth
    except:
        return jsonify({"message":"Database denied connection","error":401})
    db.users.delete_one({"name":app_name})    
    return jsonify({"message":"user deleted","status":1})

@app.route('/login')
def login(): 
    auth=request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required"'})
    try:
        client = MongoClient("localhost",27017)
        db=client.Auth
    except:
        return jsonify({"message":"Database denied connection","error":401})
    k=db.users.find({"app-name":auth.username})
    if k.count()==1:
        k=k[0]
        temp=auth.password+str(app.config['SECRET_KEY'])
        hash_val=hashlib.sha256(temp.encode())
        if str(hash_val.hexdigest())==k["password"]:
            token=jwt.encode({'id':k['app-name'],'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=15)},app.config['SECRET_KEY'])
            return jsonify({"token":token.decode('UTF-8')})
        else:
            return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required"'})
    else:
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required"'})

if __name__ == "__main__":
    app.run(debug=True)