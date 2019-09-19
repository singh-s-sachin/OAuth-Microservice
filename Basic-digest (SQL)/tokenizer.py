from flask import Flask,request,jsonify, make_response
import hashlib
import uuid
import jwt
from pymongo import MongoClient
import mysql.connector
import json
import datetime
from functools import wraps
from app import getuser,getusers,create_user,sub_login
app=Flask(__name__)
app.config["SECRET_KEY"]="ionixxtechnologiesprivatekey@sachinandram"
def apps(name,password):
    try:
        db=mysql.connector.connect(host='localhost',database='Auth',user='root',password='root')
        cursor = db.cursor()
    except:
        return False
    command='select app_name from users where app_name='+'"'+name+'"'
    cursor.execute(command)
    temp=cursor.fetchall()
    if len(temp) != 0:
        return False
    temp=password+str(app.config['SECRET_KEY'])
    pwd=hashlib.sha256(temp.encode())
    pid=str(uuid.uuid4())
    secret_key=str(uuid.uuid1())
    cursor.execute('insert into users(_id,secret_key,app_name,password,admin)values("{0}","{1}","{2}","{3}",False)'.format(pid,secret_key,name,str(pwd.hexdigest())))
    cursor.execute("create database {0}".format(name))
    cursor.execute("use {0}".format(name))
    cursor.execute("create table users(_id varchar(256) primary key,secret_key varchar(256),name varchar(36),password varchar(259),admin varchar(5))")
    cursor.execute('insert into users(_id,name,password,admin)value("{0}","{1}","{2}",True)'.format(pid,name,str(pwd.hexdigest())))
    db.commit()
    cursor.close()
    cursor.close()
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
            db=mysql.connector.connect(host='localhost',database='Auth',user='root',password='root')
            cursor = db.cursor()
        except:
            return jsonify({"message":"Database denied connection","error":401})
        k=db.users.find({"app_name":data['id']})
        if k.count()==0:
            return jsonify({"message":"User dosent exists","status":0})
        current_user=k[0]
        return f(current_user,*args,**kwargs)
    return decorated
@app.route('/app',methods=['GET'])
@token_required
def getapps(current_user):
    if not current_user['admin']:
        return jsonify({"message":"access-denied"})
    try:
        db=mysql.connector.connect(host='localhost',database='Auth',user='root',password='root')
        cursor = db.cursor()
    except:
        return jsonify({"message":"Database denied connection","error":401})
    k=db.users.find()
    l=[]
    for i in k:
        dic={"name":i["app_name"],"client_id":i["_id"],"secret_key":i["secret_key"]}
        l.append(dic)
    return json.dumps(l)
@app.route('/app/<app_name>',methods=['GET'])
@token_required
def getapp(current_user,app_name):
    if not current_user['admin']:
        return jsonify({"message":"access-denied"})
    try:
        db=mysql.connector.connect(host='localhost',database='Auth',user='root',password='root')
        cursor = db.cursor()
    except:
        return jsonify({"message":"Database denied connection","error":401})
    k=db.users.find({"app_name":app_name})
    if k.count()==1:
        k=k[0]
        return jsonify({"name":k["app_name"],"client_id":k["_id"],"secret_key":k["secret_key"]})
    else:
        return jsonify({"message":"User dosent exists"})
@app.route('/app',methods=['POST'])
def create_app():
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
        db=mysql.connector.connect(host='localhost',database='Auth',user='root',password='root')
        cursor = db.cursor()
    except:
        return jsonify({"message":"Database denied connection","error":401})
    db.users.delete_one({"app_name":app_name})    
    db[app_name].drop()
    return jsonify({"message":"user deleted","status":1})
@app.route('/login')
def login():
    auth=request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required"'})
    try:
        db=mysql.connector.connect(host='localhost',database='Auth',user='root',password='root')
        cursor = db.cursor()
    except:
        return jsonify({"message":"Database denied connection","error":401})
    k=db.users.find({"app_name":auth.username})
    if k.count()==1:
        k=k[0]
        temp=auth.password+str(app.config['SECRET_KEY'])
        hash_val=hashlib.sha256(temp.encode())
        if str(hash_val.hexdigest())==k["password"]:
            token=jwt.encode({'id':k['app_name'],'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=15)},app.config['SECRET_KEY'])
            return jsonify({"token":token.decode('UTF-8')})
        else:
            return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required"'})
    else:
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required"'})
@app.route('/<app_name>/register',methods=['POST'])
@token_required
def make_user(current_user,app_name):
    if current_user['admin']:
        return jsonify({"message":"access-denied"})
    if current_user['app_name']!=app_name:
        return jsonify({"message":"access-denied"})
    data=request.get_json()
    new_user=create_user(app_name,data['name'],data['password'])
    if new_user != False:
        return jsonify({"message":"User created","id":new_user})
    else:
        return jsonify({"message":"Database denied connection/User already exists","Error":"401"})
@app.route('/<app_name>/users',methods=['GET'])
@token_required
def get(current_user,app_name):
    if current_user['admin']:
        return jsonify({"message":"access-denied"})
    if current_user['app_name']!=app_name:
        return jsonify({"message":"access-denied"})
    res=getusers(app_name)
    if res==False:
        return jsonify({"message":"Database denied connection","error":401})
    return res
@app.route('/<app_name>/users/<user_name>',methods=['GET'])
@token_required
def gets(current_user,app_name,user_name):
    if current_user['admin']:
        return jsonify({"message":"access-denied"})
    if current_user['app_name']!=app_name:
        return jsonify({"message":"access-denied"})
    res=getuser(app_name,user_name)
    if res==False:
        return jsonify({"message":"User dosent exists","error":401})
    return res
@app.route('/<app_name>/login',methods=['GET'])
@token_required
def user_login(current_user,app_name):
    if current_user['admin']:
        return jsonify({"message":"access-denied"})
    if current_user['app_name']!=app_name:
        return jsonify({"message":"access-denied"})
    data=request.get_json()
    if not data['username'] and not data['password']:
        return jsonify({"message":"Credential needed","error":404})
    k=sub_login(app_name,data['username'],data['password'])
    return k
if __name__ == "__main__":
    app.run(debug=True)