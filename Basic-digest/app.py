from flask import Flask,request,jsonify, make_response
import jwt
import hashlib
import uuid
from pymongo import MongoClient
import json
import sqlite3
import datetime
from functools import wraps
app=Flask(__name__)
app.config["SECRET_KEY"]="ionixxtechnologiesprivatekey@sachinandram"

def getuser(app_name,user_name):
    try:
        client = MongoClient("localhost",27017)
        db=client.Auth
    except:
        return False
    k=db[app_name].find({"name":user_name})
    if k.count()==0:
        return False
    i=k[0]
    k={"name":i["name"],"user_id":i["_id"]}
    return jsonify(k)
    

def getusers(app_name):
    try:
        client = MongoClient("localhost",27017)
        db=client.Auth
    except:
        return False
    k=db[app_name].find()
    l=[]
    for i in k:
        dic={"name":i["name"],"user_id":i["_id"]}
        l.append(dic)
    return json.dumps(l)
    
def create_user(app_name,name,password):
    try:
        client = MongoClient("localhost",27017)
        db=client.Auth
    except:
        return False
    if db.users.find({"name":name}).count() != 0:
        return False
    SECRET_KEY=db.users.find({"app-name":app_name})
    SECRET_KEY=SECRET_KEY[0]
    SECRET_KEY=SECRET_KEY["secret-key"]
    temp=password+SECRET_KEY
    pwd=hashlib.sha256(temp.encode())
    pid=str(uuid.uuid4())
    credentials={"_id":pid,"name":name,"password":str(pwd.hexdigest()),"admin":False}
    pid=db[app_name].insert(credentials)
    return pid

def sub_login(app_name,username,password): 
    try:
        client = MongoClient("localhost",27017)
        db=client.Auth
    except:
        return jsonify({"message":"Database denied connection","error":401})
    k=db[app_name].find({"name":username})
    if k.count()==1:
        SECRET_KEY=db.users.find({"app-name":app_name})
        SECRET_KEY=SECRET_KEY[0]
        SECRET_KEY=SECRET_KEY["secret-key"]
        k=k[0]
        temp=password+SECRET_KEY
        hash_val=hashlib.sha256(temp.encode())
        if str(hash_val.hexdigest())==k["password"]:
            token=jwt.encode({'id':k['name'],'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=15)},SECRET_KEY)
            return jsonify({"token":token.decode('UTF-8')})
        else:
            return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required"'})
    else:
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required"'})
if __name__ == "__main__":
    app.run(debug=True)