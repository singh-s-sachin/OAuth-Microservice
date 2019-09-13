from flask import Flask,request,jsonify, make_response
import requests
from requests_oauthlib import OAuth1
import jwt
import hashlib
import uuid
import json
import mysql.connector
import datetime
app=Flask(__name__)
@app.route('/register',methods=['GET'])
def register():
    db=mysql.connector.connect(host='localhost',database='Ionixx',user='root',password='root')
    cursor = db.cursor()
    data=request.get_json()
    name=data["name"]
    reason=data["reason"]
    id=hashlib.sha256(name.encode())
    token=uuid.uuid4()
    try:
        command='insert into developer(name,reason,id,token)values("'+str(name)+'","'+str(reason)+'","'+str(id.hexdigest())+'","'+str(token)+'")'
        cursor.execute(command)
    except:
        db.commit()
        cursor.close()
        cursor.close()
        return jsonify({"message":"User already exists"})
    db.commit()
    cursor.close()
    cursor.close()
    return jsonify({"message":"token generated","token":token})
@app.route('/app',methods=['POST','GET'])
def use():
    db=mysql.connector.connect(host='localhost',database='Ionixx',user='root',password='root')
    cursor = db.cursor()
    data=request.get_json()
    if data is None:
        return jsonify({"access":"denied","message":"token required"})
    token=data["token"]
    command='select id from developer where token="'+str(token)+'"'
    cursor.execute(command)
    id=cursor.fetchall()
    if len(id)==0:
        return jsonify({"access":"denied","message":"authentication failed"})
    id=id[0]
    db.commit()
    cursor.close()
    cursor.close()
    return jsonify({"access":"granted","id":id,"message":"authentication successful"})
if __name__ == "__main__":
    app.run(debug=True)