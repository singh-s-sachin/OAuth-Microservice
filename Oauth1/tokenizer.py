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
db=mysql.connector.connect(host='localhost',database='Ionixx',user='root',password='root')
cursor = db.cursor()
cursor.execute("select PersonID from table_name")
row = cursor.fetchall()
print(row)
