from pymongo import MongoClient
import hashlib
import uuid
client = MongoClient("localhost",27017)
db=client.Auth
while True:
    username=input("Enter admin name")
    password=input("Enter password")
    if db.users.find({"name":username}).count() != 0:
        print("Username taken")
        continue
    temp=password+"ionixxtechnologiesprivatekey@sachinandram"
    pwd=hashlib.sha256(temp.encode())
    pid=str(uuid.uuid4())
    credentials={"_id":pid,"app-name":username,"password":str(pwd.hexdigest()),"admin":True,"secret-key":str(uuid.uuid1())}
    pid=db.users.insert(credentials)
    break