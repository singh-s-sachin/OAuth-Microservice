import mysql.connector
import hashlib
import uuid
db=mysql.connector.connect(host='localhost',database='Auth',user='root',password='root')
cursor = db.cursor()
while True:
    username=input("Enter admin name")
    password=input("Enter password")
    command='select app_name,_id,secret_key from users where app_name="{0}"'.format(username)
    cursor.execute(command)
    k=cursor.fetchall()
    if len(k) != 0:
        print("Username taken")
        continue
    temp=password+"ionixxtechnologiesprivatekey@sachinandram"
    pwd=hashlib.sha256(temp.encode())
    pid=str(uuid.uuid4())
    cursor.execute('insert into users(_id,secret_key,app_name,password,admin)values("{0}","{1}","{2}","{3}",True)'.format(pid,"Null",username,str(pwd.hexdigest())))
    break