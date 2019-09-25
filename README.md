# OAuth-Microservice
## Basic Authentication
It is designed using two different databases (MongoDB and MySQL). Using this one can create a microservice to provide every user their own seperate database.
This microservice contains 2 types of admin.
## Admin
### Microservice Admin
This admin is responsible for creating new users for the microservice. Beyond creation of user a seperate database gets created for them and the new user becomes the admin of newly allocated database.
### Database Admin
This admin can only perform operation on the database allocated by the microservice admin.
## Applications
this microservice can be applied in huge industries where they handles enormous amunt of clients data. Being an microservice admin they can allocate seperate database for each client. This will unite the entire data and makes easier for the organisation to handle it.
