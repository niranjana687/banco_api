from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import Mongoclient
import bcrypt

app = Flask(__name__)
api = Api(app)

# connecting to database
client = Mongoclient('localhost', 27017)
db = client.BancoApiDb
users = db["Users"]

def verifyUsername(username):
    if users.find_one({"Username": username}).count_documents() == 0:
        return False
    else:
        return True

def generateReturnDictionary(status, message):
    returnJson = {
        "status": status,
        "message": message
    }
    return jsonify(returnJson)

def verifyLogin(username, password):
    if verifyUsername(username):
        return False
    
    pwd = users.find_one({"Username": username})[0]["Password"]

    if bcrypt.hashpw(password.endode('utf8'), bcrypt.gensalt()) != pwd:
        return False
    
    return True
        
def checkAmount(amount):
    if amount <= 0:
        return False
    
    return True

def getBalance(username):
    balance = users.find_one({"Username":username})[0]["Balance"]
    return balance

# Register to the app
class Register(Resource):
    def post(self):
        # get posted data
        postedData = request.get_json()

        # retrieve username and password from posted data
        username = postedData["username"]
        password = postedData["password"]

        # check if username is available
        user_exists = verifyUsername(username)

        if user_exists:
            return generateReturnDictionary(301, "Username is not available")
        
        # If username is availabe, register the user into the database
        # after hashing the password
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert_one({
            "Username": username,
            "Password": hashed_pw,
            "Balance": 0,
            "Debt": 0
        })

        return generateReturnDictionary(200, "Registration successful")    

class Add(Resource):
    def post(self):
        # get posted data
        postedData = request.get_json()

        # retrieve username, password and amount to be added
        username = postedData["username"]
        password = postedData["password"]
        amount = postedData["amount"]

        # verify login creds
        verified = verifyLogin(username, password)

        # if credentials are incorrect send error code amd message
        if not verified:
            return generateReturnDictionary(303, "incorrect login credentials")

        # once verified check if the amount is greater than zero
        positive = checkAmount(amount)

        # send error message if not
        if not positive:
            return generateReturnDictionary(304, "amount should be greater than 0")

        # else update balance 
        balance = getBalance(username)

        users.find_one({
            "Username": username
        }, {
            "$set": {
                "Balance": balance + amount
            }
        })

        return generateReturnDictionary(200, "Successfully added funds")

api.add_resource(Register, '/register')
api.add_resource(Add, '/add')

if __name__=="__main__":
    app.run('0.0.0.0', port=5000, debug=True)