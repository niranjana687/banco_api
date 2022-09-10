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

def checkBalance(username, amount):
    balance = getBalance(username)

    if amount > balance:
        return False

    return True

def updateBalance(username, amount):
    current = getBalance(username)
    users.update_one({
        "Username":username
    }, {
        "$set": {
            "Balance": current + amount
        }
    })

def updateDebt(username, loan):
    debt = users.find_one({"Username": username})[0]["Debt"]

    users.update_one({
        "Username":username
        }, 
        {
            "$set": {
                "Debt": debt + loan
            }
        })
def getDebt(username):
    debt = users.find_one({"Username":username})[0]["Debt"]
    return debt

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

# Add funds to your account
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

# Transfer money to another account
class Transfer(Resource):
    def post(self):
        # get posted data
        postedData = request.get_json()

        # store username, password, amount, and receivers username
        username = postedData["username"]
        password = postedData["password"]
        amount = postedData["amount"]
        receiver = postedData["receiver"]

        # verify login
        verified = verifyLogin(username, password)

        # send error code if verification fails
        if not verified:
            return generateReturnDictionary(303, "invalid login")
        
        # verify amount 
        positive = checkAmount(amount)

        # send error if verification fails
        if not positive:
            return generateReturnDictionary(304, "amount should be greater than zero")

        # check if the user has sufficeint balance
        suff_balance = checkBalance(username, amount)

        # send error code if balance is insufficeint for transaction
        if not suff_balance:
            return generateReturnDictionary(305, "insufficient balance, try a lower amount or add funds")
        
        # verify username of receiver
        user_exists = verifyUsername(receiver)

        # send error code if verification fails
        if not user_exists:
            return generateReturnDictionary(301, "user does not exist. check username and try again")

        # send success code and message if transfer is successful
        transferred_amt = 0 - amount 
        updateBalance(username, transferred_amt)
        updateBalance(receiver, amount)

        return generateReturnDictionary(200, "Transaction successful")

# check account balance
class Balance(Resource):
    def post(self):
        # get posted data
        postedData = request.get_json()

        # get username and password
        username = postedData["username"]
        password = postedData["password"]

        # verify login
        verified = verifyLogin(username, password)

        # verification fails send error code
        if not verified:
            return generateReturnDictionary(303, "invalid login")

        # return success code wtih balance
        balance = getBalance(username)

        return balance, generateReturnDictionary(200, "success")

# take loan 
class TakeLoan(Resource):
    def post(self):
        # get posted data
        postedData = request.get_json()

        # get username and password
        username = postedData["username"]
        password = postedData["password"]
        loan = postedData["loan"]
        # verify login
        verified = verifyLogin(username, password)

        # send error code if unverified
        if not verified:
            return generateReturnDictionary(303, "invalid login")

        # check if loan amount is positive
        positive = checkAmount(loan)

        # send error code if not positve 
        if not positive:
            return generateReturnDictionary(304, "amount should be greater than zero")
        
        # update balance with amount
        updateBalance(username, loan)

        # update debt of user
        updateDebt(username, loan)

        # send success code
        return generateReturnDictionary(200, "loan granted")

# Pay Loan
class PayLoan(Resource):
    def post(self):
        # get posted data
        postedData = request.get_json()

        # get username password and amount payable
        username = postedData["username"]
        password = postedData["password"]
        amount = postedData["amount"]

        # verify login
        verified = verifyLogin(username, password)

        # return error code if verification fails
        if not verified:
            return generateReturnDictionary(303, "invalid login")
    
        # verify amount
        positive = checkAmount(amount)

        # return error code if amount is not positive
        if not positive:
            return generateReturnDictionary(304, "amount should be greater than zero")

        # check if the amount is more than the debt
        # return error code if more
        if amount > getDebt(username):
            return generateReturnDictionary(306, "amount is more than debt, try again")

        # check if the user has sufficient balance to pay
        # return error code if balance is insufficient
        if amount > getBalance(username)
            return generateReturnDictionary(305, "insufficient funds")
    
        # update debt
        new_debt = 0 - amount
        updateDebt(username, new_debt)

        # update balance
        withdrawal = 0 - amount
        updateBalance(username, withdrawal)

        # send success code
        return generateReturnDictionary(200, "debt paid successfully")

api.add_resource(Register, '/register')
api.add_resource(Add, '/add')
api.add_resource(Transfer, '/transfer')
api.add_resource(Balance, 'balance')
api.add_resource(TakeLoan, '/takeloan')
api.add_resource(PayLoan, '/payloan')

if __name__=="__main__":
    app.run('0.0.0.0', debug=True)