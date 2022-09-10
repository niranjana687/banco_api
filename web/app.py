from distutils.log import debug
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import Mongoclient
import bycrypt

app = Flask(__name__)
api = Api(app)

# connecting to database
client = Mongoclient('localhost', 27017)
db = client.BancoApiDb
users = db["Users"]

if __name__=="__main__":
    app.run('0.0.0.0', port=5000, debug=True)