import os
import pickle
import sqlite3

password = "admin12345"
api_key = "SECRET_API_KEY_12345"

user_input = input("Enter expression: ")
result = eval(user_input)

os.system(user_input)

data = pickle.loads(user_data)

user_id = input("User ID: ")
query = "SELECT * FROM users WHERE id=" + user_id

DEBUG = True
