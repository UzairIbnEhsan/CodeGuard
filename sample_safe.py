import os
import sqlite3

password = os.environ.get("APP_PASSWORD")

user_id = input("User ID: ")

connection = sqlite3.connect("app.db")
cursor = connection.cursor()

cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
rows = cursor.fetchall()

print(rows)
