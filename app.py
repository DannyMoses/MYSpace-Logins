from flask import Flask, request, session, render_template
from flask_pymongo import PyMongo
from datetime import date
from itsdangerous import URLSafeTimedSerializer
import json
import re
import bcrypt
import smtplib, ssl


port = 465
smtp_server = "smtp.gmail.com"
sender_email = "fatyoshienthusiasts@gmail.com"
password = "Ferdmansleftcheek123"
context = ssl.create_default_context()

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/users"

app.config["SECURITY_PASSWORD_SALT"] = "fatbirdo"
app.config["SECRET_KEY"] = "fatyoshi"

mongo = PyMongo(app)

EMAIL_REGEX = re.compile(r"([A-Z0-9_.+-]+@[A-Z0-9-]+.[A-Z0-9-.]+)", re.IGNORECASE)

def gen_token(email):
	serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
	return serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])

def confirm_token(token, expiration=10000):
	serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
	try:
		email = serializer.loads(
			token,
			salt=app.config["SECURITY_PASSWORD_SALT"],
			max_age=expiration
			)
	except:
		return False
	
	return email


@app.route('/adduser', methods=["POST"])
def add_user():
	print(80*'=')
	print("/ADDUSER() CALLED")
	data = request.json
	print("DATA: ", str(data))

	if data is None:
		print("ERROR: DATA IS NONE")
		return { "status" : "ERROR" }, 200 #400
	
	if "username" not in data or "password" not in data or "email" not in data:
		print("ERROR: IMPROPER DATA")
		return { "status" : "ERROR" }, 200 #400
	
	uname = data["username"]
	usr_collection = mongo.db.USERS

	if usr_collection is not None and usr_collection.find_one({"username" : uname }) is not None:
		print("ERROR: DATABASE CHECK FAILED")
		return { "status" : "ERROR" }, 200 #400
	
	email = data["email"]
	res = EMAIL_REGEX.match(email)

	if res == None:
		print("ERROR: BAD EMAIL REGEX MATCH")
		return { "status" : "ERROR" }, 200 #400

	hashed = bcrypt.hashpw(data["password"].encode('utf8'), bcrypt.gensalt())

	usr = { "username" : uname,
		"email" : email,
		"password" : data["password"],
		"password_hash" : hashed,
		"validated" : False

		}

	usr_collection.insert_one(usr)

	token = gen_token(email)

	html = render_template("user/activate.html", token=token)
	subject = "confirmation email"
	with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
		server.login(sender_email, password)
		server.sendmail(sender_email, email, "validation key: <"+token+">")

	return { "status" : "OK" }, 200


@app.route("/verify", methods=["POST"])
def verify_user():
	print(80*'=')
	print("/VERIFY() CALLED")
	data = request.json

	if "email" not in data or "key" not in data:
		return { "status" : "ERROR" }, 200 #400
	
	email = data["email"]
	token = data["key"]

	try:
		if email != confirm_email(token):
			return { "status" : "ERROR" }, 200 #400
	except:
		return { "status" : "ERROR" }, 200 #400
	
	print("VERIFY: ", str(email))
	mongo.db.users.update_one({"email" : email}, { '$set' : { 'validated' : True}})
	return { "status" : "OK"}, 200

@app.route('/login', methods=["POST"])
def login():
	print(80*'=')
	print("/VERIFY() CALLED")
	creds = request.json
	users_c = mongo.db.USERS

	user = users_c.find_one({'username': creds['username']})

	print("USER VALID", str(user['validated']))
	
	if user is None:
		return { "status" : "ERROR", "message" : "Username not found" }, 200 #400
	
	if user['validated'] == False:
		return { "status" : "ERROR", "message" : "User has not been validated" }, 200 #400
	
	if bcrypt.checkpw(creds['password'].encode('utf8'), user['password_hash']):
		# session['username'] = creds['username']
		print("LOGIN GOOD")
	else:
		return { "status" : "ERROR", "message" : "Incorrect password" }, 200 #400
	
	return { "status" : "OK"}, 200

@app.route('/logout', methods=["POST"])
def logout():
	session.clear()
	return { "status" : "OK"}, 200


