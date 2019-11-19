from flask import Flask, request, session, render_template
#from flask_pymongo import PyMongo
#from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer
import bcrypt
import requests

import json, re, smtplib, ssl
from datetime import date
from config import CONFIG

import mysql.connector
# gmail = None
#port = 465
#smtp_server = "smtp.gmail.com"
#sender_email = "fatyoshienthusiasts@gmail.com"
#password = "Ferdmansleftcheek123"
#context = ssl.create_default_context()

app = Flask(__name__)
#app.config["MONGO_URI"] = "mongodb://localhost:27017/users"
#app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://{}:{}@{}:{}/{}".format(
#						config['mysql_usr'],
#						config['mysql_pwd'],
#						config['mysql_server'],
#						config['mysql_port'],
#						config['mysql_db']
#					)

app.config["SECURITY_PASSWORD_SALT"] = "fatbirdo"
app.config["SECRET_KEY"] = "fatyoshi"

from Gmail import Gmail
#mongo = PyMongo(app)
db = mysql.connector.connect(
	host=CONFIG["mysql_server"],
	user=CONFIG["mysql_usr"],
	port=CONFIG["mysql_port"],
	passwd=CONFIG["mysql_pwd"],
	database=CONFIG["mysql_db"]
)


cursor = db.cursor(buffered=True)
gmail = Gmail()
gmail.get_credentials()

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

def check_user(user):
	sql = "SELECT username FROM users WHERE username = '" + user + "'" 
	print("SQL:", sql)
	x = cursor.execute(sql)
	print(x)
	if x is None:
		return False
	else:
		return True
	return False

def check_email(email):
	sql = "SELECT email FROM users WHERE email=%s"
	x = cursor.execute(sql, (email,))
	for x in cursor:
		if email in x:
			return True
	return False

def check_validated(user):
	sql = "SELECT validated FROM users WHERE username = %s"
	cursor.execute(sql, (user,))
	for x in cursor:
		return x[0] == 1
	return False

def get_pwhash(user):
	sql = "SELECT password_hash FROM users where username = %s"
	cursor.execute(sql, (user,))
	for x in cursor:
		return x[0]
	return None

@app.route('/reset_logins', methods=["POST"])
def reset():
	print("/RESET_LOGINS() CALLED")
	cursor.execute("DELETE FROM users")
	db.commit()
	return { "status": "OK" }, 200

@app.route('/adduser', methods=["POST"])
def add_user():
	print(80*'=')
	print("/ADDUSER() CALLED")
	data = request.json
	print("DATA: ", str(data))

	if data is None:
		print("error: DATA IS NONE")
		return { "status" : "error" , "error": "No data specified" }, 400

	if "username" not in data or "password" not in data or "email" not in data:
		print("error: IMPROPER DATA")
		return { "status" : "error", "error": "Not all data fields were found" }, 400

	uname = data["username"]
	# usr_collection = mongo.db.users
	# usr_collection is not None and usr_collection.find_one({"username" : uname }) is not None

	email = data["email"]
	res = EMAIL_REGEX.match(email)

	if res == None:
		print("error: BAD EMAIL REGEX MATCH")
		return { "status" : "error" }, 400
	if check_email(email) is True:
		print("error: DATABASE CHECK EMAIL FAILED")
		return { "status" : "error", "error": "Email already in use" }, 400


	hashed = bcrypt.hashpw(data["password"].encode('utf8'), bcrypt.gensalt())
	hashed = hashed.decode('utf-8')

	usr = { "username" : uname,
		"email" : email,
		"password" : data["password"],
		"password_hash" : hashed,
		"validated" : False
		}

	#usr_collection.insert_one(usr)
	sql = "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)"
	print(type(hashed))
	val = (uname, email, hashed)
	cursor.execute(sql, val)

	if check_user(uname) == True:
		print("error: DATABASE CHECK USERNAME FAILED")
		return { "status" : "error", "error": "Username taken" }, 400

	db.commit()

	token = gen_token(email)

	#html = render_template("user/activate.html", token=token)
	#subject = "confirmation email"
	#with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
	#	server.login(sender_email, password)
	#	server.sendmail(sender_email, email, "validation key: <"+token+">")

	to_address = email
	subject = "Your Moses&YangSpace Activation Key"
	body = "validation key: <" + token + ">"

	gmail.send_mail(to_address, subject, body)

	requests.post("http://" + CONFIG["profiles_ip"] + "/user", json= { "username" : uname,
		"email" : email } )

	return { "status" : "OK" }, 200


@app.route("/verify", methods=["POST"])
def verify_user():
	print(80*'=')
	print("/VERIFY() CALLED")
	data = request.json

	if "email" not in data or "key" not in data:
		return { "status" : "error", "error": "Email or key not specified in request" }, 200 #400

	email = data["email"]
	token = data["key"]

	# skip check if backdoor used
	if token != "abracadabra":
		try:
			ret = confirm_token(token)
			print("CONF_TOKEN:", ret)
			if email != confirm_token(token):
				print("WEE WOO WEE WOO BAD EMAIL")
				return { "status" : "error", "error" : "bad email" }, 400
		except Exception as e:
			print(e)
			return { "status" : "error", "error": "Contact a developer" }, 400

	print("VERIFY: ", str(email))
	#mongo.db.users.update_one({"email" : email}, { '$set' : { 'validated' : True}})
	sql = "UPDATE users SET validated = 1 WHERE email = %s"
	cursor.execute(sql, (email,))
	db.commit()
	return { "status" : "OK"}, 200

@app.route('/login', methods=["POST"])
def login():
	print(80*'=')
	print("/LOGIN() CALLED")
	creds = request.json
	print("CREDS:", creds)
	#users_c = mongo.db.users

	#user = users_c.find_one({'username': creds['username']})

	# Already logged in
	#if session['username']:
	#	return { "status" : "OK"}, 200

	# User does not exist
	if check_user(creds['username']) == False: 
		print("NO USER")
		return { "status" : "error", "error" : "Username not found" }, 400

	# print("USER VALID", str(user['validated']))

	if not check_validated(creds['username']):
		print("NOT VALIDATED")
		return { "status" : "error", "error" : "User has not been validated" }, 400
	
	
	if bcrypt.checkpw(creds['password'].encode('utf8'), get_pwhash(creds['username']).encode('utf8')):
		# session['username'] = creds['username']
		print("LOGIN GOOD")
	else:
		return { "status" : "error", "error" : "Incorrect password" }, 400

	return { "status" : "OK", "username": creds['username'] }, 200

@app.route('/logout', methods=["POST"])
def logout():
	session.clear()
	return { "status" : "OK"}, 200

if __name__ == "__main__":
	print("main")
	gmail = Gmail()
	gmail.get_credentials()
	app.run()
