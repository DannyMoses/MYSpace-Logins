from flask import Flask, request, session, render_template
from itsdangerous import URLSafeTimedSerializer
import bcrypt, requests

from Gmail import Gmail
import mysql.connector

import logging, json, re, smtplib, ssl
from datetime import date
from config import CONFIG

# gmail = None
#port = 465
#smtp_server = "smtp.gmail.com"
#sender_email = "fatyoshienthusiasts@gmail.com"
#password = "Ferdmansleftcheek123"
#context = ssl.create_default_context()

app = Flask(__name__)
#app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://{}:{}@{}:{}/{}".format(
#						config['mysql_usr'],
#						config['mysql_pwd'],
#						config['mysql_server'],
#						config['mysql_port'],
#						config['mysql_db']
#					)

app.config["SECURITY_PASSWORD_SALT"] = "fatbirdo"
app.config["SECRET_KEY"] = "fatyoshi"

db = mysql.connector.connect(
	host=CONFIG["mysql_server"],
	port=CONFIG["mysql_port"],
	user=CONFIG["mysql_usr"],
	passwd=CONFIG["mysql_pwd"],
	database=CONFIG["mysql_db"],
	buffered=True
)


gmail = Gmail()
gmail.get_credentials()

EMAIL_REGEX = re.compile(r"([A-Z0-9_.+-]+@[A-Z0-9-]+.[A-Z0-9-.]+)", re.IGNORECASE)

# Setup logging
if __name__ != '__main__':
	gunicorn_logger = logging.getLogger('gunicorn.error')
	app.logger.handlers = gunicorn_logger.handlers
	app.logger.setLevel(gunicorn_logger.level)

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

# Assumes db.cursor(dictionary=True)
def get_user(user, cursor):
	sql = "SELECT * FROM users WHERE username=%s LIMIT 1"
	#app.logger.info("check_user SQL: " + sql)
	#print("SQL:", sql)
	db.commit()
	cursor.execute(sql, (user,))
	row = cursor.fetchall()

	app.logger.debug("Result: ")
	if not row:
		return None

	app.logger.debug(json.dumps(row))
	return row[0]

def check_user(user, cursor):
	sql = "SELECT username FROM users WHERE username=%s"
	#app.logger.info("check_user SQL: " + sql)
	#print("SQL:", sql)
	cursor.execute(sql, (user,))
	app.logger.debug("Result: ")

	rows = cursor.fetchall()
	if not rows:
		return False
	
	app.logger.debug(rows)
	for x in rows:
		if user == x['username']:
			return True
	return False

def check_email(email, cursor):
	sql = "SELECT email FROM users WHERE email=%s"
	app.logger.info("check_email SQL: {} email: {}".format(sql, email))
	db.commit()
	cursor.execute(sql, (email,))
	app.logger.debug("Result: ")

	rows = cursor.fetchall()
	if not rows:
		return False
	
	app.logger.debug(rows)
	for x in rows:
		app.logger.debug(x)
		if email == x['email']:
			return True
	return False

def is_validated(user, cursor):
	sql = "SELECT validated FROM users WHERE username = %s"
	#app.logger.info("is_validated SQL: " + sql)
	db.commit()
	cursor.execute(sql, (user,))

	rows = cursor.fetchall()
	if not rows:
		return False
	
	app.logger.debug(rows)
	for x in rows:
		return x['validated'] == 1
	return False

def get_pwhash(user, cursor):
	sql = "SELECT password_hash FROM users where username = %s"
	#app.logger.info("check_pwhash SQL: " + sql)
	db.commit()
	cursor.execute(sql, (user,))

	rows = cursor.fetchall()
	if not rows:
		return None
	
	app.logger.debug(rows)
	for x in rows:
		return x['password_hash']

	return None

# Reset
@app.route('/reset_logins', methods=["POST"])
def reset():
	#print("/RESET_LOGINS() CALLED")
	app.logger.warning("/RESET_LOGINS() CALLED")

	cursor = db.cursor()
	cursor.execute("DELETE FROM users")
	db.commit()
	cursor.close()
	return { "status": "OK" }, 200

# Adduser
@app.route('/adduser', methods=["POST"])
def add_user():
	#print(80*'=')
	#print("/ADDUSER() CALLED")
	data = request.json
	#print("DATA: ", str(data))
	app.logger.debug("/adduser data: " + json.dumps(data))

	if data is None:
		#print("error: DATA IS NONE")
		app.logger.debug("/adduser no data specified")
		return { "status" : "error" , "error": "No data specified" }, 400

	if "username" not in data or "password" not in data or "email" not in data:
		#print("error: IMPROPER DATA")
		app.logger.debug("/adduser not all data fields found")
		return { "status" : "error", "error": "Not all data fields were found" }, 400

	uname = data["username"]

	email = data["email"]
	res = EMAIL_REGEX.match(email)

	if res == None:
		#print("error: BAD EMAIL REGEX MATCH")
		return { "status" : "error" }, 400

#	if check_email(email, cursor):
#		#print("error: DATABASE CHECK EMAIL FAILED")
#		return { "status" : "error", "error": "Email already in use" }, 400
#
#	app.logger.debug("/adduser email {} check passed".format(data['email']))
#
#	if check_user(uname, cursor):
#		#print("error: DATABASE CHECK USERNAME FAILED")
#		return { "status" : "error", "error": "Username taken" }, 400
#
#	app.logger.debug("/adduser user {} check passed".format(data['username']))

	hashed = bcrypt.hashpw(data["password"].encode('utf8'), bcrypt.gensalt())
	hashed = hashed.decode('utf-8')

	usr = { "username" : uname,
		"email" : email,
		"password" : data["password"],
		"password_hash" : hashed,
		"validated" : False
		}

	cursor = db.cursor(dictionary=True)
	try:
		sql = "INSERT IGNORE INTO users (username, email, password_hash) VALUES (%s, %s, %s)"
		#print(type(hashed))
		val = (uname, email, hashed)

		cursor.execute(sql, val)
		db.commit()

		if cursor.rowcount == 0:
			error = "{} <{}> already in use".format(data['username'], data['email'])
			#print("/adduser {} <{}> not unique".format(data['username'], data['email']))
			app.logger.debug("/adduser {} <{}> not unique".format(data['username'], data['email']))
			return { "status" : "error", "error": error }, 400

		# Check email is in database
		if check_email(email, cursor):
			app.logger.debug("/adduser {} <{}> found in database".format(data['username'], data['email']))
		else:
			app.logger.debug("/adduser {} <{}> not in database".format(data['username'], data['email']))
	finally:
		cursor.close()

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

	app.logger.info("/adduser user {} email sent".format(data['username']))

	return { "status" : "OK" }, 200

# Verify
@app.route("/verify", methods=["POST"])
def verify_user():
	#print(80*'=')
	#print("/VERIFY() CALLED")
	data = request.json
	app.logger.debug("/verify data: " + json.dumps(data))

	if "email" not in data or "key" not in data:
		return { "status" : "error", "error": "Email or key not specified in request" }, 200 #400

	email = data["email"]
	token = data["key"]

	cursor = db.cursor(dictionary=True)
	try:
		# Check email is in database
		if check_email(email, cursor) == False:
			#print("error: DATABASE CHECK EMAIL FAILED")
			app.logger.debug("/verify email not found in database <{}>".format(data['email']))
			return { "status" : "error", "error": "Email not found" }, 400

		app.logger.debug("/verify email check passed <{}>".format(data['email']))

		# skip check if backdoor used
		if token != "abracadabra":
			try:
				ret = confirm_token(token)
				#print("CONF_TOKEN:", ret)
				if email != ret:
					#print("WEE WOO WEE WOO BAD EMAIL")
					app.logger.debug("/verify email {} key failed".format(data['email']))
					return { "status" : "error", "error" : "Bad email or key" }, 400
			except Exception as e:
				#print(e)
				app.logger.debug("/verify email unknown error <{}>".format(data['email']))
				app.logger.debug(e)
				return { "status" : "error", "error": "Contact a developer" }, 400

		app.logger.debug("/verify email successful <{}>".format(data['email']))

		#print("VERIFY: ", str(email))
		sql = "UPDATE users SET validated = 1 WHERE email = %s"
		cursor.execute(sql, (email,))
		db.commit()
	finally:
		cursor.close()

	app.logger.debug("/verify email now verified <{}>".format(data['email']))

	return { "status" : "OK"}, 200

# Login
@app.route('/login', methods=["POST"])
def login():
	#print(80*'=')
	#print("/LOGIN() CALLED")
	creds = request.json
	#print("CREDS:", creds)
	app.logger.debug("/login creds: " + json.dumps(creds))

	db_user = None
	cursor = db.cursor(dictionary=True)
	try:
		# Get user info
		db_user = get_user(creds['username'], cursor)

		# User does not exist
		if not db_user:
			#print("NO USER")
			app.logger.debug("/login user {} not found".format(creds['username']))
			return { "status" : "error", "error" : "Username not found" }, 400

		# #print("USER VALID", str(user['validated']))
		app.logger.debug("/login user {} exists".format(creds['username']))

		if not db_user['validated']: 
			#print("NOT VALIDATED")
			app.logger.debug("/login user {} not validated".format(creds['username']))
			return { "status" : "error", "error" : "User has not been validated" }, 400
	finally:
		cursor.close()

	app.logger.debug("/login user {} validated".format(creds['username']))
	
	if bcrypt.checkpw(creds['password'].encode('utf8'), db_user['password_hash'].encode('utf8')):
		#print("LOGIN GOOD")
		app.logger.debug("/login user {} good password".format(creds['username']))
	else:
		app.logger.debug("/login user {} bad password".format(creds['username']))
		return { "status" : "error", "error" : "Incorrect password" }, 400

	app.logger.debug("/login user {} login good".format(creds['username']))

	return { "status" : "OK", "username": creds['username'] }, 200

## Logout
#@app.route('/logout', methods=["POST"])
#def logout():
#	session.clear()
#	return { "status" : "OK"}, 200

if __name__ == "__main__":
	print("main")
	gmail = Gmail()
	gmail.get_credentials()
	app.run()
