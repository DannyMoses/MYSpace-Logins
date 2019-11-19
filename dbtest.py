import mysql.connector

mydb = mysql.connector.connect(
	host="10.142.0.9",
	user="service",
	passwd="yoshi",
	database="Users"
)

mycursor = mydb.cursor()

x = mycursor.execute("SELECT username FROM users WHERE username='test1'")

for x in mycursor:
	print(x)
	print("test1" in x)
