import MySQLdb
print("SOMETHING")
mydb = MySQLdb.connect(
	host="10.142.0.9",
	user="service",
	passwd="yoshi",
	database="Users"
)

mycursor = mydb.cursor()
x = mycursor.execute("DELETE FROM users")
x = mycursor.execute("SELECT username FROM users WHERE username='test3'")

print(x)
for x in mycursor:
	print(x)
	if "21aGoxKSYQ" in x:
		print("FOUND ONE")
	else:
		print("NOT FOUND")

sql = "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)"
x = mycursor.execute(sql, ("test3", "test4", "test5"))
mydb.commit()
#
#y = mycursor.execute("SELECT validated FROM users WHERE username='test3'")
#
#for x in mycursor:
#	print(x[0])
#
#z = mycursor.execute("SELECT password_hash FROM users WHERE username='yang573'")
#
#for z in mycursor:
#	print(z)
