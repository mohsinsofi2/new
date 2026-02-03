import os
import sqlite3

db_name = "checkerdata.db" # ⚠ Don't change the name of the database


if not os.path.exists(db_name):
    conn = sqlite3.connect(db_name)
    conn.close()

    print(f"📝 Database created : {db_name} [Bot data storage].")
else:
    print(f"✅ Database [ {db_name} ] Exists")

conn = sqlite3.connect('checkerdata.db')
cur = conn.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cur.fetchall()

cur.close()
conn.close()

tablesname = [table[0] for table in tables]

if "Users" in tablesname:
    print("✅ Table already exists - Users [ Users data storage ]")
else:
    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("CREATE TABLE Users (user_id INTEGER, state TEXT, post TEXT);")

    conn.commit()
    cur.close()
    conn.close()

    print("📝 Table created - Users [ Users data storage ]")

if "Groups" in tablesname:
    print("✅ Table already exists - Groups [ Groups chat-id and link storage ]")
else:
    conn = sqlite3.connect("checkerdata.db")
    cur = conn.cursor()

    cur.execute("CREATE TABLE Groups (chatid INTEGER, link TEXT);")

    conn.commit()
    cur.close()
    conn.close()

    print("📝 Table created - Groups [ Groups chat-id and link storage ]")

print("✅ Database setup complete !")