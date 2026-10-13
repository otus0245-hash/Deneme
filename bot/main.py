import sqlite3, time

con = sqlite3.connect("test.db")
con.execute("CREATE TABLE IF NOT EXISTS kullanicilar (id INTEGER PRIMARY KEY, isim TEXT, puan INTEGER)")
con.execute("INSERT INTO kullanicilar (isim, puan) VALUES ('Ali', 10), ('Ayşe', 25)")
con.commit()
con.close()

print("Veritabani hazir", flush=True)
time.sleep(60)