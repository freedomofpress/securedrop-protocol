import os
import sqlite3

class JournalistDatabase():

    def __init__(self, path):
        self.path = path
        self.is_valid = os.path.isfile(self.path)
        self.con = sqlite3.connect(self.path)
        if self.is_valid == False:
            try:
                self.create()
            except sqlite3.OperationalError:
                pass

    def __del__(self):
        self.con.close()

    def create(self):
        cur = self.con.cursor()
        cur.execute("CREATE TABLE messages (sender TEXT NOT NULL, timestamp TEXT NOT NULL, content TEXT NOT NULL);")
        self.con.commit()

    def select_messages(self, sender):
        cur = self.con.cursor()
        cur.execute("SELECT timestamp, content FROM messages WHERE sender = ? ORDER BY timestamp;", (sender,))
        rows = cur.fetchall()
        messages = rows if len(rows) > 0 else []
        self.con.commit()
        return messages

    def insert_message(self, sender, timestamp, content):
        cur = self.con.cursor()
        cur.execute("INSERT INTO messages (sender, timestamp, content) VALUES (?,?,?);", (sender, timestamp, content))
        self.con.commit()
        return cur.lastrowid

    """
    def delete_message(self, message_id):
        cur = self.con.cursor()
        cur.execute("DELETE FROM messages WHERE message_id = ?;", message_id)
        self.con.commit()
    """
