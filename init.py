# all the imports
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash
from contextlib import closing

app = Flask(__name__)

def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
def connect_db():
    return sqlite3.connect(app.config['postman.db'])
	
if __name__ == '__main__':
    init_db()
