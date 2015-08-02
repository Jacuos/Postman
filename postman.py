# all the imports
from __future__ import print_function
import os
import random
import re
import sqlite3
import string
import time
import hashlib
import datetime
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash
from contextlib import closing
from jinja2 import utils
from flask_mail import Mail, Message
from werkzeug.routing import Map, Rule, NotFound, RequestRedirect

ATTEMPT = 5

# create our little application :)
app = Flask(__name__)
app.config.from_pyfile('conf.py')
mail = Mail(app)

def connect_db():
    return sqlite3.connect(app.config['DATABASE'])

def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def query_db(query, args=(), commit=False, single=False):
    cur = get_db().cursor()
    cur.execute(query, args)
    if commit:
        get_db().commit()
        return cur.rowcount
    elif single:
        return cur.fetchone()
    else:
        return cur.fetchall()
	
def get_db():
    db = getattr(g, 'postman.db', None)
    if db is None:
        db = g._database = sqlite3.connect(os.path.join(app.root_path, 'postman.db'))
    return db
	
# Połączenie z bazą danych i zamykanie jej
@app.before_request
def before_request():
    g.db = connect_db()

@app.teardown_request
def teardown_request(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()

@app.route('/')
def show_entries():
    cur = g.db.execute('select username, title, text from entries order by id desc')
    entries = [dict(username=row[0],title=row[1], text=row[2]) for row in cur.fetchall()]
    return render_template('show_entries.html', entries=entries)

@app.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    g.db.execute('insert into entries (username,title, text) values (?, ?, ?)',
                 [session.get('username'), request.form['title'], str(utils.escape(request.form['text']))])
    g.db.commit()
    flash('Nowa wiadomość została dodana.')
    session['info'] = None
    return redirect(url_for('show_entries'))

@app.route('/login/', methods=['GET', 'POST'])
@app.route('/login/<dev>', methods=['GET', 'POST'])
def login(dev=None):
    session['info'] = None
    error = None
    username = 'a'
    password = 'b'
    password_in = 'c'
    lastTimeLog = 0
    ip = request.remote_addr
    data = query_db('SELECT * FROM logs WHERE ip = ?',  (ip,), single=True)
    if request.method == 'POST':
        if data ==None:
            g.db.execute('insert or replace into logs (ip) values (?)',[ip])
            g.db.commit()
            data = query_db('SELECT * FROM logs WHERE ip = ?',  (ip,), single=True)
        
        if data[1] == ATTEMPT:
            g.db.execute('update logs set bantime =? where ip = ?',[time.time(),ip])
            g.db.commit()
            error = 'Przekroczono limit prób z danego ip!'

        elif (time.time() - data[2]) > 120 and data[1] > ATTEMPT:
            g.db.execute('update logs set addcount =?, bantime =? where ip = ?',[0,0,ip])
            g.db.commit()
            data = query_db('SELECT * FROM logs WHERE ip = ?',  (ip,), single=True)
        if data[1] > ATTEMPT:
            error = 'Przekroczono limi prób z danego ip!'
        
        lastTimeLog = data[3]
        if not data[1] >= ATTEMPT:
            
            if not re.match('^[a-z0-9A-Z]{3,30}$', request.form['username']):
                error = 'Login może się składać wyłącznie z liter i cyfr!'
            elif not re.match('^[a-z0-9A-Z]{3,30}$', request.form['password']):
                error = 'Hasło może się składać wyłącznie z liter i cyfr!'
            else:
                time.sleep(2)
                data = query_db('SELECT * FROM users WHERE username = ?',  (request.form['username'],), single=True)
                if data != None:
                    username = data[1]
                    password = data[3]
                    password_in =  hash_string(request.form['password'], data[4])
                if request.form['username'] != username:
                    error = 'Niepoprawny login'
                elif password_in != password:
                    error = 'Niepoprawne hasło'	    
                else:
                    sess = query_db('SELECT * FROM sessions WHERE username = ?',  (username,), single=True)
                    if sess != None : #and sess[0] != ip   - dodajemy jeśli chcemy wykrywać tylko kolizje z różnych ip!!
                        sendWarn(ip,username,sess)
                    g.db.execute('insert into sessions (ip, username) values (?,?)',[ip,username])
                    g.db.commit()
                    session['logged_in'] = True
                    session['username'] = username
                    flash('Zostałeś zalogowany')
                    return redirect(url_for('show_entries'))
                    
    if time.time() - lastTimeLog > 1800:
        g.db.execute('update logs set addcount =?, bantime =? where ip = ?',[0,0,ip])
        g.db.commit()
    if error != None:
        data = query_db('SELECT * FROM logs WHERE ip = ?',  (ip,), single=True)
        addcount = data[1]+1
        g.db.execute('update logs set addcount =? where ip = ?',[addcount,ip])
        g.db.commit()     
    g.db.execute('update logs set pause = ? where ip = ?',[time.time(),ip])
    g.db.commit()
    return render_template('login.html', error=error, dev=dev)

@app.route('/logout')
def logout():
    g.db.execute('delete from sessions where ip =? and username = ?',[request.remote_addr,session['username']])
    g.db.commit()
    session.pop('logged_in', None)
    flash('Wylogowano')
    return redirect(url_for('show_entries'))

@app.route('/check',methods=['GET', 'POST'])
def check():

    data = query_db('SELECT * FROM users WHERE username = ?',('Jan',), single=True)
    return '%s %s %s %s %s' % (data[0],data[1],data[2],data[3],data[4])

@app.route('/register', methods=['GET','POST'])
def register():
    session['info'] = None
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password2 = request.form['password2']
        email = request.form['email']
        if query_db('SELECT * FROM users WHERE username = ?',  (username,), single=True):
            error = 'nazwa użytkownika zajęta'
        elif not re.match('^[a-z0-9A-Z]{3,30}$', username):
            error = 'login powinien się składać z od 3 do 30 liter lub cyfr'
        elif not re.match('^.+@.+\.[a-z]{2,4}$', email):
            error = 'niepoprawny adres e-mail'
        elif not re.match('^[a-z0-9A-Z]{3,30}$', password):
            error = 'hasło powinno się składać z od 3 do 30 liter lub cyfr'
        elif not re.match('^[a-z0-9A-Z]{3,30}$', password2):
            error = 'hasło powinno się składać z od 3 do 30 liter lub cyfr'
        elif password != password2:
            error = 'hasła do siebie nie pasują'
        else:
            salt = random_string(8)
            password_hashed = hash_string(password, salt)
            g.db.execute('insert into users (username,password,email,salt) values (?,?,?,?)',[request.form['username'],  password_hashed, request.form['email'],salt])
            g.db.commit()
            return redirect(url_for('login'))
    return render_template('register.html', error=error)
    
@app.route('/remind',methods=['GET','POST'])
def remind():
    error = None
    username = 'a'
    email = 'b'
    if request.method == 'POST':
        if not re.match('^[a-z0-9A-Z]{3,30}$', request.form['username']):
            error = 'Login może się składać wyłącznie z liter i cyfr!'
        elif not re.match('^.+@.+\.[a-z]{2,4}$', request.form['e-mail']):
            error = 'niepoprawny adres e-mail'
        else:
            data = query_db('SELECT * FROM users WHERE username = ?',  (request.form['username'],), single=True)
            if data != None:
                username = data[1]
                email = data[2]
            if request.form['username'] != username:
                error = 'Niepoprawna nazwa użytkownika!'
            elif request.form['e-mail'] != email:
                error = 'Niepoprawny e-mail!'
            else:
                url = 'https://127.0.0.1:5000/reset/'+str(data[0])+data[4]
                msg = Message("Przypomnienie hasła",
                sender='jacuos2@gmail.com')
                msg.body = 'Hej! W alikacji Postman zgłoszono zagubienie hasła do twojego konta. \n Jeżeli to faktycznie ty zapomniałeś hasła, kliknij w poniższy link aktywacyjny. Będziesz mógł tam podać nowe hasło. \n Jeżeli nie zapomniałeś hasła i nic nie klikałeś, zignoruj to.\n '+url
                msg.html = '<b>HTML</b>Hej! W alikacji Postman zgłoszono zagubienie hasła do twojego konta. \n Jeżeli to faktycznie ty zapomniałeś hasła, kliknij w poniższy link aktywacyjny. Będziesz mógł tam podać nowe hasło. \n Jeżeli nie zapomniałeś hasła i nic nie klikałeś, zignoruj to. \n '+url          
                msg.recipients= [email]
                mail.send(msg)
                return redirect(url_for('login',dev='Mail wysłany'))
    return render_template('remind.html',error=error)
    
@app.route('/reset/<req>',methods=['GET','POST'])
def reset(req):
    error=None
    table = list(req)
    if request.method == 'POST':
        data = query_db('SELECT * FROM users WHERE user_id = ?',(table[0],), single=True) 
        if data[4] == (''.join(table[1:])):
            if not re.match('^[a-z0-9A-Z]{3,30}$', request.form['password']):
                error = 'Hasło może się składać wyłącznie z liter i cyfr!'
            elif not re.match('^[a-z0-9A-Z]{3,30}$', request.form['password2']):
                error = 'Hasło może się składać wyłącznie z liter i cyfr!'
            elif not request.form['password'] == request.form['password2']:
                error= 'Wpisane hasła nie są zgodne'
            else:
                salt = random_string(8)
                password_hashed = hash_string(request.form['password'], salt)
                g.db.execute('update users set password =?, salt =? where user_id = ?',[password_hashed,salt,data[0]])
                g.db.commit()            
                return redirect(url_for('login',dev='Hasło zmienione')) 
        else:
            error = 'Niepoprawna próba zmiany hasła. Wynocha marny hakerze!'
    return render_template('reset.html',req=req,error=error)
    
@app.route('/change',methods=['GET','POST'])
def change():
    error=None
    if request.method == 'POST' and  session['logged_in'] == True:
        data = query_db('SELECT * FROM users WHERE username = ?',(session['username'],), single=True)
        if not re.match('^[a-z0-9A-Z]{3,30}$', request.form['newPassword']):
            error = 'Hasło może się składać wyłącznie z liter i cyfr!'
        
            if data[3] == hash_string(request.form['oldPassword'], data[4]):
                if not re.match('^[a-z0-9A-Z]{3,30}$', request.form['newPassword']):
                    error = 'Hasło może się składać wyłącznie z liter i cyfr!'
                elif not re.match('^[a-z0-9A-Z]{3,30}$', request.form['newPassword2']):
                    error = 'Hasło może się składać wyłącznie z liter i cyfr!'
                elif not request.form['newPassword'] == request.form['newPassword2']:
                    error= 'Wpisane hasła nie są zgodne'
                else:
                    salt = random_string(8)
                    password_hashed = hash_string(request.form['newPassword'], salt)
                    g.db.execute('update users set password =?, salt =? where username= ?',[password_hashed,salt,data[1]])
                    g.db.commit()   
                    session['info'] = 'Zmieniono hasło.'
                    return redirect(url_for('show_entries'))
            else:
                error = 'Podane stare hasło jest niepoprawne!'
    return render_template('change.html',error=error)
    
def random_string(n):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def hash_string(text, salt):
    hashed = hashlib.md5(text.encode() + salt.encode()).hexdigest()
    for i in range(9):
        hashed = hashlib.md5(hashed.encode() + salt.encode()).hexdigest()

    return hashed
    
def sendWarn(ip,username,old):
    data = query_db('SELECT * FROM users WHERE username = ?',  (username,), single=True)
    msg = Message("Ostrzeżenie dla "+old[1],
                sender='jacuos2@gmail.com')
    when = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
    whoAlready = old[0]
    whoNew = ip
    msg.body = 'Zauważono podejrzaną aktywność użytkownika w aplikacji Postman. \n Czas incydentu: '+when+' \n Wystąpiły dwie sesje tego samego konta. Może to świadczyć o dokonanym przejęciu konta. Poniżej podane są numery IP związane ze zdarzeniem. \n'+'Użytkownik zalogowany wcześniej: '+whoAlready+' \n Użytkownik który stworzył kolizję:'+whoNew
    msg.recipients= [data[2]]
    mail.send(msg)
    return None
    
# XSRF - Losowanie tokena dla sesji, pakowanie go do hidden fields, sprawdzanie przy każdym requeście  
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(403)
        else:
            print('\n\n'+token+'\n\n')

def generate_csrf_token():
    if '_csrf_token' not in session:
        rand = random_string(10)
        salt = random_string(5)
        session['_csrf_token'] = rand+salt
    return session['_csrf_token']


  

#Odpalamy apkę
if __name__ == '__main__':
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    rand = random_string(10)
    salt = random_string(5)
    app.secret_key = hash_string(rand,salt)
    app.run(host='127.0.0.1', ssl_context=('ssl/server.crt', 'ssl/server.key'))
    init_db()
    session['logged_in'] = False
