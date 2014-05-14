# chat.py
import os
import logging
from flask import Flask, render_template, flash, url_for, redirect, abort, request, g
from flask_sockets import Sockets
from flask_login import *
from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask.ext.security import login_required
from flask.ext.login import login_user, logout_user, current_user
import random
import string
import json



# P = 2698727
P = 1000667
G = 98
NUM_CHALLENGES = 20
TOKEN_LEN = 6

app = Flask(__name__)
app.debug = 'DEBUG' in os.environ

sockets = Sockets(app)


challenges_dict = {}
half_logged_in = {}
token_dict1 = {}
token_dict2 = {}


from logging import StreamHandler
file_handler = StreamHandler()
app.logger.setLevel(logging.DEBUG)  # set the desired logging level here
app.logger.addHandler(file_handler)
app.secret_key = 'A0Zr965464fgfdsN]LWX/,?RC'



Base = declarative_base()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'
login_manager.setup_app(app)

@login_manager.user_loader
def load_user(username):
    dbsession = dbsetup('users')
    return dbsession.query(User).get(username)


@app.before_request
def before_request():
    # If the user is logged in, set the g.username 
    if current_user.is_authenticated():
        g.username = current_user.username







def dbsetup(name):
    thisdir = os.path.dirname(os.path.abspath(__file__))
    dbdir = os.path.join(thisdir, "db", name)
    if not os.path.exists(dbdir):
        os.makedirs(dbdir)

    dbfile = os.path.join(dbdir, "%s.db" % name)
    engine = create_engine('sqlite:///%s' % dbfile)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)
    return session()



class CryptoGroupGenerator:
  def __init__ (self, prime, gen):
    self.p = prime
    self.g = gen
  def add (self, x, y):
    return (x+y) % self.p
  def multiply (self, x, y):
    return (x*y) % self.p
  def powG (self, e):
    accum = self.g
    for i in xrange(1, e):
      accum = (accum * self.g) % self.p 
    return accum
  def pow (self, x, e):
    if e == 0:
      return 1
    accum = x
    for i in xrange(1, e):
      accum = (accum * x) % self.p 
    return accum

CryptoGroup = CryptoGroupGenerator(P, G)



class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key = True, unique=True)
    gx = Column(Integer)

    def __repr__(self):
        return "username=%s, gx=%d" \
            % (self.username, self.gx)

    # def __init__(self , username, gx):
    #     self.username = username
    #     self.gx = gx

    def is_authenticated(self):
        return True
 
    def is_active(self):
        return True
 
    def is_anonymous(self):
        return False
 
    def get_id(self):
        return self.username


def check_response(username, res):
  res = [int(i) for i in res]
  gx = challenges_dict[username][0]
  a = challenges_dict[username][1]
  chals = challenges_dict[username][2]
  for (x,y) in zip(res, chals):
    r = CryptoGroup.powG(x)
    truth = CryptoGroup.multiply(CryptoGroup.pow(gx, y), a)
    # app.logger.debug(r)
    # app.logger.debug(truth)
    if r != truth:
      return False

  return True



class ChallengeData:
  def __init__ (self, count, gx, gk):
    self.count = count
    self.gx = gx
    self.gk = gk
    self.c = 0
  
  def checkAndUpdate(self, res):
    res = int(res)
    r = CryptoGroup.powG(res)
    truth = CryptoGroup.multiply(CryptoGroup.pow(self.gx, self.c), self.gk)
    self.count = self.count + 1
    return r == truth

  def updateCommitment(self, newGk):
    self.gk = newGk  

  def generateNewC(self):
    newC = random.randint(0, 3)
    self.c = newC
    return 'CHALLENGE:' + str(newC)

  def getCount(self):
    return self.count





@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated():
        return render_template('home.html')
    if request.method == 'GET':
        return render_template('register.html')


    dbsession = dbsetup('users')
    if dbsession.query(User).get(request.form['username']) is not None:
      flash('Username already taken')
      return render_template('register.html')

    user = User()
    user.username = request.form['username']
    user.gx = int(request.form['gx'])

    dbsession.add(user)
    dbsession.commit()

    flash('User successfully registered')
    return render_template('index.html')
 


@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated():
        return render_template('home.html')
    if request.method == 'GET':
        return render_template('index.html')

    dbsession = dbsetup('users')
    username = request.form['username']
    token = request.form['token']
    user = dbsession.query(User).get(username)
    # if user.gx != token:
    if user is None:
      flash('Username or Token is invalid')
      return render_template('index.html')
    elif username not in half_logged_in.keys(): 
      if username in token_dict2.keys() and token == token_dict2[username]:
        del token_dict2[username]
        flash('You are being sniped. Please start over.')
        return render_template('index.html')
      if username not in token_dict1.keys() or token != token_dict1[username]:
        flash('Username or Token is invalid')
        return render_template('index.html')
      else: # if right token
        half_logged_in[username] = request.form['cookie']
        flash('Logged in halfway successfully.')
        return render_template('zkp.html')

    else: # if already half in
      cookie = half_logged_in[username]
      del half_logged_in[username]
      if token == token_dict1[username]:
        del token_dict1[username]
        flash('You are being sniped. Please start over.')
        return render_template('index.html')
      if username not in token_dict2.keys() or token != token_dict2[username]:
        flash('Username or Token is invalid')
        return render_template('index.html')
      else:
        del token_dict1[username]
        if cookie != request.form['cookie']:
          flash('You are being sniped. Please start over.')
          return render_template('index.html')
        del token_dict2[username]
        login_user(user, remember = True)
        g.username = current_user.username
        flash('Logged in successfully')
        return render_template('home.html')






@app.route('/zkp', methods=['GET','POST'])
def zkp():
    if current_user.is_authenticated():
        return render_template('home.html')
    if request.method == 'GET':
        return render_template('zkp.html')
    
    username = None
    commitment = None
    response = None

    cmd = request.form['command']
    if cmd == 'INITZKP':
      dbsession = dbsetup('users')

      try:
        username = request.form['username']
        commitment = int(request.form['commitment'])
      except ValueError:
        return 'NOUSER'

      user = dbsession.query(User).get(username)
      if user is None:
        # flash('Username is invalid')
        # render_template('index.html')
        return 'NOUSER'

      newCD = ChallengeData(0, user.gx, commitment)
      challenges_dict[username] = (newCD)
      return newCD.generateNewC()

    if cmd == 'ZKP':
      dbsession = dbsetup('users')

      try:
        username = request.form['username']
        commitment = int(request.form['commitment'])
        response = int(request.form['response'])

      except ValueError:
        if username in challenges_dict.keys():
          del challenges_dict[username]
        return 'FAIL'

      if (username not in challenges_dict.keys() or challenges_dict[username].checkAndUpdate(response) is not True):
        if username in challenges_dict.keys():
          del challenges_dict[username]
        return 'FAIL'

      if challenges_dict[username].getCount() >= NUM_CHALLENGES:
        del challenges_dict[username]
        if username in half_logged_in:
          token_dict2[username] = generate_token(TOKEN_LEN)
          return 'PASS:' + token_dict2[username]
        else:
          token_dict1[username] = generate_token(TOKEN_LEN)
          return 'PASS:' + token_dict1[username]
      else:
        challenges_dict[username].updateCommitment(commitment)
        return challenges_dict[username].generateNewC()


def generate_token (n):
  return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))




@app.route('/')
def server():
    if current_user.is_authenticated():
      return render_template('home.html')
    return render_template('index.html')



@app.route('/logout/')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/home')
@login_required
def home():
    return render_template('home.html')


