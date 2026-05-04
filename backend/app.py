# request for incoming HTTP requests; jsonify for sending JSON response; session for server-side sessions
from flask import Flask, request, jsonify, session
from flask_cors import CORS #Cross-Origin Resource Sharing - frontend to backend
from flask_bcrypt import Bcrypt # Handle password hashing and verification
from flask_sqlalchemy import SQLAlchemy #ORM (Object Relational Mapping)
import jwt # PyJwt Library, create and decode JSON Web Tokens for auth
import datetime #Handle exp times for JWT tokens
import os 
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__) #init Flask app
#Config
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") #Secret key to secure sessionns and by PyJWT to sign tokens. TEMP.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db' # Config db URI for alch. Point to SQLite db (site.db)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False #No need to track mods; 
 
#Init
db = SQLAlchemy(app) #Init SQLA ORM 

# Allow requests for any routes w/ /api/*
CORS(app, resources={r"/api/*": {"origins":"http://localhost:5173"}}, supports_credentials=True) # Allow cookies/auth headers to be sent

bcrypt = Bcrypt(app) # Init Bcrypt for pw hashing and verification

#After every CORS request
@app.after_request #Decorator
# CORS-related headers to response. More specific/explicit.
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = 'http://localhost:5173'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
#db model = User 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # un and pw can't be null
    username = db.Column(db.String(30), unique=True, nullable=False) #30 keys max, must be unique
    password = db.Column(db.String(60), nullable=False) #60 keys max
    # One-to-many r/s; lazy=true (load when needed)
    flashcards = db.relationship('Flashcard', backref='author', lazy=True) #author attr. for each card.
#db model/table = flashcard
class Flashcard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # quest/answ = text (longer than string), can't be null
    question = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)
    # foreign key referencing id col in user table. Links card to author (user)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create all tables in db's if they DNE already. 
with app.app_context():
    db.create_all()

# Helper func; gen's JWT for a username
def gen_token(username):
    #payload for token
    payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours = 1) #1-hour expiration
    }
    #encodes payload using serer's secret key w/ HS256 algo
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token 

#Decorator func - ensure valid JWT token
def token_required(f): 
    # wrapper wil replace og func f
    def wrapper(*args, **kwargs):
        #Handle OPTIONS requests
        if request.method == 'OPTIONS':
            return f(*args, **kwargs)


        token = None #init token as None

        #JWT is passed in the request headers: Authorization: Bearer<token>
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1] #take 2nd part [1] as the token

        if not token:
            return jsonify({'message': 'Token is missing'}), 403 #Forbidden status code

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256']) #Decode token w/ secret key
            current_user = User.query.filter_by(username=data['username']).first() #Find matching username db
            #If user DNE 
            if not current_user:
                return jsonify({'message': 'User not found'}), 403 #Forbidden Status Code
        except:
            return jsonify({'message': 'Token is invalid or expired'}), 403 #Forbidden Status Code

        # Call og func f
        return f(current_user, *args, **kwargs)
    wrapper.__name__ = f.__name__ #Perserve og func name
    return wrapper #protected vs. of f


# AUTHENTICATION APIS

# Register
@app.route('/register', methods = ['POST'])
def register():
    # Extract JSON data from request body
    data = request.get_json() 
    #Get username and password fields from JSON data (data)
    username = data['username']
    password = data['password']

    current_user = User.query.filter_by(username=username).first()
    if current_user:
        return jsonify({'message': 'Username already exists'}), 400 #Bad Request status code (invalid input)
    #Hash pw w/ Bcrypt; decode from bytes to str
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8') #hash->decoding
    #Create and save new user
    user = User(username=username, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'Registration successful'}), 201 #Created status code

# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'message': 'User does not exist'}), 404 #User not found (not registered)
    #Check password w/ Bcrypt
    if bcrypt.check_password_hash(user.password, password):
        token = gen_token(username) #gen JWT 
        return jsonify({'token': token}), 200 #OK
    else:
        return jsonify({'message': 'Wrong password'}), 401 #Unauthorized 

# DATA APIs (protected - @token_required)
@app.route('/api/flashcards', methods=['GET'])
@token_required
#current_user protected from protected route
def get_flashcards(current_user):
    flashcards = Flashcard.query.filter_by(user_id=current_user.id).all() # Fetch all flashcards
    # Return list of dictionaries ((id, question, answer) foreach card in flashcards)
    return jsonify([{
        'id': card.id,
        'question': card.question,
        'answer': card.answer,
    } for card in flashcards])

@app.route('/api/flashcards', methods=['POST'])
@token_required
def add_flashcard(current_user):
    data = request.json
    # If no answer and/or question written, can't be saved 
    if not data or 'question' not in data or 'answer' not in data:
        return jsonify({'error': 'Missing question or answer'}), 400 #Bad input
    # init new_flashcard
    new_flashcard = Flashcard(
        question = data['question'],
        answer=data['answer'],
        user_id=current_user.id #Use current_user's id as user_id for card
    )
    # Add and save
    db.session.add(new_flashcard)
    db.session.commit()
    # Return card in json
    return jsonify({
        'id': new_flashcard.id,
        'question': new_flashcard.question,
        'answer': new_flashcard.answer
    }), 201 # Created

@app.route('/api/flashcards/<int:id>', methods=['DELETE'])
@token_required
def delete_flashcard(current_user, id):
    #Delete a flashcard from session by ID
    flashcard = Flashcard.query.filter_by(id=id, user_id=current_user.id).first() #Find user's flashcard
    #If card DNE
    if not flashcard:
        return jsonify({'error': 'Card not found'}), 404 # Not Found
    # Delete card from session and commit
    db.session.delete(flashcard) 
    db.session.commit()
    return jsonify({'message': 'Card deleted'}), 200 #OK

# Home route (Up and running)
@app.route('/')
def index():
    return 'Hello World!'
# Entry point 
if __name__ == '__main__':
    app.run(debug=True)