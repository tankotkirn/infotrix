from flask import Flask, render_template, request, redirect, session
from pymongo import MongoClient
from bcrypt import hashpw, gensalt, checkpw

app = Flask(__name__)
app.secret_key = "secret_key"

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['user_registration_system']
users_collection = db['users']


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if the username or email already exists
        if users_collection.find_one({"$or": [{"username": username}, {"email": email}]}):
            return "Username or email already exists!"

        # Hash the password
        hashed_password = hashpw(password.encode('utf-8'), gensalt())

        # Create a new user document
        user = {
            'username': username,
            'email': email,
            'password': hashed_password
        }
        
        # Insert the user document into the collection
        users_collection.insert_one(user)

        return redirect('/login')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Retrieve the user document based on the provided username
        user = users_collection.find_one({'username': username})

        # Check if the user exists and verify the password
        if user and checkpw(password.encode('utf-8'), user['password']):
            # Store the user's session data
            session['username'] = user['username']
            session['email'] = user['email']
            return redirect('/profile')
        else:
            return "Invalid username or password!"

    return render_template('login.html')


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' in session:
        if request.method == 'POST':
            new_username = request.form['username']
            new_email = request.form['email']
            new_password = request.form['password']
            
            # Update the user document with the new data if provided
            update_data = {}
            
            if new_username:
                update_data['username'] = new_username
            
            if new_email:
                update_data['email'] = new_email
            
            if new_password:
                hashed_password = hashpw(new_password.encode('utf-8'), gensalt())
                update_data['password'] = hashed_password
            
            # Update the user document
            users_collection.update_one({'username': session['username']}, {"$set": update_data})
            
            # Update the session data if the username was changed
            if new_username:
                session['username'] = new_username
            
            return redirect('/profile')

        return render_template('profile.html')
    else:
        return redirect('/login')


@app.route('/logout')
def logout():
    # Clear the user's session data
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
