from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from pymongo import MongoClient
import bcrypt
import re

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

client = MongoClient('mongodb://localhost:27017/')
db = client['mydatabase']
users_collection = db['users']

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('profile'))
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password'].encode('utf-8')

    existing_user = users_collection.find_one({'username': username})
    if existing_user:
        return jsonify({'error': 'Kullanıcı zaten mevcut!'})

    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    users_collection.insert_one({'username': username, 'password': hashed_password})
    
    session['username'] = username
    return redirect(url_for('profile'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password'].encode('utf-8')

    user = users_collection.find_one({'username': username})
    if user and bcrypt.checkpw(password, user['password']):
        session['username'] = username
        return redirect(url_for('profile'))
    else:
        return jsonify({'error': 'Geçersiz kullanıcı adı veya şifre!'})

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/save_text', methods=['POST'])
def save_text():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    username = session['username']
    # user_text = request.form['user_text']
    user_text = request.form['metinAlani']
    user_text = re.sub(r">\s+<", '><', user_text)
    user_text=user_text.strip()
    text_name = request.form['text_name']
    
    # Kullanıcı ile ilişkilendirilmiş metni veritabanına kaydet
    users_collection.update_one({'username': username}, {'$push': {'texts': {'name': text_name, 'content': user_text}}})
    
    return redirect(url_for('profile'))

@app.route('/get_text/<text_name>')
def get_text(text_name):
    if 'username' not in session:
        return redirect(url_for('index'))
    
    username = session['username']
    
    # Kullanıcı ile ilişkilendirilmiş metni veritabanından al
    user = users_collection.find_one({'username': username})
    texts = user.get('texts', [])
    for text in texts:
        if text['name'] == text_name:
            return text['content']
    
    return 'Metin bulunamadı'

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    username = session['username']
    
    # Kullanıcı ile ilişkilendirilmiş metinleri veritabanından al
    user = users_collection.find_one({'username': username})
    texts = user.get('texts', [])
    
    return render_template('rightclick.html', username=username, texts=texts)


if __name__ == '__main__':
    app.run(debug=True)
