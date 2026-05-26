from flask import Flask, request, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
import bcrypt

app = Flask(__name__)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"]
)

# DATABASE CONFIGURATION
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://projectuser:project123@localhost/securetaskdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT SECRET KEY
app.config['JWT_SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# USER MODEL
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(255))
    role = db.Column(db.String(20), default='user')

# TASK MODEL
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))

# HOME PAGE
@app.route('/')
def home():
    return redirect('/login')

# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']
        if len(password) < 6:
            return "Password must be at least 6 characters"

        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        )

        new_user = User(
            username=username,
            password=hashed_password.decode('utf-8')
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect('/login')

    return render_template('register.html')

# LOGIN
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(
            password.encode('utf-8'),
            user.password.encode('utf-8')
        ):

            if user.role == 'admin':
                return redirect('/admin')

            return redirect('/dashboard')

        return "Invalid username or password"

    return render_template('login.html')

# DASHBOARD
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():

    if request.method == 'POST':

        title = request.form['title']

        task = Task(title=title)

        db.session.add(task)
        db.session.commit()

    tasks = Task.query.all()

    return render_template('dashboard.html', tasks=tasks)

# DELETE TASK
@app.route('/delete/<int:id>')
def delete_task(id):

    task = Task.query.get(id)

    db.session.delete(task)
    db.session.commit()

    return redirect('/dashboard')

# ADMIN PAGE
@app.route('/admin')
def admin():

    users = User.query.all()
    tasks = Task.query.all()

    return render_template(
        'admin.html',
        users=users,
        tasks=tasks
    )

# CREATE TABLES
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
