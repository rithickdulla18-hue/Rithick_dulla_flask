# Flask Task Management System - Hiring Assessment

# A complete CRUD application with authentication

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import os

app = Flask(**name**)
app.config[‘SECRET_KEY’] = ‘your-secret-key-here-change-in-production’
app.config[‘SQLALCHEMY_DATABASE_URI’] = ‘sqlite:///tasks.db’
app.config[‘SQLALCHEMY_TRACK_MODIFICATIONS’] = False

db = SQLAlchemy(app)

# Database Models

class User(db.Model):
id = db.Column(db.Integer, primary_key=True)
username = db.Column(db.String(80), unique=True, nullable=False)
email = db.Column(db.String(120), unique=True, nullable=False)
password = db.Column(db.String(200), nullable=False)
created_at = db.Column(db.DateTime, default=datetime.utcnow)
tasks = db.relationship(‘Task’, backref=‘owner’, lazy=True, cascade=‘all, delete-orphan’)

class Task(db.Model):
id = db.Column(db.Integer, primary_key=True)
title = db.Column(db.String(200), nullable=False)
description = db.Column(db.Text, nullable=True)
status = db.Column(db.String(20), default=‘pending’)  # pending, in_progress, completed
priority = db.Column(db.String(20), default=‘medium’)  # low, medium, high
due_date = db.Column(db.Date, nullable=True)
created_at = db.Column(db.DateTime, default=datetime.utcnow)
updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
user_id = db.Column(db.Integer, db.ForeignKey(‘user.id’), nullable=False)

# Decorator for login required

def login_required(f):
@wraps(f)
def decorated_function(*args, **kwargs):
if ‘user_id’ not in session:
flash(‘Please login to access this page.’, ‘warning’)
return redirect(url_for(‘login’))
return f(*args, **kwargs)
return decorated_function

# Routes

@app.route(’/’)
def index():
if ‘user_id’ in session:
return redirect(url_for(‘dashboard’))
return render_template(‘index.html’)

@app.route(’/register’, methods=[‘GET’, ‘POST’])
def register():
if request.method == ‘POST’:
username = request.form.get(‘username’)
email = request.form.get(‘email’)
password = request.form.get(‘password’)
confirm_password = request.form.get(‘confirm_password’)

```
    # Validation
    if not username or not email or not password:
        flash('All fields are required!', 'danger')
        return redirect(url_for('register'))
    
    if password != confirm_password:
        flash('Passwords do not match!', 'danger')
        return redirect(url_for('register'))
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists!', 'danger')
        return redirect(url_for('register'))
    
    if User.query.filter_by(email=email).first():
        flash('Email already registered!', 'danger')
        return redirect(url_for('register'))
    
    # Create new user
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    flash('Registration successful! Please login.', 'success')
    return redirect(url_for('login'))

return render_template('register.html')
```

@app.route(’/login’, methods=[‘GET’, ‘POST’])
def login():
if request.method == ‘POST’:
username = request.form.get(‘username’)
password = request.form.get(‘password’)

```
    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['username'] = user.username
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid username or password!', 'danger')

return render_template('login.html')
```

@app.route(’/logout’)
@login_required
def logout():
session.clear()
flash(‘You have been logged out.’, ‘info’)
return redirect(url_for(‘index’))

@app.route(’/dashboard’)
@login_required
def dashboard():
user = User.query.get(session[‘user_id’])
tasks = Task.query.filter_by(user_id=user.id).order_by(Task.created_at.desc()).all()

```
# Statistics
total_tasks = len(tasks)
completed_tasks = len([t for t in tasks if t.status == 'completed'])
pending_tasks = len([t for t in tasks if t.status == 'pending'])
in_progress_tasks = len([t for t in tasks if t.status == 'in_progress'])

stats = {
    'total': total_tasks,
    'completed': completed_tasks,
    'pending': pending_tasks,
    'in_progress': in_progress_tasks
}

return render_template('dashboard.html', tasks=tasks, stats=stats)
```

@app.route(’/task/create’, methods=[‘GET’, ‘POST’])
@login_required
def create_task():
if request.method == ‘POST’:
title = request.form.get(‘title’)
description = request.form.get(‘description’)
priority = request.form.get(‘priority’)
due_date_str = request.form.get(‘due_date’)

```
    if not title:
        flash('Title is required!', 'danger')
        return redirect(url_for('create_task'))
    
    due_date = None
    if due_date_str:
        try:
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format!', 'danger')
            return redirect(url_for('create_task'))
    
    new_task = Task(
        title=title,
        description=description,
        priority=priority or 'medium',
        due_date=due_date,
        user_id=session['user_id']
    )
    
    db.session.add(new_task)
    db.session.commit()
    
    flash('Task created successfully!', 'success')
    return redirect(url_for('dashboard'))

return render_template('create_task.html')
```

@app.route(’/task/edit/<int:task_id>’, methods=[‘GET’, ‘POST’])
@login_required
def edit_task(task_id):
task = Task.query.get_or_404(task_id)

```
if task.user_id != session['user_id']:
    flash('Unauthorized access!', 'danger')
    return redirect(url_for('dashboard'))

if request.method == 'POST':
    task.title = request.form.get('title')
    task.description = request.form.get('description')
    task.status = request.form.get('status')
    task.priority = request.form.get('priority')
    
    due_date_str = request.form.get('due_date')
    if due_date_str:
        try:
            task.due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format!', 'danger')
            return redirect(url_for('edit_task', task_id=task_id))
    
    db.session.commit()
    flash('Task updated successfully!', 'success')
    return redirect(url_for('dashboard'))

return render_template('edit_task.html', task=task)
```

@app.route(’/task/delete/<int:task_id>’)
@login_required
def delete_task(task_id):
task = Task.query.get_or_404(task_id)

```
if task.user_id != session['user_id']:
    flash('Unauthorized access!', 'danger')
    return redirect(url_for('dashboard'))

db.session.delete(task)
db.session.commit()
flash('Task deleted successfully!', 'success')
return redirect(url_for('dashboard'))
```

@app.route(’/api/tasks’)
@login_required
def api_tasks():
“”“API endpoint to get tasks in JSON format”””
tasks = Task.query.filter_by(user_id=session[‘user_id’]).all()
return {
‘tasks’: [{
‘id’: task.id,
‘title’: task.title,
‘status’: task.status,
‘priority’: task.priority,
‘created_at’: task.created_at.isoformat()
} for task in tasks]
}

# Initialize database

with app.app_context():
db.create_all()

if **name** == ‘**main**’:
app.run(debug=True)
