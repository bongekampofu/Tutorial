from decimal import Decimal
import os
import os.path as op
from datetime import datetime as dt
from sqlalchemy import Column, Integer, DateTime
from flask import Flask, render_template, send_from_directory, url_for, redirect, request
from flask_wtf import FlaskForm
#from flask_sqlalchemy import Pagination

from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired, Length, Email, EqualTo

from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.event import listens_for
from markupsafe import Markup
from flask_admin import Admin, form
from flask_admin.form import rules
from flask_admin.contrib import sqla, rediscli
from flask import session as login_session
from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import relationship
from sqlalchemy import select
from sqlalchemy import select
import operator
from werkzeug.utils import secure_filename
import os
from flask import Flask, flash, request, redirect, url_for
from werkzeug.utils import secure_filename
from sqlalchemy import update
from wtforms import PasswordField
#new imports
from sqlalchemy.ext.hybrid import hybrid_property

from jinja2 import TemplateNotFound  # Import TemplateNotFound exception
import logging

#for xml files
from xml.etree.ElementTree import Element, SubElement, tostring, ElementTree
from datetime import datetime as dt


admin = Admin()
app = Flask(__name__, static_folder='static')

# see http://bootswatch.com/3/ for available swatches
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\Bongeka.Mpofu\\DB Browser for SQLite\\tutor.db'


app.config['SECRET_KEY'] = 'this is a secret key '
app.config['SQLALCHEMY_ECHO'] = True
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max file size

db = SQLAlchemy(app)
login_manager.init_app(app)
admin.init_app(app)

#UPLOAD_FOLDER = 'static'
#app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

UPLOAD_FOLDER = os.path.join('static', 'uploads')  # Point to the uploads subfolder
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# moodels abd tables
class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class Tutorial(db.Model):
    __tablename__ = "tutorial"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    file_url = db.Column(db.String(200), nullable=False)  # Path to the file
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Quiz(db.Model):
    __tablename__ = "quiz"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    questions = db.relationship('Question', back_populates='quiz', lazy=True, cascade="all, delete")

class Question(db.Model):
    __tablename__ = "question"
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete="CASCADE"), nullable=False)
    text = db.Column(db.String(300), nullable=False)
    correct_answer = db.Column(db.String(100), nullable=False)
    options = db.Column(db.String(300), nullable=False)
    quiz = db.relationship('Quiz', back_populates='questions')


class Markbook(db.Model):
    __tablename__ = "markbook"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegistrationForm(FlaskForm):
    __tablename__ = "registrationform"
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    __tablename__ = "loginform"
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class TutorialForm(FlaskForm):
    __tablename__ = "tutorialform"
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    file = FileField('Upload File', validators=[FileAllowed(['pdf', 'docx', 'txt', 'jpg', 'png', 'ppt', 'pptx', 'doc', 'xls', 'xlsx', 'zip', 'rar', 'mp4', 'avi'], 'Only specific file types are allowed!')])
    submit = SubmitField('Upload Tutorial')



# Routes
@app.route("/")
def home():
    tutorials = Tutorial.query.all()
    return render_template("home.html", tutorials=tutorials)

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = LoginForm()
    if form.validate_on_submit():
        # Debugging Step: Print form data
        print("Email:", form.email.data)
        print("Password:", form.password.data)

        user = User.query.filter_by(email=form.email.data).first()

        # Debugging Step: Check if the user exists
        print("User Found:", user)

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login successful!', 'success')
            return redirect(url_for("home"))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')

    # Render the login page
    return render_template("login.html", form=form)



@app.route("/quiz/<int:quiz_id>", methods=["GET", "POST"])
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = quiz.questions

    if request.method == "POST":
        score = 0
        total_questions = len(questions)

        # Check each question
        for question in questions:
            user_answer = request.form.get(f"question-{question.id}")
            if user_answer and user_answer == question.correct_answer:
                score += 1

        # Calculate percentage
        score_percentage = (score / total_questions) * 100

        # Save progress
        progress = Progress(user_id=current_user.id, quiz_id=quiz.id, score=score_percentage)
        db.session.add(progress)
        db.session.commit()

        flash(f"You scored {score_percentage:.2f}%", "success")
        return redirect(url_for("progress"))

    return render_template("quiz.html", quiz=quiz, questions=questions)


@app.route("/progress")
@login_required
def progress():
    progress_records = Progress.query.filter_by(user_id=current_user.id).all()
    return render_template("progress.html", progress_records=progress_records)


@app.route("/create_sample_data")
def create_sample_data():
    # Add a quiz
    quiz = Quiz(title="Python Basics")
    db.session.add(quiz)
    db.session.commit()

    # Add questions
    question1 = Question(
        quiz_id=quiz.id,
        text="What is the output of print(2 * 3)?",
        correct_answer="6",
        options="6,23,5,None"
    )
    question2 = Question(
        quiz_id=quiz.id,
        text="What is the keyword for defining a function in Python?",
        correct_answer="def",
        options="def,function,lambda,fun"
    )
    db.session.add_all([question1, question2])
    db.session.commit()

    flash("Sample data created!", "success")
    return redirect(url_for("quizzes"))


@app.route('/read_online/<filename>')
def read_online(filename):
    tutorial_dir = os.path.join(app.root_path, 'static', 'uploads')
    file_path = os.path.join(tutorial_dir, filename)
    print("Checking file path:", file_path)
    print("File exists:", os.path.exists(file_path))

    if not os.path.isfile(file_path):  # <- Ensure correct check
        print("File not found:", file_path)
        return "File not found", 404

    with open(file_path, 'rb') as file:
        file_content = file.read()

    return render_template('view_tutorial.html', content=file_content, filename=filename)




@app.route("/download/<filename>")
@login_required
def download(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

    except FileNotFoundError:
        abort(404)



@app.route("/quizzes")
@login_required
def quizzes():
    quizzes = Quiz.query.all()
    return render_template("quizzes.html", quizzes=quizzes)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    form = TutorialForm()
    if form.validate_on_submit():
        if form.file.data:
            # Get and secure the filename
            filename = secure_filename(form.file.data.filename)

            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            form.file.data.save(file_path)
            print(file_path)

            # Create a new tutorial record in the database
            tutorial = Tutorial(
                title=form.title.data,
                description=form.description.data,
                file_url=filename,  # Save just the filename
                uploaded_by=current_user.id
            )
            db.session.add(tutorial)
            db.session.commit()

            flash('Tutorial uploaded successfully!', 'success')
            return redirect(url_for("read_online", filename=filename))
        else:
            flash('No file uploaded. Please upload a valid file.', 'danger')
    return render_template("upload.html", form=form)



@app.route("/templates/<template>")
def show_template(template):
    return render_template(template)


if __name__ == "__main__":
    app_dir = op.realpath(os.path.dirname(__file__))
    with app.app_context():
        db.create_all()
    app.run(debug=True)

