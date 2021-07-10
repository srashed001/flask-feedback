from flask import Flask, redirect, render_template, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from forms import LoginForm, RegisterUserForm, FeedbackForm
from models import connect_db, db, User, Feedback
from sqlalchemy.exc import DatabaseError, IntegrityError

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///feedback_db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

connect_db(app)

toolbar = DebugToolbarExtension(app)

@app.route('/')
def redirect_to_register():
    return render_template('home.html')
    
@app.route('/users/<username>')
def secret_page(username):
    if 'username' not in session:
        flash("Please login first", 'danger')
        return redirect('/register')
    user = User.query.get_or_404(username)
    if user.username == session['username']:
        feedbacks = Feedback.query.filter_by(username = user.username)
        return render_template('user.html', user = user, feedbacks = feedbacks)
    else:
        flash("Sorry you do not have authorization to see other user details", 'danger')
        return redirect(f'/users/{session["username"]}')

@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    user = User.query.get_or_404(username)
    db.session.delete(user)
    db.session.commit()
    session.pop('username')
    return redirect('/')
  

@app.route('/register', methods = ['GET', 'POST'])
def register_user():

    form = RegisterUserForm()
    if form.validate_on_submit():
        user = User.register(
            username = form.username.data,
            password = form.password.data,
            email = form.email.data,
            first_name = form.first_name.data,
            last_name = form.last_name.data 
        )
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username taken please take another')
            return render_template('register.html', form=form)
        session['username'] = user.username
        return redirect(f'/users/{user.username}')

    return render_template('register.html', form = form )

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.authenticate(
            username = form.username.data,
            password = form.password.data
        )
        if user: 
            flash(f"Welcome Back {user.full_name()}", 'success')
            session['username'] = user.username
            return redirect(f'/users/{user.username}')
        else:
            form.username.errors = ['Invalid Username/Password']
    return render_template('login.html', form = form)



@app.route('/logout')
def logout_user():
    session.pop('username')
    flash('Goodbye', 'success')
    return redirect('/')     

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def create_feedback(username):
    user = User.query.get_or_404(username)
    if user.username == session['username']:
        form = FeedbackForm()
        if form.validate_on_submit():
            feedback = Feedback(
                title = form.title.data,
                content = form.content.data,
                username = user.username
            )
            db.session.add(feedback)
            db.session.commit()
            return redirect(f'/users/{user.username}')
        return render_template('feedback.html', form = form)

    flash("Sorry you do not have authorization to add feedback", 'danger')
    return redirect(f'/users/{session["username"]}')

@app.route('/feedback/<int:id>/update', methods=['GET', 'POST'])
def update_feedback(id):
    feedback = Feedback.query.get_or_404(id)
    user = feedback.user 
    if user.username == session['username']:
        form = FeedbackForm(obj=feedback)
        if form.validate_on_submit():
            feedback.title = form.title.data
            feedback.content = form.content.data
            db.session.commit()
            return redirect(f'/users/{user.username}')
        return render_template('update_feedback.html', form=form)
    
    flash("Sorry you do not have authorization to update feedback", 'danger')
    return redirect(f'/users/{session["username"]}')

@app.route('/feedback/<int:id>/delete', methods=['POST'])
def delete_feedback(id):
    feedback = Feedback.query.get_or_404(id)
    user = feedback.user
    db.session.delete(feedback)
    db.session.commit()
    return redirect(f'/users/{user.username}')
        
   