from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_migrate import Migrate
from itsdangerous import Serializer
from flask_mail import Mail, Message
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from flask_login import current_user
from flask import url_for
from sqlalchemy.orm.exc import NoResultFound
from dotenv import load_dotenv
import openai
import os
import logging

load_dotenv()

logging.basicConfig(level=logging.DEBUG)

openai.api_key = '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'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'boggartB#GG3r'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
mail = Mail(app)

google_blueprint = make_google_blueprint(
    client_id="985539098035-u28t653bnmkgc6852vf4alqiisg4tldv.apps.googleusercontent.com",
    client_secret="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",
    scope=["profile", "email"],
    redirect_url="https://4428-73-12-16-54.ngrok.io/login/google/authorized",
    offline=True,
    reprompt_consent=True,
)

@app.route("/login/google")
def login_google():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v1/userinfo")
    assert resp.ok, resp.text
    return "You are {email} on Google".format(email=resp.json()["email"])

@app.route("/login/google/authorized")
def google_authorized():
    resp = google.authorized_response()
    print(resp)
    if resp is None:
        return "Access denied: reason=%s error=%s" % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (resp['access_token'], '')
    me = google.get('userinfo')
    return "You are {email} on Google".format(email=me.data["email"])

@oauth_authorized.connect_via(google_blueprint)
def google_logged_in(blueprint, token):
    resp = blueprint.session.get("/oauth2/v1/userinfo")
    if resp.ok:
        email = resp.json()["email"]
        query = User.query.filter_by(email=email)

        try:
            user = query.one()
        except NoResultFound:
            user = User(email=email)
            db.session.add(user)
            db.session.commit()

        login_user(user)

app.register_blueprint(google_blueprint, url_prefix="/login")

def send_reset_email(user, token):
    msg = Message('Password Reset Request',
                  sender='AIrepairpros@gmail.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
            return User.query.get(user_id)
        except:
            return None

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

# Registration Form
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

# Password reset request
class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

# Password reset form
class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class DiagnosisForm(FlaskForm):
    make = StringField('Make', validators=[DataRequired()])
    model = StringField('Model', validators=[DataRequired()])
    vin = StringField('VIN', validators=[DataRequired()])
    dtc = StringField('DTC', validators=[DataRequired()])
    complaint = StringField('Complaint', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ModelSelectionForm(FlaskForm):
    model = SelectField('Model', choices=[('openai', 'OpenAI')], validators=[DataRequired()])
    submit = SubmitField('Select Model')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Registered successfully", "success")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.get_reset_token()
            send_reset_email(user, token)  # Uncommented this line
            flash('An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid email or password", "danger")

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "success")
    return redirect(url_for('home'))

@app.route('/')
def home():
    form = DiagnosisForm()
    model_selection_form = ModelSelectionForm()
    return render_template('index.html', form=form, model_selection_form=model_selection_form)

@app.route('/select_model', methods=['POST'])
@login_required
def select_model():
    form = ModelSelectionForm()
    if form.validate_on_submit():
        session['selected_model'] = form.model.data
        flash("Model selected successfully", "success")
    return redirect(url_for('home'))

@app.route('/diagnose', methods=['POST'])
@login_required
def diagnose():
    try:
        make = request.form.get('make')
        model = request.form.get('model')
        vin = request.form.get('vin')
        dtc = request.form.get('dtc')
        complaint = request.form.get('complaint')

        selected_model = session.get('selected_model')

        if selected_model == 'openai':
            # Persona prompt for OpenAI
            persona_prompt = """
            "Create a persona named Max the Automotive Pro with a focus on assisting individuals in the automotive repair industry."
            "The persona should have the following skills: 1. Comprehensive knowledge of automotive diagnostics and repair techniques. 2. Familiarity with various automotive makes, models, and common issues. 3. Ability to provide step-by-step guidance for troubleshooting and repair. 4. Expertise in recommending suitable parts and tools for each specific task. 5. Capacity to communicate clearly, patiently, and effectively. 6. Adaptability to various skill levels, experience, and learning styles. 7. Dedication to staying up-to-date with industry trends and developments. 8. Strong emphasis on safety guidelines and best practices."
            "The persona should avoid the following: 1. Providing inaccurate, outdated, or misleading information. 2. Encouraging users to perform dangerous or unsafe actions. 3. Failing to take users' skill levels and experience into account. 4. Demonstrating impatience or frustration with user questions or concerns. 5. Promoting or endorsing unreliable, untested, or unverified repair methods. 6. Ignoring or overlooking essential safety guidelines and best practices. 7. Inability to adapt to different user needs and preferences. 8. Offering unsolicited or irrelevant advice unrelated to the user's situation."
            """

            # Diagnostic prompt for OpenAI
            diagnostic_prompt = f"""
            "Assist with automotive repair for a professional automotive repair technician."
            "The make of the vehicle is '{make}'."
            "The model of the vehicle is '{model}'."
            "The VIN of the vehicle is '{vin}'."
            "The DTC code is '{dtc}'."
            "The complaint is '{complaint}'."
            "Provide thorough and complete automotive diagnostics with estimated likelihood percentages for identified issues."
            "Focus on comprehensive diagnostics based on available information for the specific vehicle."
            "Using the provided make, model, VIN, and DTC code, access available information and resources to provide a thorough and complete diagnosis of the vehicle."
            "REFERENCE COMPLAINT AGAINST COMMONLY KNOWN ISSUES, FACTORY MANUALS, FACTORY REPAIR GUIDES, FORUM AND SOCIAL MEDIA GROUP POSTS PERTAINING TO THE COMPLAINT, AND REFERENCE VIDEO SCRIPTS FROM YOUTUBE.COM TO PUT TOGETHER EFFECTIVE SOLUTIONS BASED ON THE BEST POSSIBLE INFORMATION AND THE SPECIFIC VEHICLE AT HAND."
            "INCLUDE ESTIMATED PERCENTAGES OF LIKELIHOOD FOR IDENTIFIED ISSUES."
            "Include detailed and comprehensive disassembly procedure and guide to locate, access, test, diagnose, and repair the identified parts."
            "Include factory part numbers."
            "Include links to tutorials about the diagnosis, test procedure, disassembly, and/or repair."
            "Include links for further learning that specifically focus on the subject of the repair diagnosis or testing procedure."
            "Always answer questions with accurate diagnostic responses in the fashion instructed."
            "ONLY RESPOND AS CREATED PERSONA 'MAX' DURING ALL RESPONSES."
            """
            
            # Generate diagnosis using OpenAI
            diagnosis_response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",  # Use GPT-4 model
                messages=[
                    {"role": "system", "content": persona_prompt},
                    {"role": "user", "content": diagnostic_prompt},
                ],
            )

            diagnosis = diagnosis_response['choices'][0]['message']['content'].strip()

        # Print the diagnosis in the console
        print(diagnosis)

        session['diagnosis_results'] = diagnosis
        return redirect(url_for('diagnosis_results'))
    except Exception as e:
        print(f"Error: {e}")
        flash("An error occurred while generating the diagnosis.", "danger")
        return redirect(url_for('home'))


@app.route('/diagnosis_results')
def diagnosis_results():
    results = session.get('diagnosis_results', 'No diagnosis results found.')
    return render_template('diagnosis.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
