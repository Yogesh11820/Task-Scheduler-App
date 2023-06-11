from flask import Flask, render_template,flash, request, redirect, url_for, session,send_file
from sqlobject import *
import os,platform,psutil,subprocess,paramiko,re
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField,TextAreaField,DateField,SelectField
from wtforms.validators import DataRequired
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from celery import Celery
from flask_mail import Mail, Message
from flask_login import login_required,current_user
from datetime import datetime,timedelta
import pytz



app = Flask(__name__)
app.config['SECRET_KEY'] = 'qwerasdfzxcv'  
csrf = CSRFProtect(app)


#--------flask login,signup and dashboard---------

class User(SQLObject):
    email = StringCol(alternateID=True, unique=True)
    password_hash = StringCol()
    role = StringCol(default="")

    @classmethod
    def create_user(cls, email, password,role=""):
        password_hash = generate_password_hash(password)
        cls(email=email, password_hash=password_hash,role=role)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    


db_filename = os.path.abspath('credentials.sqlite')
connection_string = 'sqlite:' + db_filename
connection = connectionForURI(connection_string)
sqlhub.processConnection = connection

User.createTable(ifNotExists=True)


@app.route('/')
def home():

    # users = User.select()
    # for user in users:
    #     print(f"User ID: {user.id}")
    #     print(f"Email: {user.email}")
    #     print(f"Role: {user.role}")
    #     print("---")

    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if request.method == 'POST':
        email = request.form['username']
        password = request.form['password']
        error = 'Invalid email or password'

        try:
            user = User.byEmail(email)
            #print(user)
        except SQLObjectNotFound:
            return render_template('login.html', error=error,form=request.form)
        
        #print(user.password_hash)

        if user.verify_password(password):
            session['username'] = user.email
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error=error,form=request.form)

    return render_template('login.html',form=request.form)



class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    role = StringField('Role',validators=[DataRequired()])

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        email = form.username.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        role = form.role.data

        if User.selectBy(email=email).count() > 0:
            error = 'User already registered. Please choose a different email.'
            return render_template('signup.html', form=form, error=error)

        if password != confirm_password:
            error = 'The provided password and confirm password do not match. Please ensure both fields have the same value.'
            return render_template('signup.html', form=form, error=error)

        User.create_user(email=email, password=password,role=role)
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)




@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))


@app.route('/dashboard')
def dashboard():
    
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = User.byEmail(session['username'])
    return render_template('dashboard.html',user=user)



#-------------------------------Task management-----------------------------------------

class TaskData(SQLObject):
    user_id = IntCol()
    task_name = StringCol()
    task_description = StringCol()
    task_duedate = DateCol()
    task_priority = StringCol()
    task_status = StringCol()

    def __repr__(self):
        return "<TaskData(task_name=%s, task_description=%s,task_duedate=%s,task_priority=%s, task_status=%s, user_id=%d)>" % (
             self.task_name, self.task_description,self.task_duedate,self.task_priority, self.task_status, self.user_id
        )
    


TaskData.createTable(ifNotExists=True)


#TaskData.dropTable()

@app.route('/task_list')
def task_list():

    login_user = User.byEmail(session['username'])
    print(login_user.id)                                     #current user 
    tasks = TaskData.selectBy(user_id=login_user.id)

    for task in tasks:
        print(task.task_name)

    return render_template('task_list.html', tasks=tasks)


class AddTaskForm(FlaskForm):
    task_name = StringField('Task Name', validators=[DataRequired()])
    task_description = TextAreaField('Task Description', validators=[DataRequired()])
    task_duedate = DateField('Task Due Date', validators=[DataRequired()])
    task_priority = SelectField('Task Priority', choices=[('L', 'Low'), ('M', 'Medium'), ('H', 'High')], validators=[DataRequired()])

@app.route('/add_task', methods=['GET', 'POST'])
def add_task():
    form = AddTaskForm()
    dummy = ''
    if form.validate_on_submit():
        task_name = form.task_name.data
        task_description = form.task_description.data
        task_status = "pending"
        task_duedate = form.task_duedate.data
        task_priority = form.task_priority.data
        
        login_user = User.byEmail(session['username'])
        print(login_user.email)

        task = TaskData(
            task_name=task_name,
            task_description=task_description,
            task_status=task_status,
            task_duedate=task_duedate,
            task_priority=task_priority,
            user_id=login_user.id
        )

        return redirect(url_for('task_list'))
    
    return render_template('add_task.html', form=form)



class AssignTask(FlaskForm):
    assignee_email = StringField('Assignee Email',validators=[DataRequired()])
    task_name = StringField('Task Name', validators=[DataRequired()])
    task_description = TextAreaField('Task Description', validators=[DataRequired()])
    task_duedate = DateField('Task Due Date', validators=[DataRequired()])
    task_priority = SelectField('Task Priority', choices=[('L', 'Low'), ('M', 'Medium'), ('H', 'High')], validators=[DataRequired()])

@app.route('/assign_task', methods=['GET', 'POST'])
def assign_task():
    form = AssignTask()
    if form.validate_on_submit():
        assignee_email = form.assignee_email.data
        task_name = form.task_name.data
        task_description = form.task_description.data
        task_status = "pending"
        task_duedate = form.task_duedate.data
        task_priority = form.task_priority.data
        
        login_user = User.byEmail(session['username'])

        assignee = User.byEmail(assignee_email)
        print(assignee.id)

        task = TaskData(
            task_name=task_name,
            task_description=task_description,
            task_status=task_status,
            task_duedate=task_duedate,
            task_priority=task_priority,
            user_id = assignee.id
        )

        return redirect(url_for('task_list'))
    
    return render_template('assign_task.html', form=form)


class EditTaskForm(FlaskForm):
    task_name = StringField('Task Name', validators=[DataRequired()])
    task_description = TextAreaField('Task Description', validators=[DataRequired()])
    task_duedate = DateField('Task Due Date', validators=[DataRequired()])
    task_priority = SelectField('Task Priority', choices=[('L', 'Low'), ('M', 'Medium'), ('H', 'High')], validators=[DataRequired()])
    task_status = StringField('Task Status', validators=[DataRequired()])

@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    task = TaskData.get(task_id)
    form = EditTaskForm(obj=task)
    if form.validate_on_submit():
        form.populate_obj(task)
        return redirect(url_for('task_list'))
    return render_template('edit_task.html', form=form, task_id=task_id)


@app.route('/delete_task/<int:task_id>', methods=['GET', 'POST'])
def delete_task(task_id):
    task = TaskData.get(task_id)
    if task:
        task.destroySelf()
    return redirect(url_for('task_list'))


#----------------report generation---------


@app.route("/system_report")
def system_report():
    
    user = 'chetan'
    password = 'chetan'
    port = 22
    host = '192.168.2.200'

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port, user,password)  

    command = "hostname; uname -a; df -h; a; ip addr show eth0; lscpu; lsblk"


    #GET http://localhost:5000/system_info?user=laptop-3cn3kh55\yogesh&host=192.168.2.200&port=22


    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode("utf-8")
    try:
        if os.path.exists('systemdata.txt'):
           os.remove('systemdata.txt')
           with open('systemdata.txt', 'w', encoding='utf-8') as file:
                file.write(output)
    except Exception as e:
         print("An error occurred while writing to the file:", str(e))

    client.close()
    
    #-----output----
    
    
    with open('systemdata.txt', 'r') as file:
       system_info = file.read()

    architecture_info = re.search(r'(?<=Architecture:)\s*(.*\S)', system_info).group(1).strip()

    processor_info = re.search(r'(?<=Model name:)\s*(.*\S)', system_info).group(1).strip()
    #---output----

    system_info = {}
    system_info["Hostname"] = output.splitlines()[0]
    system_info["Operating_system"] = output.splitlines()[1].split(" ")[0]
    system_info["OS Version"] = output.splitlines()[1].split(" ")[2]
    system_info["Processor"] =  processor_info
    system_info['Architecture'] = architecture_info
    system_info["ip_address"] = host

    return render_template('system_report.html', system_info=system_info,filename='systemdata.txt')

@app.route("/download_file/<filename>")
def download_file(filename):
    return send_file(filename, as_attachment=True)




#----------run script--------

class ScriptData(SQLObject):
    Runby = StringCol()
    Filename = StringCol()
    Language = StringCol()
    DateTime = DateTimeCol()
    Status = StringCol()

ScriptData.createTable(ifNotExists=True)

@app.route('/run_script', methods=['GET', 'POST'])
def run_script():
    login_user = User.byEmail(session['username'])

    user_name = login_user.email

    script_data = ScriptData.selectBy(Runby=user_name)

    print(script_data)

    if request.method == 'POST':
        script_file = request.files['script']
        script_language = request.form['language']

        # supported_languages = {
        #     'python': ['python', 'script_.py'],
        #     'go': ['go', 'script_.go'],
        #     'ruby': ['ruby', 'script_.rb'],
        #     'java': ['java', 'script_.java'],
        #     'javascript': ['node', 'script_.js']
        # }

        if script_file and script_file.filename.endswith('.py'):
            temp_file = 'script_.py'
            script_file.save(temp_file)

            try:
                command = ['python', temp_file]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = process.communicate()
                output = output.decode('utf-8')
                error = error.decode('utf-8')

                print(process.returncode)       # 0 --> success

                result = 'SUCCESS'
                if process.returncode:
                    result = 'FAILED'
                
                login_user = User.byEmail(session['username'])
                print(login_user.email)
                stat = ScriptData(
                    Runby=login_user.email,
                    Filename=script_file.filename,
                    Language=script_language,
                    DateTime=datetime.now(),
                    Status=result,
                )
                
                login_user = User.byEmail(session['username'])

                user_name = login_user.email

                script_data = ScriptData.selectBy(Runby=user_name)

                print(script_data)


                return render_template('script_result.html', output=output, error=error, script_data=script_data)
            except Exception as e:
                error = str(e)
                return render_template('script_result.html', error=error)

    return render_template('run_script.html', script_data=script_data)

#-------mail updated------


def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery


app.config.update(
    CELERY_BROKER_URL='redis://localhost:6379',
    CELERY_RESULT_BACKEND='redis://localhost:6379'
)
celery = make_celery(app)



app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'cp258889@gmail.com'
app.config['MAIL_PASSWORD'] = 'loasojlrnpimgelr'
app.config['MAIL_DEFAULT_SENDER'] = 'cp258889@gmail.com'

mail = Mail(app)

class Mailbody(FlaskForm):
    email = StringField('Task Name', validators=[DataRequired()])
    Subject = TextAreaField('Subject', validators=[DataRequired()])
    Body = TextAreaField('Body', validators=[DataRequired()])


@app.route('/mailquick',methods=['GET','POST'])
def index():
    form = Mailbody()

    if request.method == 'GET':
        return render_template('index.html', form = form, email=session.get('email', ''))
    
    if form.validate_on_submit():
        email = form.email.data
        session['email'] = email
        subject = form.Subject.data
        body = form.Body.data

        email_data = {
            'subject': subject,
            'to': email,
            'body': body
        }
        
        print(email_data)
        
        
        if request.form['submit'] == 'Send':
            print('its working')
            try:
                send_async_email.delay(email_data)
                flash('Sending email to {0}'.format(email))
            except Exception as e:
                print(e)

        elif request.form['submit'] == 'Send afer 1 Min':
            send_async_email.apply_async(args=[email_data], countdown=60)
            flash('An email will be sent to {0} in one minute'.format(email))
        
        elif request.form['submit'] == 'Schedule Mail':
            try:
                india_timezone = pytz.timezone('ASIA/KOLKATA')
                datetime_input = '2023-6-9 18:59'
                scheduled_datetime = india_timezone.localize(datetime.strptime(datetime_input, "%Y-%m-%d %H:%M"))

                
                time_difference = scheduled_datetime - datetime.now(india_timezone)

                print(datetime.now(india_timezone))
                print(time_difference.total_seconds())
                exit()
                send_async_email.apply_async(args=[email_data], countdown=time_difference.total_seconds())
                flash('Email scheduled for {}'.format(scheduled_datetime))
            except Exception as e:
                print(e)
         
        return redirect(url_for('index'))

    return render_template('index.html', form=form)


@celery.task(name='send_async_email')
def send_async_email(email_data):
    print('Great Success!!')


    msg = Message(email_data['subject'],
                  sender=app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[email_data['to']])
    msg.body = email_data['body']
    with app.app_context():
         
         try:
            mail.send(msg)
         except Exception as e:
            print(f"An error occurred while sending the email: {str(e)}")



if __name__ == '__main__':
    app.run(debug=True)