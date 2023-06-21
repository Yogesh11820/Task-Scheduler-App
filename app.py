from flask import Flask, render_template,flash, request, redirect, url_for, session,send_file,jsonify,current_app,make_response
from sqlobject import *
import os,subprocess,paramiko,re
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField,FileField,TextAreaField,DateField,SelectField, DateTimeLocalField,IntegerField,TimeField,SelectMultipleField
from wtforms.validators import DataRequired,Optional,InputRequired
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from celery import Celery
from flask_mail import Mail, Message
from datetime import datetime
from celery.schedules import crontab
import pytz





app = Flask(__name__)
app.config['SECRET_KEY'] = 'qwerasdfzxcv'  
csrf = CSRFProtect(app)


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
    CELERY_RESULT_BACKEND='redis://localhost:6379',
    CELERY_TASK_RESULT_EXPIRES=30,
    CELERY_TIMEZONE='ASIA/KOLKATA',
    CELERY_ACCEPT_CONTENT=['json', 'msgpack', 'yaml'],
    CELERY_TASK_SERIALIZER='json',
    CELERY_RESULT_SERIALIZER='json',
    # CELERYBEAT_SCHEDULE={
    #     'dailymail-celery': {
    #         'task': 'daily_email',
    #         'schedule': crontab(hour=19,minute=44),
    #     },
    #     'weeklymail-celery': {
    #         'task': 'week_email',
    #         'schedule': crontab(hour=16,minute=13,day_of_week=1),
    #     },
    #     # 'dailyreportmcelery': {
    #     #     'task': 'daily_report_m',
    #     #     'schedule': crontab(hour=15,minute=42),
    #     # },
    #     # 'dailyreportecelery': {
    #     #     'task': 'daily_report_e',
    #     #     'schedule': crontab(hour=17,minute=0),
    #     # },
    # }
)

celery = make_celery(app)

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


@app.route('/', methods=["GET","POST"])
def home():
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

#-----------------Send Mail-------------

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'cp258889@gmail.com'
app.config['MAIL_PASSWORD'] = 'loasojlrnpimgelr'
app.config['MAIL_DEFAULT_SENDER'] = 'cp258889@gmail.com'

mail = Mail(app)

class Maildata(SQLObject):
    Sender = StringCol()
    # Email = StringCol()
    Recipient = StringCol()
    Subject = TextAreaField()
    Body = TextAreaField()
    Scheduledtime = StringCol()
    Status = StringCol()

Maildata.createTable(ifNotExists=True)

class Mailbody(FlaskForm):
    email = StringField('Task Name', validators=[DataRequired()])
    Subject = TextAreaField('Subject', validators=[DataRequired()])
    Body = TextAreaField('Body', validators=[DataRequired()])
    Schedule = DateTimeLocalField('DateTime', format='%Y-%m-%dT%H:%M')


@app.route('/mailquick',methods=['GET','POST'])
def index():
    return render_template('mailbutton.html')

@app.route('/instanmail',methods=['GET','POST'])
def instantmail():
    login_user = User.byEmail(session['username'])
    user_name = login_user.email
    print(user_name)

    mail_logs = Maildata.selectBy(Sender=user_name)
    print(mail_logs)

    form = Mailbody()
    if request.method == 'GET':
        return render_template('instantmail.html', form = form, email=session.get('email', ''),mail_logs=mail_logs)
    if form.validate_on_submit():
        email = form.email.data
        session['email'] = email
        subject = form.Subject.data
        body = form.Body.data

        email_data = {
            'subject': subject,
            'to': email,
            'body': body,
            'username' : user_name
        }
        
        if request.form['submit'] == 'Send':
            print('its working')
            try:
                send_async_email.delay(email_data)
                return render_template('index.html', form=form, mail_logs=mail_logs)

            except Exception as e:
                print(e)
        
        return redirect(url_for('instantmail'))
    return render_template('instantmail.html', form=form,mail_logs=mail_logs)


@app.route('/schedulemail',methods=['GET','POST'])
def schedulemail():
    login_user = User.byEmail(session['username'])
    user_name = login_user.email
    print(user_name)

    mail_logs = Maildata.selectBy(Sender=user_name)
    print(mail_logs)

    form = Mailbody()
    if request.method == 'GET':
        return render_template('schedulemail.html', form = form, email=session.get('email', ''),mail_logs=mail_logs)
    if form.validate_on_submit():
        email = form.email.data
        session['email'] = email
        subject = form.Subject.data
        body = form.Body.data
        date_time = form.Schedule.data
        print(date_time)

        email_data = {
            'subject': subject,
            'to': email,
            'body': body,
            'username' : user_name
        }
        
        if request.form['submit'] == 'Schedule Mail':
            try:
                india_timezone = pytz.timezone('ASIA/KOLKATA')
                #datetime_input = '2023-6-9 18:59'
                datetime_input = str(date_time)
                scheduled_datetime = india_timezone.localize(datetime.strptime(datetime_input, "%Y-%m-%d %H:%M:%S"))

                
                time_difference = scheduled_datetime - datetime.now(india_timezone)

                print(datetime.now(india_timezone))
                print(time_difference.total_seconds())
                send_async_email.apply_async(args=[email_data], countdown=time_difference.total_seconds())
            except Exception as e:
                print(e)
        

        return redirect(url_for('schedulemail'))

    return render_template('schedulemail.html', form=form,mail_logs=mail_logs)


@celery.task(name='send_async_email')
def send_async_email(email_data):
    print('Great Success!!')


    msg = Message(email_data['subject'],
                  sender=app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[email_data['to']])
    msg.body = email_data['body']
    with app.app_context():
         try:
            # print(email_data)
            maildata = Maildata(
                    Sender = email_data['username'],
                    Recipient = email_data['to'],
                    Subject = email_data['subject'],
                    Body = email_data['body'],
                    Scheduledtime = str(datetime.now()),
                    Status = 'Sent'
                )
            
            mail.send(msg)
         except Exception as e:
            maildata = Maildata(
                    Sender = email_data['username'] ,
                    Recipient = email_data['to'],
                    Subject = email_data['subject'],
                    Body = email_data['body'],
                    Scheduledtime = str(datetime.now()),
                    Status = 'Failed'
                )
            print(f"An error occurred while sending the email: {str(e)}")



#----------------report generation---------

class Reportdata(SQLObject):
    Host = StringCol()
    Port = IntCol()
    DateTimeStamp = DateTimeCol()
    Report = BLOBCol()
    
Reportdata.createTable(ifNotExists=True)

@app.route("/system_report",methods=['GET','POST'])
def system_report():
    return render_template('reportoptions.html')


@app.route("/instantreport",methods=['GET','POST'])
def instantreport():
    login_user = User.byEmail(session['username'])
    

    report_logs = Reportdata.selectBy()
    print(report_logs)


    if request.method == 'POST':
        user = request.form['user']
        password = request.form['password']
        port = int(request.form['port'])
        host = request.form['host']
    
        # user = 'chetan'
        # password = 'chetan'
        # port = 22
        # host = '192.168.2.200'
        print(password)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
           client.connect(host, port, user,password)
        except Exception as e:
            return render_template('reportgenerror.html',error=e)  
        command = "hostname; uname -a; df -h; a; ip addr show eth0; lscpu; lsblk"
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
        
    
        with open('systemdata.txt', 'r') as file:
           system_info = file.read()

        architecture_info = re.search(r'(?<=Architecture:)\s*(.*\S)', system_info).group(1).strip()

        processor_info = re.search(r'(?<=Model name:)\s*(.*\S)', system_info).group(1).strip()

        system_info = {}
        system_info["Hostname"] = output.splitlines()[0]
        system_info["Operating_system"] = output.splitlines()[1].split(" ")[0]
        system_info["OS Version"] = output.splitlines()[1].split(" ")[2]
        system_info["Processor"] =  processor_info
        system_info['Architecture'] = architecture_info
        system_info["ip_address"] = host
        print('report generated')
      
        with open('systemdata.txt', 'rb') as file:
                report_file = file.read()

                report_d = Reportdata(
                    Host = host,
                    Port = port,
                    DateTimeStamp = datetime.now(),
                    Report = report_file
                )

        return render_template('system_report.html', system_info=system_info,filename='systemdata.txt',report_logs=report_logs)
    
    return render_template('reportform.html',report_logs=report_logs)

#---report file for instant report---

@app.route("/download_report/<filename>")
def download_file(filename):
    return send_file(filename, as_attachment=True)



class ReportCred(FlaskForm):
    user = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    port = IntegerField('Port', validators=[DataRequired()])
    host = StringField('Host',validators=[DataRequired()])
    schedule = DateTimeLocalField('DateTime', format='%Y-%m-%dT%H:%M')    



@app.route("/schedulereport", methods=['GET', 'POST'])
def schedulereport():
    login_user = User.byEmail(session['username'])
    report_logs = Reportdata.selectBy()
    print(report_logs)


    form = ReportCred()
    if form.validate_on_submit():
        user = form.user.data
        # session['email'] = email
        password = form.password.data
        port = form.port.data
        host = form.host.data
        date_time = form.schedule.data
        

        report_cred = {
            'user': user,
            'password': password,
            'port': port,
            'host': host
        }
        
        print(request.form['submit'])
        if request.form['submit'] == 'Schedule Report':
            try:
                india_timezone = pytz.timezone('ASIA/KOLKATA')
                datetime_input = str(date_time)
                scheduled_datetime = india_timezone.localize(datetime.strptime(datetime_input, "%Y-%m-%d %H:%M:%S"))

                
                time_difference = scheduled_datetime - datetime.now(india_timezone)

                print(datetime.now(india_timezone))
                print(time_difference.total_seconds())
                result = generate_system_report.apply_async(args=[report_cred], countdown=time_difference.total_seconds())
                return render_template('reportontime.html', form=form,report_logs=report_logs)

            except Exception as e:
                print(e)

        return redirect(url_for('schedulereport'))

    return render_template('reportontime.html',form=form,report_logs=report_logs)


@celery.task(name='generate_system_report')
def generate_system_report(report_cred):
        
        print('enter')
        host = report_cred['host']
        port = report_cred['port']
        user = report_cred['user']
        password  = report_cred['password']

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
           client.connect(host, port, user,password)  
        except Exception as e:
            print(e)

        command = "hostname; uname -a; df -h; a; ip addr show eth0; lscpu; lsblk"

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
       
        print('reached')
        try:
           with open('systemdata.txt', 'rb') as file:
                report_file = file.read()
        except Exception as e:
            print(e)
         
        data = Reportdata(
            Host=host,
            Port=port,
            DateTimeStamp=datetime.now(),
            Report=report_file
        )


@app.route('/download_reportfile/<int:report_id>',methods=['GET','POST'])
def download_reportfile(report_id):
    report = Reportdata.selectBy(id=report_id).getOne(None)
    print(report.Host)
    if report:
        response = make_response(report.Report)
        response.headers.set('Content-Type', 'application/octet-stream')
        response.headers.set('Content-Disposition', 'attachment', filename='report.txt')
        return response

    



#----------run script--------
class ScriptData(SQLObject):
    Runby = StringCol()
    Filename = StringCol()
    Scriptcode = BLOBCol()
    Scriptreport = BLOBCol()
    Language = StringCol()
    DateTime = DateTimeCol()
    Status = StringCol()

ScriptData.createTable(ifNotExists=True)


@app.route('/runscriptoptions',methods=['GET','POST'])
def runscriptoptions():
    return render_template('runscriptoptions.html')

@app.route('/run_script', methods=['GET', 'POST'])
def run_script():

    login_user = User.byEmail(session['username'])

    user_name = login_user.email

    script_data = ScriptData.selectBy(Runby=user_name)

    save_folder = r'C:\Users\yoges\OneDrive\Desktop\intern\TaskSchedule\scriptsfolder'
    
    

    if request.method == 'POST':
        script_file = request.files['script']
        script_language = request.form['language']

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")  
        filename = f"{timestamp}_{login_user.id}_{script_file.filename}"
        file_path = os.path.join(save_folder, filename)
        script_file.save(file_path)
        
    
        with open(file_path, 'rb') as file:
            script_code = file.read()  

        if script_file and script_language=='python':

            try:
                command = ['python', file_path]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = process.communicate()
                
                

                
                
                print(process.returncode) 

                if process.returncode:  
                    stat = ScriptData(
                        Runby=login_user.email,
                        Filename=script_file.filename,
                        Scriptcode = script_code,
                        Scriptreport = error ,
                        Language=script_language,
                        DateTime=datetime.now(),
                        Status='FAILED',
                    )
                else:
                    stat = ScriptData(
                        Runby=login_user.email,
                        Filename=script_file.filename,
                        Scriptcode = script_code,
                        Scriptreport = output  ,
                        Language=script_language,
                        DateTime=datetime.now(),
                        Status='SUCCESS',
                    )

                output = output.decode('utf-8')
                error = error.decode('utf-8')
                return render_template('script_result.html',output=output,error=error,script_data=script_data)


            except Exception as e:
                print(e)


        elif script_file and script_language=='go':

            try:
                command = ['go','run', file_path]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = process.communicate()
               

                print(process.returncode)   

            
                if process.returncode:  
                    stat = ScriptData(
                        Runby=login_user.email,
                        Filename=script_file.filename,
                        Scriptcode = script_code,
                        Scriptreport = error ,
                        Language=script_language,
                        DateTime=datetime.now(),
                        Status='FAILED',
                    )
                else:
                    stat = ScriptData(
                        Runby=login_user.email,
                        Filename=script_file.filename,
                        Scriptcode = script_code,
                        Scriptreport = output  ,
                        Language=script_language,
                        DateTime=datetime.now(),
                        Status='SUCCESS',
                    )
                output = output.decode('utf-8')
                error = error.decode('utf-8')
                return render_template('script_result.html',output=output,error=error,script_data=script_data)
            
            except Exception as e:
                error = str(e)

        
        elif script_file and script_language=='java':

            try:
                compile_command = ['javac', file_path]
                compile_process = subprocess.Popen(compile_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                compile_output, compile_error = compile_process.communicate()
                compile_output = compile_output.decode('utf-8')
                compile_error = compile_error.decode('utf-8')

                
                if compile_process.returncode == 0:
                    class_name = file_path.split('.')[0]
                    command = ['java', class_name]
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    output, error = process.communicate()
                else:
                    output = ''
                    error = compile_error
                

                if process.returncode:  
                    stat = ScriptData(
                        Runby=login_user.email,
                        Filename=script_file.filename,
                        Scriptcode = script_code,
                        Scriptreport = error ,
                        Language=script_language,
                        DateTime=datetime.now(),
                        Status='FAILED',
                    )
                else:
                    stat = ScriptData(
                        Runby=login_user.email,
                        Filename=script_file.filename,
                        Scriptcode = script_code,
                        Scriptreport = output  ,
                        Language=script_language,
                        DateTime=datetime.now(),
                        Status='SUCCESS',
                    )

                output = output.decode('utf-8')
                error = error.decode('utf-8')
                return render_template('script_result.html',output=output,error=error,script_data=script_data)

            except Exception as e:
                error = str(e)

        elif script_file and script_language=='javascript':

            try:
                command = ['node', file_path]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = process.communicate()

                print(process.returncode)   

                
                if process.returncode:  
                    stat = ScriptData(
                        Runby=login_user.email,
                        Filename=script_file.filename,
                        Scriptcode = script_code,
                        Scriptreport = error ,
                        Language=script_language,
                        DateTime=datetime.now(),
                        Status='FAILED',
                    )
                else:
                    stat = ScriptData(
                        Runby=login_user.email,
                        Filename=script_file.filename,
                        Scriptcode = script_code,
                        Scriptreport = output  ,
                        Language=script_language,
                        DateTime=datetime.now(),
                        Status='SUCCESS',
                    )

                output = output.decode('utf-8')
                error = error.decode('utf-8')
                return render_template('script_result.html',output=output,error=error,script_data=script_data)

            except Exception as e:
                print(e)


    return render_template('run_script.html', script_data=script_data)



@app.route('/download_script/<script_id>')
def download_scriptcode(script_id):
    script = ScriptData.selectBy(id=script_id).getOne(None)
    response = make_response(script.Scriptcode)
    response.headers.set('Content-Type', 'application/octet-stream')
    response.headers.set('Content-Disposition', 'attachment', filename='code.txt')
    return response

@app.route('/download_scriptreport/<script_id>')
def download_scriptreport(script_id):
    script = ScriptData.selectBy(id=script_id).getOne(None)
    response = make_response(script.Scriptreport)
    response.headers.set('Content-Type', 'application/octet-stream')
    response.headers.set('Content-Disposition', 'attachment', filename='report.txt')
    return response



#------------Schedule Run Script---------

class RunScriptForm(FlaskForm):
    script = FileField('Select Script File', validators=[InputRequired()])
    language = SelectField('Select Script Language', choices=[
        ('python', 'Python'),
        ('go', 'Go'),
        ('ruby', 'Ruby'),
        ('java', 'Java'),
        ('javascript', 'JavaScript')
    ])
    schedule = DateTimeLocalField('Date and Time', format='%Y-%m-%dT%H:%M', validators=[InputRequired()])


@app.route('/schedulerunscript', methods=['GET', 'POST'])
def schedulerunscript():

    login_user = User.byEmail(session['username'])
    user_name = login_user.email
    script_data = ScriptData.selectBy(Runby=user_name)
    save_folder = r'C:\Users\yoges\OneDrive\Desktop\intern\TaskSchedule\scriptsfolder'

    form = RunScriptForm()
    if form.validate_on_submit():
        script_file = form.script.data
        language = form.language.data
        schedule = form.schedule.data
        
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")  
        filename = f"{timestamp}_{login_user.id}_{script_file.filename}"
        file_path = os.path.join(save_folder, script_file.filename)
        script_file.save(file_path)

        scriptinfo = { 'scriptpath' : file_path,'scriptlang' : language,'useremail':user_name,'filename' : script_file.filename }

        if request.form['submit'] == 'Run Script':
            try:
                india_timezone = pytz.timezone('ASIA/KOLKATA')
                print(india_timezone)
                datetime_input = str(schedule)

                scheduled_datetime = india_timezone.localize(datetime.strptime(datetime_input, "%Y-%m-%d %H:%M:%S"))
                time_difference = scheduled_datetime - datetime.now(india_timezone)
                
                
                runscriptinfuture.apply_async(args=[scriptinfo], countdown=time_difference.total_seconds())
            except Exception as e:
                print(e)
        
        return redirect(url_for('schedulerunscript'))

    return render_template('runscriptschedule.html',form=form)

@celery.task(name='runscriptinfuture')
def runscriptinfuture(scriptinfo):

    with open(scriptinfo['scriptpath'], 'rb') as file:
        script_code = file.read()

    
    if scriptinfo['scriptlang'] == 'python':

        try:
            command = ['python', scriptinfo['scriptpath']]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            
            if process.returncode:  
                stat = ScriptData(
                    Runby=scriptinfo['useremail'],
                    Filename=scriptinfo['filename'],
                    Scriptcode = script_code,
                    Scriptreport = error ,
                    Language=scriptinfo['scriptlang'],
                    DateTime=datetime.now(),
                    Status='FAILED',
                )
            else:
                stat = ScriptData(
                    Runby=scriptinfo['useremail'],
                    Filename=scriptinfo['filename'],
                    Scriptcode = script_code,
                    Scriptreport = output ,
                    Language=scriptinfo['scriptlang'],
                    DateTime=datetime.now(),
                    Status='SUCCESS',
                )


        except Exception as e:
           print(e)
    
    if scriptinfo['scriptlang'] == 'go':
        try:
            command = ['go','run', scriptinfo['scriptpath']]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
 
            if process.returncode:  
                stat = ScriptData(
                    Runby=scriptinfo['useremail'],
                    Filename=scriptinfo['filename'],
                    Scriptcode = script_code,
                    Scriptreport = error ,
                    Language=scriptinfo['scriptlang'],
                    DateTime=datetime.now(),
                    Status='FAILED',
                )
            else:
                stat = ScriptData(
                    Runby=scriptinfo['useremail'],
                    Filename=scriptinfo['filename'],
                    Scriptcode = script_code,
                    Scriptreport = output ,
                    Language=scriptinfo['scriptlang'],
                    DateTime=datetime.now(),
                    Status='SUCCESS',
                )
        except Exception as e:
            print(e)

    if scriptinfo['scriptlang'] == 'java':
        try:
                compile_command = ['javac', scriptinfo['scriptpath']]
                compile_process = subprocess.Popen(compile_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                compile_output, compile_error = compile_process.communicate()
                compile_output = compile_output.decode('utf-8')
                compile_error = compile_error.decode('utf-8')

                
                if compile_process.returncode == 0:
                    class_name = scriptinfo['scriptpath'].split('.')[0]
                    command = ['java', class_name]
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    output, error = process.communicate()
                else:
                    output = ''
                    error = compile_error

                if process.returncode:  
                    stat = ScriptData(
                        Runby=scriptinfo['useremail'],
                        Filename=scriptinfo['filename'],
                        Scriptcode = script_code,
                        Scriptreport = error ,
                        Language=scriptinfo['scriptlang'],
                        DateTime=datetime.now(),
                        Status='FAILED',
                    )
                else:
                    stat = ScriptData(
                        Runby=scriptinfo['useremail'],
                        Filename=scriptinfo['filename'],
                        Scriptcode = script_code,
                        Scriptreport = output ,
                        Language=scriptinfo['scriptlang'],
                        DateTime=datetime.now(),
                        Status='SUCCESS',
                    )

        except Exception as e:
            print(e)

    if scriptinfo['scriptlang'] == 'javascript':
        try:
            command = ['node', scriptinfo['scriptpath']]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()


            if process.returncode:  
                    stat = ScriptData(
                        Runby=scriptinfo['useremail'],
                        Filename=scriptinfo['filename'],
                        Scriptcode = script_code,
                        Scriptreport = error ,
                        Language=scriptinfo['scriptlang'],
                        DateTime=datetime.now(),
                        Status='FAILED',
                       )
            else:
                stat = ScriptData(
                    Runby=scriptinfo['useremail'],
                    Filename=scriptinfo['filename'],
                    Scriptcode = script_code,
                    Scriptreport = output ,
                    Language=scriptinfo['scriptlang'],
                    DateTime=datetime.now(),
                    Status='SUCCESS',
                )
                
        

        except Exception as e:
            print(e)







if __name__ == '__main__':
    app.run(debug=True)




