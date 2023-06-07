from flask import render_template, request, session, flash, redirect, url_for
from celery import Celery
from flask_mail import Mail, Message
import secrets, os


from app import app

# app = Flask(__name__)
# app.secret_key = secrets.token_hex(16)


#------changes--------
os.environ.setdefault('FORKED_BY_MULTIPROCESSING', '1')
#------changes--------


celery = Celery(app.name, broker='redis://localhost:6379/0')
celery.conf.update(app.config)           

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'cp258889@gmail.com'
app.config['MAIL_PASSWORD'] = 'loasojlrnpimgelr'
app.config['MAIL_DEFAULT_SENDER'] = 'cp258889@gmail.com'

mail = Mail(app)


@app.route('/mailquick', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template('index.html', email=session.get('email', ''))
    email = request.form['email']
    session['email'] = email
    email_data = {
        'subject': 'Hello from Flask',
        'to': email,
        'body': 'This is a test email sent from a background Celery task.'
    }
    # import pdb;pdb.set_trace()
    if request.form['submit'] == 'Send':
        
        send_async_email.delay(email_data)
        flash('Sending email to {0}'.format(email))
    else:
        send_async_email.apply_async(args=[email_data], countdown=60)
        flash('An email will be sent to {0} in one minute'.format(email))

    return redirect(url_for('index'))


@celery.task(name='send_async_email')
def send_async_email(email_data):
    print('blah blah')
    """Background task to send an email with Flask-Mail."""
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
    app.run()
