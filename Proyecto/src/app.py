from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required

from config import config

# Models:
from models.ModelUser import ModelUser
from models.ModelVisitante import ModelVisitante

# Entities:
from models.entities.User import User

app = Flask(__name__)

csrf = CSRFProtect()
db = MySQL(app)
login_manager_app = LoginManager(app)


@login_manager_app.user_loader
def load_user(id):
    return ModelUser.get_by_id(db, id)


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # print(request.form['username'])
        # print(request.form['password'])
        user = User(0, request.form['username'], request.form['password'])
        logged_user = ModelUser.login(db, user)
        if logged_user != None:
            if logged_user.password:
                login_user(logged_user)
                cursor = db.connection.cursor()
                sql = """SELECT role FROM user 
                    WHERE username = '{}'""".format(user.username)
                cursor.execute(sql)
                row = cursor.fetchone()
                print(row)
                if row[0] == 'admin':
                    return redirect(url_for('homeadmin'))
                else:
                    return redirect(url_for('homeuser'))
            else:
                flash("Invalid password...")
                return render_template('auth/loginutec.html')
        else:
            flash("User not found...")
            return render_template('auth/loginutec.html')
    else:
        return render_template('auth/loginutec.html')

@app.route('/login1', methods=['GET', 'POST'])
@login_required
def login1():
    if request.method == 'POST':
        user = User(0, request.form['username'], '')
        logged_user = ModelVisitante.login(db, user)
        if logged_user != None:
            login_user(logged_user)  
            return redirect(url_for('homevisitante'))
        else:
            flash("User not found...")
            return render_template('auth/login_visitante.html')
    else:
        return render_template('auth/login_visitante.html')



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/homeadmin')
@login_required
def homeadmin():
        return render_template('homeadmin.html')



@app.route('/homeuser')
@login_required
def homeuser():
    return render_template('homeuser.html')

@app.route('/utecespacios1')
@login_required
def utecespacios1():
    return render_template('utecespacios1.html')

@app.route('/utecEstadisticas')
@login_required
def utecEstadisticas():
    return render_template('utecEstadisticas.html')


@app.route('/homevisitante')
@login_required
def homevisitante():
    return render_template('homevisitante.html')


@app.route('/protected')
@login_required
def protected():
    return "<h1>Esta es una vista protegida, solo para usuarios autenticados.</h1>"


def status_401(error):
    return redirect(url_for('login'))


def status_404(error):
    return "<h1>Página no encontrada</h1>", 404


if __name__ == '__main__':
    app.config['TESTING'] = False
    app.config.from_object(config['development'])
    csrf.init_app(app)
    app.register_error_handler(401, status_401)
    app.register_error_handler(404, status_404)
    app.run()
