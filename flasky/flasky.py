import os
from app import create_app, db, socketio
from app.models import User, Role
from flask_migrate import Migrate
import pymysql
import click
from werkzeug.contrib.fixers import ProxyFix

pymysql.install_as_MySQLdb()

app = create_app(os.getenv('FLASK_CONFIG') or 'default')
app.wsgi_app = ProxyFix(app.wsgi_app)
migrate = Migrate(app, db)

@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role)

@app.cli.command()
@click.option('--drop', is_flag=True, help='Create after drop')
def initdb(drop):
    """初始化数据库"""
    if drop:
        click.confirm('This optration will delete the database, do you want to continue', abort=True)
        db.drop_all()
        click.echo('Drop tables.')
        db.create_all()
        click.echo('Initialized databases.')


COV=None
if os.environ.get('FLASK_COVERAGE'):
    import coverage
    COV = coverage.coverage(branch=True, include='app/*')
    COV.start()

@app.cli.command()
@click.option('--coverage/--no-coverage', default=False, help='Run tests under code coverage')
def test(coverage):
    """Run the unit tests."""
    if coverage and not os.environ.get('FLASK_COVERAGE'):
        os.environ['FLASK_COVERAGE']=1
        os.excvp(sys.executable, [sys.executable] + sys.argv)
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)
    if COV:
        COV.stop()
        COV.save()
        print('Coverage Summary:')
        COV.report()
        basdir = os.abspath(os.path.dirname(__file__))
        covdir = os.path.join(basdir, 'tmp/coverage')
        COV.html_report(directory=covdir)
        print('HTML version:file//%s/index.html' % covdir)
        COV.erase()
    
if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0')
