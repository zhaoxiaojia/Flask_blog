import os

COV = None
if os.environ.get('FLASK_COVERAGE'):
    import coverage

    COV = coverage.coverage(branch=True, include='app/*')
    COV.start()
import sys, click
from app import create_app, db
from app.models import User, Role, Permission
from flask_migrate import Migrate, upgrade

app = create_app(os.getenv('FLASKY_CONFIG') or 'default')
migrate = Migrate(app, db)


# 该装饰器装饰的内容可在shell环境中自由使用
@app.shell_context_processor
def make_shell_context():
    return dict(db=db, Role=Role, User=User, Permission=Permission)


@app.cli.command()
@click.option('--coverage/--no-coverage', default=False, help='Run tests under code coverage')
def test(coverage):
    '''Run the unit tests'''
    if coverage and not os.environ.get('FLASK_COVERAGE'):
        os.environ['FLASK_COVERAGE'] = '1'
        os.execvp(sys.executable, [sys.executable] + sys.argv)
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)
    if COV:
        COV.stop()
        COV.save()
        print('Coverage Summary')
        COV.report()
        basedir = os.path.abspath(os.path.dirname(__file__))
        covdir = os.path.join(basedir, 'tmp/coverage')
        COV.html_report(directory=covdir)
        print('HTML version:file//%s/index.html' % covdir)
        COV.erase()


@app.cli.command()
@click.option('--length', default=25, help='Number of functions to include in the profiler report.')
@click.option('--profile-dir', default=None, help='Directory where profiler data files are saved.')
def profile(length, profile_dir):
    """Start the application under the code profiler."""
    from werkzeug.contrib.profiler import ProfilerMiddleware
    app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[length], profile_dir=profile_dir)
    app.run(debug=False)


@app.cli.command
def deploy():
    """Run deployment tasks."""
    # 把数据库迁移到最新修订版本
    upgrade()
    # 创建或更新用户角色
    Role.insert_roles()
    # 确保所有用户都关注了他们自己
    User.add_self_follows()
