from flask import Blueprint

main = Blueprint('main', __name__)

from . import errors, views
from ..models import Permission


# 该装饰器装饰的内容可在模板中自由使用
@main.app_context_processor
def inject_permission():
    return dict(Permission=Permission)
