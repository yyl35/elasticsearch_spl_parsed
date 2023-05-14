from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from django.conf import settings

# 设置'default' Django设置模块的名称为'celery'.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'djangoProject1.settings')

app = Celery('djangoProject1')

# 使用Django的设置模块。
app.config_from_object('django.conf:settings', namespace='CELERY')

# 从所有已注册的Django app配置中加载任务模块。
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))
