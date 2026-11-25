import logging

from django.core.management.base import BaseCommand
from django.db import connection

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    """
    Textquestions for surveys need to be modified after loading the fixture
    as they contain an instance dependant polymorphic content id
    """

    help = "Usage: manage.py migration_textquestions"

    def handle(self, *args, **options):
        logger.info("Started migrating textquestions ...")

        update_textquestions = """UPDATE orasec_question
SET polymorphic_ctype_id = (
    SELECT id
    FROM django_content_type
    WHERE app_label = 'orasec'
      AND model = 'textquestion')
WHERE
    id IN (SELECT question_ptr_id
           FROM orasec_textquestion)"""

        with connection.cursor() as cursor:
            cursor.execute(update_textquestions)

        logger.info("Finished migrating textquestions")
