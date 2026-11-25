from django.db.models.signals import post_save
from django.dispatch import receiver

from orasec.announcement.models import Announcement, UserAnnouncement
from orasec.user.models import OraSec_User


@receiver(post_save, sender=OraSec_User)
def add_announcement_to_new_user(sender, instance, **kwargs):
    announcement = Announcement.objects.first()
    if announcement is not None:
        UserAnnouncement.objects.get_or_create(
            user=instance, announcement=announcement,
        )


@receiver(post_save, sender=Announcement)
def announcement_post_save(sender, instance, created, **kwargs):
    if created:
        UserAnnouncement.objects.bulk_create(
            [
                UserAnnouncement(
                    user=user_id, announcement=instance,
                )
                for user_id in OraSec_User.objects.all()
            ],
        )
