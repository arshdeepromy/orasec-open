from django.urls import path

from orasec.ora import views

W = "orasec/ora/api/"
A = "api/v2/orasec/mobile/ora/"

urlpatterns = [
    path("orasec/ora/settings/", views.settings_page, name="orasec_ora_settings"),
    path("orasec/ora/assets/<str:name>", views.asset, name="orasec_ora_asset"),
    # web (session)
    path(W + "status/", views.status, name="orasec_ora_status"),
    path(W + "chat/", views.chat, name="orasec_ora_chat"),
    path(W + "conversations/", views.conversations),
    path(W + "conversations/<int:cid>/", views.conversation),
    path(W + "conversations/<int:cid>/delete/", views.conversation_delete),
    path(W + "messages/<int:mid>/feedback/", views.feedback),
    path(W + "proposals/<str:pid>/", views.proposal),
    path(W + "preference/", views.preference),
    path(W + "memories/", views.memories),
    path(W + "memories/forget/", views.forget),
    path(W + "guides/<slug:gid>/", views.guide),
    # phone app (device token; inside the Cloudflare Access bypass for /api/v2/orasec/mobile)
    path(A + "status/", views.app_status),
    path(A + "chat/", views.app_chat),
    path(A + "conversations/", views.app_conversations),
    path(A + "conversations/<int:cid>/", views.app_conversation),
    path(A + "conversations/<int:cid>/delete/", views.app_conversation_delete),
    path(A + "messages/<int:mid>/feedback/", views.app_feedback),
    path(A + "proposals/<str:pid>/", views.app_proposal),
    path(A + "preference/", views.app_preference),
    path(A + "memories/", views.app_memories),
    path(A + "memories/forget/", views.app_forget),
]

