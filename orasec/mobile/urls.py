from django.urls import path

from orasec.mobile import api, views

urlpatterns = [
    # web: link / revoke phones
    path("orasec/mobile/", views.devices, name="orasec_mobile_devices"),
    path("orasec/mobile/code/", views.new_code, name="orasec_mobile_new_code"),
    path("orasec/mobile/devices/<int:did>/revoke/", views.revoke, name="orasec_mobile_revoke"),
    # app API (the only OraSec path reachable without Cloudflare Access; device-token auth)
    path("api/v2/orasec/mobile/server/", api.server_info),
    path("api/v2/orasec/mobile/link/", api.link, name="orasec_mobile_api_link"),
    path("api/v2/orasec/mobile/logout/", api.logout),
    path("api/v2/orasec/mobile/me/", api.me),
    path("api/v2/orasec/mobile/plugins/", api.plugins),
    path("api/v2/orasec/mobile/push/register/", api.push_register),
    path("api/v2/orasec/mobile/push/unregister/", api.push_unregister),
    path("api/v2/orasec/mobile/push/settings/", api.push_settings),
    path("api/v2/orasec/mobile/push/test/", api.push_test),
    path("api/v2/orasec/mobile/dashboard/", api.dashboard),
    path("api/v2/orasec/mobile/findings/", api.findings),
    path("api/v2/orasec/mobile/findings/<int:fid>/", api.finding_detail),
    path("api/v2/orasec/mobile/findings/<int:fid>/note/", api.finding_note),
    path("api/v2/orasec/mobile/findings/<int:fid>/close/", api.finding_close),
    path("api/v2/orasec/mobile/findings/<int:fid>/assign/", api.finding_assign),
    path("api/v2/orasec/mobile/assets/", api.assets),
    path("api/v2/orasec/mobile/assets/<path:key>/", api.asset_detail),
    path("api/v2/orasec/mobile/attacks/", api.attacks),
    path("api/v2/orasec/mobile/code/", api.code),
    path("api/v2/orasec/mobile/risks/", api.risks),
    path("api/v2/orasec/mobile/risks/<int:rid>/", api.risk_detail),
    path("api/v2/orasec/mobile/compliance/", api.compliance),
    path("api/v2/orasec/mobile/connectors/", api.connectors),
    path("api/v2/orasec/mobile/my-work/", api.my_work),
]

