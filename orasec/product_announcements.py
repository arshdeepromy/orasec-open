"""
Product announcements (removed).

Upstream used these hooks to inject upgrade/upsell banners and API response keys. OraSec is the full product, so every
announcement is a no-op. The classes keep their call signatures because import, error and middleware code calls them.
"""


class ProductAnnouncementManager:

    """No-op base: never adds banners to the session or keys to API responses."""

    def __init__(self, *args, **kwargs):
        return


class ErrorPageProductAnnouncement(ProductAnnouncementManager):
    pass


class LargeScanSizeProductAnnouncement(ProductAnnouncementManager):
    pass


class LongRunningRequestProductAnnouncement(ProductAnnouncementManager):
    pass


class ScanTypeProductAnnouncement(ProductAnnouncementManager):
    pass
