from textual.app import App

from bogrod.tui.vulnlist import VulnerabilityList


class BogrodApp(App):
    CSS_PATH = "styles.tcss"
    TITLE = "bogrod"
    _on_mount_cb = []

    def __init__(self, *args, bogrod=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.bogrod = bogrod
        list_screen = VulnerabilityList(bogrod=self.bogrod)
        self.install_screen(list_screen, 'vulnerability-list')

    def on_mount(self):
        self.push_screen('vulnerability-list')
