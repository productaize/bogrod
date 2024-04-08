from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Input


class InputModal(ModalScreen):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def compose(self) -> ComposeResult:
        with Container():
            yield Input(id='input-modal', classes="box")

    def on_key(self, event) -> None:
        if event.key == 'enter':
            self.dismiss(self.data())

    def data(self):
        return self.query_one('#input-modal').value


class SearchModal(ModalScreen):
    def compose(self) -> ComposeResult:
        with Container():
            yield Input(id='search-modal', classes="box")

    def on_key(self, event):
        if event.key == 'enter':
            self.dismiss(self.data())

    def data(self):
        return self.query_one('#search-modal').value