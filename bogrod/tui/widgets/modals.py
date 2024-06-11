from textwrap import dedent

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Grid
from textual.screen import ModalScreen
from textual.widgets import Input, Label, Footer, MarkdownViewer


class InputModal(ModalScreen):
    def __init__(self, border_title=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.border_title = border_title

    def compose(self) -> ComposeResult:
        with Container():
            text_field = Input(id='input-modal', classes="box")
            text_field.border_title = self.border_title
            yield text_field

    def on_key(self, event) -> None:
        if event.key == 'enter':
            self.dismiss(self.data())

    def data(self):
        return self.query_one('#input-modal').value


class SearchModal(ModalScreen):
    def compose(self) -> ComposeResult:
        with Grid():
            filter = Input(id='search-modal', classes="box")
            filter.border_title = 'Search'
            yield filter
            yield Label('id to search for or <column>:<value>. Empty value resets filter.')

    def on_key(self, event):
        if event.key == 'enter':
            self.dismiss(self.data())
        if event.key == 'escape':
            self.dismiss('.cancel')

    def data(self):
        return self.query_one('#search-modal').value


class HelpModal(ModalScreen):
    DEFAULT_CSS = """
    HelpModal {
        layout: grid;
        background: $background 60%;
        align: center middle;
        grid-size: 5;
    }
    HelpModal Grid {
        column-span: 2;
    }
    HelpModal Markdown {
        margin-left: 1;
        margin-right: 1;
    }
    HelpModal MarkdownViewer {
        width: 100%;
        scrollbar-size: 1 1;
    }
    """

    BINDINGS = [
        Binding(key='escape', action='cancel', description='dismiss'),
    ]

    def __init__(self, screens, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.related_screens = screens if isinstance(screens, (list, tuple)) else [screens]

    def compose(self) -> ComposeResult:
        with Grid(classes="box") as grid:
            grid.border_title = 'help'
            text = (
                '| Key | Action |\n'
                '|-----|-----|\n'
            )
            details_text = ''
            for screen in self.related_screens:
                for binding in getattr(screen, 'help_bindings', screen.BINDINGS):
                    text += f'| `{binding.key}` | {binding.description} |\n'
                details_text += dedent('\n\n' + getattr(screen, 'help_text', '') + '\n')
            text += details_text
            yield MarkdownViewer(dedent(text), id='help-text', show_table_of_contents=False)
            yield Footer()

    def on_moun(self):
        self.get_widget_by_id('help-text').scroll_to('top').focus()

    def on_key(self, event):
        if event.key == 'enter':
            self.dismiss('ok')
        if event.key == 'escape':
            self.dismiss('cancel')


class HelpableMixin:
    def compose(self) -> ComposeResult:
        # FIXME this does not work - screen must add binding to its own BINDINGS
        has_help = any(binding.action == 'help' for binding in self.BINDINGS)
        if not has_help:
            self.BINDINGS.append(Binding(key="?", action='help', description="help", priority=True, show=True))
        super().compose()

    def action_help(self):
        def on_dismiss(result):
            # self.app.pop_screen()
            pass

        related = self.related_screens if hasattr(self, 'related_screens') else self
        self.app.push_screen(HelpModal(related), on_dismiss)
