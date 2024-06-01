from typing import ClassVar

from rich.style import Style
from textual.binding import Binding
from textual.widgets import DataTable


class MultiSelectDataTable(DataTable):
    """ A DataTable that allows selecting multiple rows

    This class extends DataTable to allow selecting multiple rows.
    All selected rows are highlighted with a customized style background,
    CSS datatable--selected-rows. Alternatively, specify the style by setting
    MultiSelectDataTable.selected_rows_style.

    Usage:
        - To select/deselect a row, move the cursor to the row and press the space key.
        - To select/deselect all selected rows, press control+space.
        - To clear all selected rows programmatically, call clear_selected_rows().
        - To set the list of selected rows programmatically, call select_rows().
        - To get the list of selected rows, access the selected_rows attribute, the set
          of row indexes.
    """
    BINDINGS = [
        Binding("space", "select_cursor", "Select", show=False),
        Binding("ctrl+@", "select_rows", "Toggle selection (ctrl+space)", show=False),  # control+space
        Binding("up", "cursor_up", "Cursor Up", show=False),
        Binding("down", "cursor_down", "Cursor Down", show=False),
        Binding("right", "cursor_right", "Cursor Right", show=False),
        Binding("left", "cursor_left", "Cursor Left", show=False),
        Binding("pageup", "page_up", "Page Up", show=False),
        Binding("pagedown", "page_down", "Page Down", show=False),
    ]

    DEFAULT_CSS = DataTable.DEFAULT_CSS + """
    MultiSelectDataTable > .datatable--cursor {
        background: $primary-lighten-3;
    }
    MultiSelectDataTable > .datatable--selected-rows {
        color: $text-muted;
        background: $primary-background-lighten-3;
    }
    """

    COMPONENT_CLASSES: ClassVar[set[str]] = DataTable.COMPONENT_CLASSES | {
        # additional style for MultiSelectDataTable
        "datatable--selected-rows",
    }

    selected_rows_style = Style(bgcolor="white")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.selected_rows = set()

    def action_select_cursor(self) -> None:
        # called by space
        super().action_select_cursor()
        row_index = self.cursor_coordinate.row
        if row_index is not None:
            if row_index in self.selected_rows:
                self.selected_rows.remove(row_index)
            else:
                self.selected_rows.add(row_index)
            # we have to clear all caches to force applying new styles
            self._clear_caches()
            self.refresh_row(row_index)
        self.app.log(f"Selected rows: {self.selected_rows}")

    def action_select_rows(self):
        # called by control+space
        if self.selected_rows:
            self.clear_selected_rows()
            self._clear_caches()
            self.refresh()
        else:
            for row_index in range(len(self.rows)):
                self.selected_rows.add(row_index)
            self._clear_caches()
            self.refresh()

    def _get_row_style(self, row_index: int, base_style: Style) -> Style:
        if row_index in self.selected_rows:
            try:
                style = self.get_component_styles("datatable--selected-rows").rich_style
            except KeyError:
                style = self.selected_rows_style
        else:
            style = super()._get_row_style(row_index, base_style)
        return style

    def select_rows(self, rows):
        """ Select the given list of rows

        Args:
            rows: a list of row indexes to select
        """
        self.selected_rows = set(rows)
        self._clear_caches()
        self.refresh()

    def clear_selected_rows(self):
        """ Clear all selected rows """
        self.selected_rows.clear()
        self._clear_caches()
        self.refresh()
