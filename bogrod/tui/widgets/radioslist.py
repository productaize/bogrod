from textual.widgets import SelectionList


class RadioSelectionList(SelectionList):
    """
    A selection list that only allows one item to be selected at a time
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def on_selection_list_selection_toggled(self, event):
        toggled = event.selection_index
        active = toggled in event.selection_list.selected
        self.deselect_all()
        self.select(toggled) if active else None
