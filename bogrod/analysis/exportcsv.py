import csv


class DataExporter:
    def __init__(self, data, separator='_'):
        """
        Initialize with a list of dictionaries.
        :param data: List of dictionaries (can be nested).
        :param separator: String used to join nested keys (e.g., 'info_city').
        """
        self.separator = separator
        self.flat_data = [self._flatten(row) for row in data]

    def _flatten(self, d, parent_key=''):
        """Internal recursive method to flatten nested dictionaries."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{self.separator}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten(v, new_key).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def to_csv(self, filename):
        """Exports the flattened data to a CSV file."""
        if not self.flat_data:
            print("No data to export.")
            return

        # Get headers from the first row
        headers = self.flat_data[0].keys()

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(self.flat_data)
            print(f"Successfully exported to {filename}")
        except OSError as e:
            print(f"Error writing to file: {e}")

    def get_data(self):
        """Returns the flattened list of dictionaries."""
        return self.flat_data


# --- Example Usage ---
if __name__ == "__main__":
    raw_data = [
        {"name": "Alice", "info": {"age": 30, "city": "New York"}, "meta": {"id": 1, "status": "active"}},
        {"name": "Bob", "info": {"age": 25, "city": "Los Angeles"}, "meta": {"id": 2, "status": "inactive"}},
    ]

    # Create the exporter instance
    exporter = DataExporter(raw_data, separator='.')

    # Option 1: Export to CSV
    exporter.to_csv("my_data.csv")

    # Option 2: Get the flattened list for other uses
    print(exporter.get_data())
    # Output: [{'name': 'Alice', 'info.age': 30, 'info.city': 'New York', ...}, ...]
