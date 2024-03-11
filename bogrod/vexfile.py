import yaml


class BogrodVEXFile:
    def __init__(self, data):
        self.data = data

    def from_file(self, path):
        with open(path, 'r') as fin:
            print("Reading vex: ", path)
            self.vex = yaml.safe_load(fin)
        return BogrodVEXFile(self.vex)

