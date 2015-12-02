class FileMetaData():
    default_data = {
        'empty': True,
        'length': 0,
        'old_length': 0,
        'path': '',
        'truncated': False
    }

    def __init__(self, data={}):
        self.data = self.default_data
        self.update(data)

        if 'path' in self.data:
            self.path = self.data['path']

    def set_default_data(self):
        self.data = self.default_data
        #self.update(self.default_data)

    def set_empty(self, clear_data=True):
        print("set empty")
        self.data['empty'] = True
        if clear_data:
            self.set_default_data()

    def is_empty(self):
        return self.data['empty']

    def update_attribute(self, key, val):
        self.update_attributes(Dict([(key, val)]))

    def update(self, data):
        self.data.update(data)

    def set_length(self, length):
        print("set length for %s to %s" % (self['path'], length))
        new_m = {
            'old_length': self['length'],
            'length': length
        }
        self.data.update(new_m)

    def __getitem__(self, key):
        return self.data.__getitem__(key)

    def __setitem__(self, key, value):
        self.data.__setitem__(key, value)

    def __contains__(self, key):
        return self.data.__contains__(key)

    def __str__(self):
        return self.data.__str__()
