class Symbol(object):
    def __init__(self, name, module, version, export):
        self.name, self.module = name, module
        self.version, self.export = version, export

    def __eq__(self, other):
        if not isinstance(other, Symbol):
            return NotImplemented

        # Symbols are resolved to modules by depmod at installation/
        # upgrade time, not compile time, so moving a symbol between
        # modules is not an ABI change.  Compare everything else.
        if self.name != other.name:
            return False
        if self.version != other.version:
            return False
        if self.export != other.export:
            return False

        return True

    def __ne__(self, other):
        ret = self.__eq__(other)
        if ret is NotImplemented:
            return ret
        return not ret


class Symbols(dict):
    def __init__(self, file=None):
        if file:
            self.read(file)

    def read(self, file):
        for line in file:
            version, name, module, export = line.strip().split()
            self[name] = Symbol(name, module, version, export)

    def write(self, file):
        for s in sorted(self.values(), key=lambda i: i.name):
            file.write("%s %s %s %s\n" %
                    (s.version, s.name, s.module, s.export))
