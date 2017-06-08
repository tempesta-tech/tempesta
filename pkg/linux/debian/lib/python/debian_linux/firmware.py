import re


class FirmwareFile(object):
    def __init__(self, binary, desc=None, source=None, version=None):
        self.binary = binary
        self.desc = desc
        self.source = source
        self.version = version


class FirmwareSection(object):
    def __init__(self, driver, files, licence):
        self.driver = driver
        self.files = files
        self.licence = licence


class FirmwareWhence(list):
    def __init__(self, file):
        self.read(file)

    def read(self, file):
        in_header = True
        driver = None
        files = {}
        licence = None
        binary = []
        desc = None
        source = []
        version = None

        for line in file:
            if line.startswith('----------'):
                if in_header:
                    in_header = False
                else:
                    # Finish old section
                    if driver:
                        self.append(FirmwareSection(driver, files, licence))
                    driver = None
                    files = {}
                    licence = None
                continue

            if in_header:
                continue

            if line == '\n':
                # End of field; end of file fields
                for b in binary:
                    # XXX The WHENCE file isn't yet consistent in its
                    # association of binaries and their sources and
                    # metadata.  This associates all sources and
                    # metadata in a group with each binary.
                    files[b] = FirmwareFile(b, desc, source, version)
                binary = []
                desc = None
                source = []
                version = None
                continue

            match = re.match(
                r'(Driver|File|Info|Licen[cs]e|Source|Version'
                r'|Original licen[cs]e info(?:rmation)?):\s*(.*)\n',
                line)
            if match:
                keyword, value = match.group(1, 2)
                if keyword == 'Driver':
                    driver = value.split(' ')[0].lower()
                elif keyword == 'File':
                    match = re.match(r'(\S+)(?:\s+--\s+(.*))?', value)
                    binary.append(match.group(1))
                    desc = match.group(2)
                elif keyword in ['Info', 'Version']:
                    version = value
                elif keyword == 'Source':
                    source.append(value)
                else:
                    licence = value
            elif licence is not None:
                licence = (licence + '\n' +
                           re.sub(r'^(?:[/ ]\*| \*/)?\s*(.*?)\s*$', r'\1', line))

        # Finish last section if non-empty
        for b in binary:
            files[b] = FirmwareFile(b, desc, source, version)
        if driver:
            self.append(FirmwareSection(driver, files, licence))
