from __future__ import print_function

import glob
import os
import shutil
import subprocess


class Operation(object):
    def __init__(self, name, data):
        self.name, self.data = name, data

    def __call__(self, dir='.', reverse=False):
        try:
            if not reverse:
                self.do(dir)
            else:
                self.do_reverse(dir)
            self._log(True)
        except:
            self._log(False)
            raise

    def _log(self, result):
        if result:
            s = "OK"
        else:
            s = "FAIL"
        print("""  (%s) %-4s %s""" % (self.operation, s, self.name))

    def do(self, dir):
        raise NotImplementedError

    def do_reverse(self, dir):
        raise NotImplementedError


class OperationPatch(Operation):
    def __init__(self, name, filename, data):
        super(OperationPatch, self).__init__(name, data)
        self.filename = filename

    def _call(self, dir, *extraargs):
        with open(self.filename) as f:
            subprocess.check_call(
                    ("patch", "-p1", "-f", "-s", "-t", "--no-backup-if-mismatch") + extraargs,
                    cwd=dir,
                    stdin=f,
            )

    def patch_push(self, dir):
        self._call(dir, '--fuzz=1')

    def patch_pop(self, dir):
        self._call(dir, '-R')


class OperationPatchPush(OperationPatch):
    operation = '+'

    do = OperationPatch.patch_push
    do_reverse = OperationPatch.patch_pop


class OperationPatchPop(OperationPatch):
    operation = '-'

    do = OperationPatch.patch_pop
    do_reverse = OperationPatch.patch_push


class SubOperation(Operation):
    def _log(self, result):
        if result:
            s = "OK"
        else:
            s = "FAIL"
        print("""    %-10s %-4s %s""" % ('(%s)' % self.operation, s, self.name))


class SubOperationFilesRemove(SubOperation):
    operation = "remove"

    def do(self, dir):
        name = os.path.join(dir, self.name)
        for n in glob.iglob(name):
            if os.path.isdir(n):
                shutil.rmtree(n)
            else:
                os.unlink(n)


class SubOperationFilesUnifdef(SubOperation):
    operation = "unifdef"

    def do(self, dir):
        filename = os.path.join(dir, self.name)
        ret = subprocess.call(("unifdef", "-o", filename, filename) + tuple(self.data))
        if ret == 0:
            raise RuntimeError("unifdef of %s removed nothing" % self.name)
        elif ret != 1:
            raise RuntimeError("unifdef failed")


class OperationFiles(Operation):
    operation = 'X'

    suboperations = {
        'remove': SubOperationFilesRemove,
        'rm': SubOperationFilesRemove,
        'unifdef': SubOperationFilesUnifdef,
    }

    def __init__(self, name, filename, data):
        super(OperationFiles, self).__init__(name, data)

        ops = []

        with open(filename) as f:
            for line in f:
                line = line.strip()
                if not line or line[0] == '#':
                    continue

                items = line.split()
                operation, filename = items[:2]
                data = items[2:]

                if operation not in self.suboperations:
                    raise RuntimeError('Undefined operation "%s" in series %s' % (operation, name))

                ops.append(self.suboperations[operation](filename, data))

        self.ops = ops

    def do(self, dir):
        for i in self.ops:
            i(dir=dir)


class PatchSeries(list):
    operations = {
        '+': OperationPatchPush,
        '-': OperationPatchPop,
        'X': OperationFiles,
    }

    def __init__(self, name, root, fp):
        self.name, self.root = name, root

        for line in fp:
            line = line.strip()

            if not len(line) or line[0] == '#':
                continue

            items = line.split(' ')
            operation, filename = items[:2]
            data = items[2:]

            if operation in self.operations:
                f = os.path.join(self.root, filename)
                if os.path.exists(f):
                    self.append(self.operations[operation](filename, f, data))
                else:
                    raise RuntimeError("Can't find patch %s for series %s" % (filename, self.name))
            else:
                raise RuntimeError('Undefined operation "%s" in series %s' % (operation, name))

    def __call__(self, cond=bool, dir='.', reverse=False):
        if not reverse:
            l = self
        else:
            l = self[::-1]
        for i in l:
            if cond(i):
                i(dir=dir, reverse=reverse)

    def __repr__(self):
        return '<%s object for %s>' % (self.__class__.__name__, self.name)
