from . import tf_cfg

STATE_BEGIN_START = "begin_start"
STATE_STARTED = "started"
STATE_STOPPED = "stopped"
STATE_ERROR = "error"

class Stateful(object):
    state = STATE_STOPPED
    stop_procedures = []

    def run_start(self):
        """ Shoul be overrided """
        pass

    def restart(self):
        self.stop()
        self.start()

    def start(self, obj=""):
        """ Try to start object """
        if self.state != STATE_STOPPED:
            if obj == "":
                tf_cfg.dbg(3, "Not stopped")
            else:
                tf_cfg.dbg(3, "%s not stopped" % obj)
            return
        self.state = STATE_BEGIN_START
        self.run_start()
        self.state = STATE_STARTED

    def force_stop(self):
        """ Stop object """
        for stop_proc in self.stop_procedures:
            try:
                stop_proc()
            except Exception as exc:
                tf_cfg.dbg(1, 'Exception in stoping Tempesta: %s' % str(exc))
                self.state = STATE_ERROR

        if self.state != STATE_ERROR:
            self.state = STATE_STOPPED

    def stop(self, obj=""):
        """ Try to stop object """
        if self.state != STATE_STARTED and self.state != STATE_BEGIN_START:
            if obj == "":
                tf_cfg.dbg(3, "Not started")
            else:
                tf_cfg.dbg(3, "%s not started" % obj)
            return
        self.force_stop()
