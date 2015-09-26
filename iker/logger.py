# -*- coding: utf-8 -*-
# borja@libcrack.so
# jue jun 25 20:05:47 CEST 2015

import logging
import os

logger_name = 'iker'
default_log_level = 'info'


class Logger:

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    DEFAULT_FORMAT = '%(asctime)s %(module)s [%(levelname)s]: %(message)s'
    SYSLOG_FORMAT = logger_name + \
        ': %(asctime)s %(module)s [%(levelname)s]: %(message)s'
    __formatter = logging.Formatter(DEFAULT_FORMAT)
    __streamhandler = None

    # load the console handler by default
    # it will be removed in daemon mode
    __streamhandler = logging.StreamHandler()
    __streamhandler.setFormatter(__formatter)
    logger.addHandler(__streamhandler)

    def remove_file_handler(filepath):
        """
        Removes a file handler using the filepath
        (Useful when you need to stop logging into current file and start
            logging into another logfile)
        This methods iterates the Logger.logger.handlers list looking for handlers
            matching the especified filepath. If a matching FileHandler is found,
            it will be permanently removed.
        """
        for handler in Logger.logger.handlers:
            if isinstance(handler, logging.FileHandler):
                if handler.baseFilename and handler.baseFilename == filepath:
                    print(
                        "Logger: removing handler for %s" %
                        handler.baseFilename)
                    Logger.logger.removeHandler(handler)

    remove_file_handler = staticmethod(remove_file_handler)

    def remove_console_handler():
        """
        Removes the stream handler
        (Useful when agent starts in daemon mode)
        """
        if Logger.__streamhandler:
            Logger.logger.removeHandler(Logger.__streamhandler)

    remove_console_handler = staticmethod(remove_console_handler)

    def _add_file_handler(file, log_level=None):
        """
        log to file (file should be log->file in configuration)
        """
        dir = file.rstrip(os.path.basename(file))
        if not os.path.isdir(dir):
            try:
                os.makedirs(dir, 0o0755)
            except OSError as e:
                print("Logger: Error adding file handler,",
                      "can not create log directory (%s): %s" % (dir, e))
                return

        try:
            handler = logging.FileHandler(file)
        except IOError as e:
            print("Logger: Error adding file handler: %s" % (e))
            return

        handler.setFormatter(Logger.__formatter)
        if log_level:  # modify log_level
            handler.setLevel(log_level)
        Logger.logger.addHandler(handler)

    _add_file_handler = staticmethod(_add_file_handler)

    def add_file_handler(file, log_level=None):
        Logger._add_file_handler(file)
        if log_level is not None:
            Logger.set_verbose(log_level)

    add_file_handler = staticmethod(add_file_handler)

    def add_error_file_handler(file):
        """
        Error file handler
        the purpouse of this handler is to only log error and critical messages
        """
        Logger._add_file_handler(file, logging.ERROR)

    add_error_file_handler = staticmethod(add_error_file_handler)

    def add_syslog_handler(address):
        """
        Send events to a remote syslog
        """
        from logging.handlers import SysLogHandler
        handler = SysLogHandler(address)
        handler.setFormatter(logging.Formatter(Logger.SYSLOG_FORMAT))
        Logger.logger.addHandler(handler)

    add_syslog_handler = staticmethod(add_syslog_handler)

    def set_verbose(verbose='info'):
        """
        Show DEBUG messages or not
        modifying the global (logger, not handler) threshold level
        """
        if verbose.lower() == 'debug':
            Logger.logger.setLevel(logging.DEBUG)
        elif verbose.lower() == 'info':
            Logger.logger.setLevel(logging.INFO)
        elif verbose.lower() == 'warning':
            Logger.logger.setLevel(logging.WARNING)
        elif verbose.lower() == 'error':
            Logger.logger.setLevel(logging.ERROR)
        elif verbose.lower() == 'critical':
            Logger.logger.setLevel(logging.CRITICAL)
        else:
            Logger.logger.setLevel(logging.INFO)

    set_verbose = staticmethod(set_verbose)

    def next_verbose_level(verbose):
        levels = ['debug', 'info', 'warning', 'error', 'critical']
        if verbose in levels:
            index = levels.index(verbose)

            if index > 0:
                return levels[index - 1]

        return verbose

    next_verbose_level = staticmethod(next_verbose_level)

    def test():
        Logger.set_verbose('debug')
        Logger.add_file_handler('./logger.log')
        Logger.add_error_file_handler('./logger_error.log')
        Logger.remove_console_handler()
        logger = Logger.logger
        logger.debug("un mensaje de debug")
        logger.info("un mensaje de informacion")
        logger.warning("un mensaje de aviso")
        logger.error("un mensaje de error")
        logger.critical("un mensaje critico")

log_dir = './'
logfile_path = '%s/%s.log' % (log_dir, logger_name)
errfile_path = '%s/%s.log' % (log_dir, logger_name)
Logger.add_file_handler(logfile_path)
# Logger.add_error_file_handler(errfile_path)
# Logger.remove_console_handler()
Logger.set_verbose(default_log_level)

# vim:ts=4 sts=4 tw=79 expandtab:
