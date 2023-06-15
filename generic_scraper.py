#!/usr/bin/env python



############################
## VERSION INFO           ##
############################
'''
Generic HTML Scraper (light-weight).
Requires no additional python modules.
Can use Twisted if available to handle HTTP requests, parsing, and writing in parallel.
Can be run interactively or imported as module.
Scraping driven by JSON data which supports user interaction.
See README for details.

- CHANGE LOG -

VERSION: 0.2.0
* DATE: 2021-03-26
* AUTHORS: BinarySemaphore
* NOTES:
  * Started converting Steam Screanshot Scraper to Generic Scraper.
  * Designed config.json to drive scraping instructions.
  * Added HTMLParser and HTMLEntity to act as DOM for searching.

VERSION: 0.2.1
* DATE: 2021-05-27
* AUTHORS: BinarySemaphore
* NOTES:
  * Retry on Check
  * OS Valid Encode for Save
  * Minor fixes and improvements
  * Logging improvements and fixes

VERSION: 0.2.2
* DATE: 2023-05-19
* AUTHORS: BinarySemaphore
* NOTES:
  * Logging improvements for failed LOAD-SELECT combo in Iteration to show source URL if possible
  * Added continue_on_error option for ITERATE - default is false

VERSION: 0.2.3
* DATE: 2023-06-14
* AUTHORS: BinarySemaphore
* NOTES:
  * Added "_re_all" to get_filter to allow capturing all matched groups
'''

__version__ = '0.2.3'



############################
## IMPORTS                ##
############################

import os
import sys

import re
import time
import copy
import json
import logging

from html.parser import HTMLParser

try:
    import urllib.request as urllib_request
    import urllib.parse as urllib_parse
except ImportError:
    # python2.7 support?
    print('\nWARNING: Python3.5 or later is suggested (untested on this version of Python)\n')
    import urllib2 as urllib_request
    import urllib as urllib_parse

__can_parallel__ = False
try:
    from twisted.internet import reactor, threads
    from twisted.internet.defer import Deferred, inlineCallbacks, returnValue
    #__can_parallel__ = True
except ImportError:
    print('\nWARNING: Python Twisted module is suggested (download in parallel)\n')

log = logging.getLogger('main')
log.warn = log.warning  # stupidly deprecated warn for less good warning


############################
## DEFAULTS               ##
############################

USER_CONFIG_FILE = 'config.json'

RE_VAR_IN_PARAM = re.compile(
    r'{{\W{0,}(\w+)\W{0,}}}',
    re.DOTALL
)



############################
## CLASSES                ##
############################

class Result(object):
    '''
    Result container for command methods.
    Holds var (dict) for updating config vars, success status, and logging msg data. 
    '''
    def __init__(self, status, msg='', *msg_args, **var):
        '''
        Args:
            status: <bool> - required
                True or False command execution success.
            msg: <str> - optional
                Log message.
            *msg_args: <tuple> - optional
                Log message arguments for format replacement.
            **var: <dict> - optional
                Varialbe dict response from command; used for updating Config local vars.
            
        '''
        self.var = var
        self.status = status
        self.msg = msg
        self.msg_args = msg_args


class Config(object):
    '''
    Initial and Running configuration vars and processes.
    Used for instruction guiding and containing relevent processing variables.
    Create a config object based on JSON config_data.
    See __init__.
    Call next_proc to iterate command and param object.
    '''
    def __init__(self, config_data, parent_config=None):
        '''
        Args:
            config_data: <dict> - required
                Must have "process" in JSON config_data.
                JSON config_data in form:
                {
                    "vars": {
                        "<var_name>": <var_value>,
                        ...
                    },
                    "process": [
                        {
                            "command": "<command_name>",
                            "parameters": {...}
                        },
                        ...
                    }
                }
            parent_config: <Config> - optional
                Parent Config object for referencing non-local variables.
        Returns:
            Config instance.
        '''
        self.parent = parent_config
        self.var = copy.deepcopy(config_data.get('vars', {}))
        self.proc = copy.deepcopy(config_data.get('process', []))
        self.inst_limit = len(self.proc)
        self.inst_index = 0

    def __str__(self):
        return 'config<vars:%d, procs:%d, index:%d>' % (len(self.var), self.inst_limit, self.inst_index)

    def next_proc(self):
        if self.inst_index == self.inst_limit:
            return None
        proc = self.proc[self.inst_index]
        self.inst_index += 1
        return proc

    def get_val_from_any_var(self, key, default=None):
        if key not in self.var.keys():
            if self.parent:
                return self.parent.get_val_from_any_var(key)
            return default
        return self.var[key]


class Agent(object):
    '''
    Light weight HTTP requester agent.
    Read-only (GET) support
    '''
    def __init__(self, url, params={}, allow_tslash=True, tz_offset_enforce=True):
        '''
        Args:
            url: <str> - required
                URL for adding partial URL paths for requests.
            params: <dict> - optional (default empty dictionary)
                Default URL parameters merged with request parameters.
            allow_tslash: <bool> - optional (default True)
                Assume full URLs should end with a trailing slash.
            tz_offset_enforce: <bool> - optional (default True)
                Inject timezone offset cookie. Steam has JavaScript which, at runtime, adds
                this cookie instead of using response Set-Cookie. Without timezone offset,
                the latest images organized by date may not be accessible.
        Returns:
            Agent instance.
        '''
        self.allow_tslash = allow_tslash
        self.def_params = params
        self._cookies = []
        self._cookies_custom = []
        self._tz_offset_enforce = tz_offset_enforce
        self.setBase(url)
        log.debug('Agent created for base url: %s', self._base_url)

    def request(self, path='', params={}, auto_utf=True):
        '''
        GET request.
        '''
        d = threads.deferToThread(
            self._request, path=path, params=params, auto_utf=auto_utf)
        return d

    def _request(self, path='', params={}, auto_utf=True):
        if path:
            url = '/'.join([self._base_url, path])
        else:
            url = self._base_url
        if not self.allow_tslash:
            url = self._removeTrailingSlash(url)
        url = self.encodeUrlParams(url, params=params)
        log.info('GET request: %s' % url)

        request = urllib_request.Request(url, headers={'User-Agent': 'Mozilla/5.0', 'X-Screen-Width': 1080,'X-Screen-Height': 10000})
        self._handleCookies(request=request)
        
        '''
        if not auto_utf:
            import pdb
            pdb.set_trace()
        '''
        # TODO: couple issues (other than refactoring and solifying the process model args):
        '''
            1: Found last screenshot of ylands is missing content-disposition (filename):
                Link: https://steamcommunity.com/sharedfiles/filedetails/?id=1642909079
                Image: https://steamuserimages-a.akamaihd.net/ugc/936088957981405889/E857D173A30099334A707245A5328640CD08BD87/
                * invesitgate, find alternate name as retying does not seem to work.
            2: Test for paged image-grid games (ylands is single page test).
        '''

        with urllib_request.urlopen(request) as resp:
            data = resp.read()
            self._handleCookies(resp=resp)

        if auto_utf:
            data = self.encodeByteToUtf(data)

        return data, resp

    def encodeUrlParams(self, url, params={}):
        if not params:
            return url
        url_params = self.def_params.copy()
        url_params.update(params)
        url_params = urllib_parse.urlencode(url_params)
        return '%s?%s' % (url, url_params)

    def encodeForUrl(self, data):
        return urllib_parse.quote(data, safe='')

    def encodeByteToUtf(slef, data):
        return data.decode('utf-8')

    def encodeUtfToAscii(self, data):
        return str(data.encode("ascii","ignore"))

    def setBase(self, url):
        self._base_url = self._removeTrailingSlash(url)
        self._clearCookies()

    def _clearCookies(self):
        log.debug('Clearing cookies')
        self._cookies = []
        self._cookies_custom = []

    def _handleCookies(self, resp=None, request=None):
        if not self._tz_offset_enforce:
            return None
        if not self._cookies_custom:
            log.debug('Creating timezoneOffset cookie')
            # Steam is crazy about client timezone, so appeasing here
            tz_offset = time.timezone * -1
            active_dst = time.daylight * time.localtime().tm_isdst

            # Five day exp on timezoneOffset Cookie
            expire_time = time.gmtime(time.time() + 432000)
            expire_str = time.strftime('%a, %d %b %Y %H:%M:%S GMT', expire_time)

            self._cookies_custom.append('timezoneOffset=%d,%d' % (tz_offset, active_dst))
            self._cookies_custom.append('expires=%s' % expire_str)

        if resp:
            log.debug('Capturing cookies')
            self._cookies = []
            for key, value in resp.headers._headers:
                if key == 'Set-Cookie':
                    self._cookies.append(value)
        elif request:
            log.debug('Appling cookies')
            cookies_list = self._cookies.copy()
            cookies_list.extend(self._cookies_custom)
            request.add_header('Cookie', '; '.join(cookies_list))

        log.debug('Cookies: %r + %r', self._cookies, self._cookies_custom)

    def _removeTrailingSlash(self, url):
        if url.endswith('/'):
            url = url[:-1]
        return url


class HTMLEntity(object):
    '''
    HTML Entity container for tag, tag attrs (as dict), data (as list), children, and parent.
    Data appended with append_data is stripped; ignorning empty data strings.
    Children automatically added to parent on init.
    Can be printed: will print all children under pipe indent.
    '''
    def __init__(self, tag, attrs=[], parent=None):
        '''
        Args:
            tag: <str> - required
                Tag name of the HTML Entity.
            attrs: <list> - optional
                HTML Entity attributes as a list of tuple pairs.
                Converted to dict; "id" and "class" values split and will always be lists.
                All values are stripped.
            parent: <HTMLEntity> - optional
                Parent HTMLEntity.
                The parent will automatically add this HTMLEntity to parent's children list.
        Returns:
            HTMLEntity instance.
        '''
        self.tag = tag
        self.attrs = {}
        self.data = []
        self.parent = parent
        self.children = []
        if self.parent:
            self.parent.children.append(self)
        for name, value in attrs:
            if value:
                value = value.strip()
                if name in ('id', 'class'):
                    value = value.split()
            self.attrs[name] = value

    def append_data(self, data):
        data = data.strip()
        if data:
            self.data.append(data)

    def __str__(self):
        output = "ENTITY [%s]:\n" % self.tag
        if self.attrs:
            output += "- Attrs: %r\n" % self.attrs
        if self.data:
            output += "- Data: %r\n" % self.data
        if self.children:
            output += "- Children (%d):\n" % len(self.children)
            for child in self.children:
                child_outputs = str(child).split('\n')
                for child_output in child_outputs:
                    output += " |%s\n" % child_output
        return output


class HTMLParserToEntity(HTMLParser):
    '''
    Extend HTMLParser interface to build HTMLEntity classes.
    Root HTMLEntity (should be "html") is contained in document variable.
    HTMLEntity(s) will be tree-ed to parent and children per the parsing.
    Manages current and stack to handle unclosed HTML tagging.
    If current HTMLEntity becomes None somehow, any data added will go into document HTMLEntity.
    See HTMLEntity for storage details.
    '''
    document = None
    current = None
    stack = []

    def handle_starttag(self, tag, attrs):
        self.stack.append(tag)
        new_entity = HTMLEntity(tag, attrs, parent=self.current)
        if self.document is None:
            self.document = new_entity
        self.current = new_entity

    def handle_startendtag(self, tag, attrs):
        HTMLEntity(tag, attrs, parent=self.current)

    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] != tag:
            if tag in self.stack:
                while self.stack[-1] != tag:
                    self.stack.pop()
                    self.current = self.current.parent
        if self.stack:
            self.stack.pop()
        if self.current and self.current.parent:
            self.current = self.current.parent

    def handle_data(self, data):
        if self.current is None:
            if self.document is None:
                return
            self.current = self.document
        self.current.append_data(data)

    def handle_comment(self, data):
        pass


class ProgressBar(object):
    '''
    Create a progress bar in terminal.
    Line output will be: "Progress 50.0 % [>>>>>     ] (5 of 10)"
    Call update() to adjust items or item-steps completed.
    Call refresh() to output fresh progress data on same line.
    Call clear() to remove the progress bar if desired.
    '''
    def __init__(self, item_count, steps_per_item=1, width=50):
        '''
        Args:
            item_count: <int> - required
                Number of items to track progress.
                Call update(item_delta=<num>) to mark <num> of items completed.
            steps_per_item: <int> - optional (default 2)
                Number of expected steps per item to track individual progress.
                Call update(step_delta=<num>) to mark <num> of current item steps completed.
            width: <int> - optional(default 50)
                Width of the actual progress bar.
                Note: consider line output (see class desc.) for total width.
        Returns:
            ProgressBar instance.
        '''
        self.cur_item = 0
        self.cur_step = 0
        self.item_count = item_count
        self.step_count = item_count * steps_per_item
        self._width = width
        self._stepsPerChar = self.step_count / width
        self._lastOutputSize = 0

    def refresh(self):
        percent = (self.cur_step * 100.0) / self.step_count
        fill_count = int(self.cur_step / self._stepsPerChar)
        empty_count = self._width - fill_count

        out_fill = '>' * fill_count
        out_empty = ' ' * empty_count
        out_percent = '%4.1f %%' % percent

        output = 'Progress %s [%s%s] (%d of %d)' % (
            out_percent,
            out_fill,
            out_empty,
            self.cur_item,
            self.item_count
        )

        self._lastOutputSize = len(output)
        sys.stdout.write('\r' + output)
        sys.stdout.flush()

    def clear(self, output=None):
        if self._lastOutputSize:
            sys.stdout.write('\r' + ' ' * self._lastOutputSize)

    def update(self, item_delta=0, step_delta=1):
        if self.cur_item < self.item_count:
            self.cur_item += item_delta
        if self.cur_step < self.step_count:
            self.cur_step += step_delta



############################
## METHODS ENTRY          ##
############################

def start_interactive():
    '''
    Start interactive session.
    Read user args from terminal and call start entry.
    '''
    args = arg_parse()
    start(args, args['config_filename'])


def start(args, config_or_file):
    '''
    Primary entry with initialization.
    Setup logging, get or read config data, create config for instructions.
    Check for parallel processing and execute main method to start processing.
    '''
    config = None
    setup_logging(args)
    log.info('Logging setup')
    log.info('Arg Params: %r', args)

    if not isinstance(config_or_file, Config):
        log.info('Config File: %s', config_or_file)
        with open(config_or_file, 'r') as f:
            data = json.load(f)
        config = Config(data)
    else:
        log.info('Config given')
        config = config_or_file
    log.info('Config setup')
    log.debug('Config: %s', str(config))

    if __can_parallel__:
        start_twisted()
    else:
        main(config)


def start_twisted():
    '''
    Enable start with twisted.
    '''
    log.info('Starting Twisted Reactor')
    reactor.addSystemEventTrigger('before', 'shutdown', reactor_interupt)
    reactor.callWhenRunning(main, config)
    reactor.run()


############################
## METHODS MAIN           ##
############################

COMMANDS = {}


def main(config):
    '''
    Primary instruction execution and main thread.
    Check for command based methods.
    Call for running instructions in config using commands.
    '''
    log.info('Executing main method')

    global COMMANDS
    for name, cmd in globals().items():
        if name.startswith('_cmd_'):
            COMMANDS[name.replace('_cmd_', '')] = cmd
    log.debug('Available commands: %r', COMMANDS)

    while run_config_procs(config):
        pass



############################
## METHODS HANDLERS       ##
############################

def run_config_procs(config):
    '''
    Iterate instructions from config.
    Call to render vars in parameters, then execute commands.
    Handle returns from commands, updating config vars.
    '''
    log.debug('RUN CONFIG PROC')

    process = config.next_proc()
    log.debug('Next PROC: %r', process)

    if process is None:
        return False

    cmd_name = process['command']
    cmd_params = process.get('parameters', {})

    render_vars_in_params(cmd_params, config)

    cmd = COMMANDS.get(cmd_name)
    if cmd is None or not callable(cmd):
        log.error('Unrecognized command "%s"', cmd_name)
        exit(1)
    log.info('CMD Call [%s]: %r', cmd_name, cmd_params)
    result = cmd(config, **cmd_params)
    if not result.status:
        log.error('CMD FAILED [%s]: ' + result.msg, cmd_name, *result.msg_args)
        raise RuntimeError('CMD FAILED')
    if result.var:
        config.var.update(result.var)
        log.info('CMD Result: %r', result.var)

    return True
    

def render_vars_in_params(params, config):
    '''
    Check for vars in parameters.
    For each string parameter value, if a substitutable var is required, then substitute.
    '''
    for name, raw_value in params.items():
        if isinstance(raw_value, dict):
            render_vars_in_params(raw_value, config)
        elif isinstance(raw_value, str):
            rnd_index = 0
            rnd_value = ""
            for match in RE_VAR_IN_PARAM.finditer(raw_value):
                var_key = match.groups()[0]
                var_val = config.get_val_from_any_var(var_key)
                rnd_value += raw_value[rnd_index:match.start()]
                rnd_value += str(var_val)
                rnd_index = match.end()
            rnd_value += raw_value[rnd_index:]
            params[name] = rnd_value



############################
## METHODS COMMANDS       ##
############################

def _cmd_PROMPT(config, text='Input: ', **kwargs):
    '''
    '''
    _as = kwargs.get('as', 'last_result')
    from_user = input(text)
    try:
        from_user = int(from_user)
    except Exception:
        pass
    resp = { _as: from_user }
    return Result(True, **resp)


def _cmd_OUTPUT(config, text='', info=False, **kwargs):
    '''
    OUTPUT Command.
    Print text to stdout.
    Args:
        text: <str> - optional
            Text to output.
        info: <bool> - optional
            Mark output for info and debug only. Will print if verbosity 1 or 2.
    Return:
        Result (containing status, logging message and args, and vars dict for updates).
    '''
    if info and log.getEffectiveLevel() > logging.INFO:
        return Result(True)
    print(text)
    return Result(True)


def _cmd_ITERATE(config, process, **kwargs):
    '''
    '''
    _from = kwargs.pop('from')
    _as = kwargs.pop('as', 'index')
    _continue_on_error = kwargs.pop('continue_on_error', False)
    
    source = config.get_val_from_any_var(_from)
    if not source:
        return Result(False, 'Could not find %s in vars to iterate over', _from)
    if isinstance(source, list):
        for index in range(len(source)):
            sub_config = Config({
                'vars': { _as: index },
                'process': process
            }, parent_config=config)
            try:
                while run_config_procs(sub_config):
                    pass
            except RuntimeError as e:
                log.error('Iteration instance failed: %s', str(e))
                if _continue_on_error:
                    log.warn('Continue iteration: continue_on_error given')
                    log.warn('Please review the source of failure and re-execute as needed\n')
                    continue
                else:
                    return Result(False, 'Stopped iteration: no continue_on_error given')
    return Result(True)


def _cmd_ITERATE_RANGE(config, process, end, start=0, **kwargs):
    '''
    '''
    _as = kwargs.pop('as', 'index')
    for index in range(int(start), int(end) + 1):
        sub_config = Config({
            'vars': { _as: index },
            'process': process
        }, parent_config=config)
        while run_config_procs(sub_config):
            pass
    return Result(True)


def _cmd_URL_ENCODE(config, url, ignore=None, **kwargs):
    '''
    '''
    _as = kwargs.pop('as', 'last_result')
    encoded_url = urllib_parse.quote(url, ignore)
    resp = { _as: encoded_url }
    return Result(True, **resp)


def _cmd_SAVE(config, url, filename, filetype="jpg", destination="downloads", overwrite=True, retry=1, header_has_filename=False, **kwargs):
    '''
    '''
    destination = os_valid_encode(destination)
    if not os.path.isdir(destination):
        os.mkdir(destination)

    raw_data = None
    actual_filename = None
    header_filename = None
    image_agent = Agent(url, tz_offset_enforce=False)

    if header_has_filename:
        print('Downloading %s' % url)
        raw_data, resp_obj = image_agent._request(auto_utf=False)
        header_filename = resp_obj.headers.get_filename()
        if header_filename is None:
            if retry > 0:
                print('Failed to fully download: header missing expected filename: retring...')
                retry -= 1
                time.sleep(5)
                return _cmd_SAVE(config, url, filename, filetype, destination=destination, retry=retry, header_has_filename=header_has_filename, **kwargs)
            else:
                print('Failed to get filename from header: out of retries - using alternative')

    if header_filename:
        actual_filename = header_filename
    elif filename:
        actual_filename = "%s.%s" % (filename, filetype)
    else:
        print('No alternative filename given: coming up with one')
        actual_filename = "%s.%s" % (time.time(), filetype)

    # cleanup filename
    actual_filename = os_valid_encode(actual_filename)

    full_path = os.path.join(destination, actual_filename)
    if not overwrite and os.path.isfile(full_path):
        print('Skipping [OVERWRITE DISABLED]: file already exists "%s"\n' % actual_filename)
        return Result(True)

    if raw_data is None:
        print('Downloading %s' % url)
        raw_data, resp_obj = image_agent._request(auto_utf=False)

    with open(full_path, 'wb') as f:
        f.write(raw_data)
    print('Saved to "%s"\n' % actual_filename)
    return Result(True)


def _cmd_LOAD(config, url, path="", args={}, retry=5, retry_if_missing={}, **kwargs):
    '''
    LOAD Command.
    GET request from server and path, expecting HTML response.
    HTML is parsed into an tree structure of HTMLEntity objects.
    Args:
        url: <str> - required
            URL base address of server for client to access.
        path: <str> - optional (default "")
            URL Path on base address for client to request from.
        args:
            URL arguments.
            Parameters which are joined to the URL as "<url>/<path>?<arg1>&<arg2>..."
        as: <str> - optional (default "document")
            VAR name to deposit root HTMLEntity parsed from response.
    Returns:
        Result (containing status, logging message and args, and vars dict for updates).
    '''
    _as = kwargs.pop('as', 'document')

    agent = Agent(url)
    resp_data, resp_obj = agent._request(path=path, params=args)
    if not resp_data:
        return Result(False, 'No response from server')
    parser = HTMLParserToEntity()
    parser.feed(resp_data)
    parser.close()
    if not parser.document:
        return Result(False, 'Failed to get HTMLEntity document from response')
    #log.debug('Response: \n%s', str(parser.document))
    log.debug('Response root [%s] with %d children', parser.document.tag, len(parser.document.children))
    if retry_if_missing:
        config.var[_as] = parser.document
        retry_if_missing['from'] = _as
        test_res = _cmd_SELECT_ALL(config, **retry_if_missing)
        if not test_res.status or not test_res.var.get('last_result'):
            print('LOAD <retry_if_missing> check failed')
            if retry > 0:
                print('LOAD retry (%d remaining)...' % retry)
                time.sleep(2)
                retry -= 1
                return _cmd_LOAD(config, url, path=path, args=args, retry=retry, retry_if_missing=retry_if_missing, **kwargs)
    resp = {
        '_url': url,
        _as: parser.document
    }
    return Result(True, source=url, **resp)


def _cmd_SELECT(config, get_index=None, get_filter=None, as_type=None, default=None, **kwargs):
    '''
    SELECT Command.
    HTML search and get first to var <as-name>.
    Args:
        from: <str> - required
            Var name of HTMLEntity to search.
        type:
            Tag name type to search.
        as: <str> - optional (default "document")
            VAR name to deposit root HTMLEntity parsed from response.
    Returns:
        Result (containing status, logging message and args, and vars dict for updates).
    '''
    _from = kwargs.get('from', None)
    _as = kwargs.get('as', 'last_result')

    source = config.get_val_from_any_var(_from)
    if isinstance(source, list) and get_index is not None:
        try:
            resp = { _as: source[int(get_index)] }
        except IndexError:
            log.info('List index invalid using default: %r', default)
            resp = { _as: default }
        return Result(True, **resp)

    if isinstance(source, HTMLEntity):
        result = _cmd_SELECT_ALL(config, **kwargs)
        if not result.var.get(_as):
            source = config.var.get('_url', 'Unknown Source')
            return Result(False, 'Failed to select from source: %r', source)
    else:
        resp = { _as: source }
        result = Result(True, **resp)

    if result.var.get(_as):
        if isinstance(result.var[_as], list):
            result.var[_as] = result.var[_as][0]

    if get_filter:
        if get_filter.startswith('_re='):
            get_filter = get_filter.replace('_re=', '')
        if get_filter.startswith('_re_all='):
            get_filter = get_filter.replace('_re_all=', '')
            term = re.compile(get_filter, re.DOTALL)
            match = term.findall(result.var[_as])
            if match:
                result.var[_as] = match
        else:
            term = re.compile(get_filter, re.DOTALL)
            match = term.search(result.var[_as])
            if match and match.groups():
                result.var[_as] = match.groups()[0]

    if default is not None and result.var.get(_as) is None:
        result.var[_as] = default

    if as_type:
        if as_type == 'integer':
            result.var[_as] = int(result.var[_as])
    return result


def _cmd_SELECT_ALL(config, default=None, **kwargs):
    '''
    SELECT_ALL Command.
    Search based on type and list all to var <as-name>.
    Args:
        from: <str> - required
            Var name of HTMLEntity to search.
        type:
            Tag name type to search.
        as: <str> - optional (default "document")
            VAR name to deposit root HTMLEntity parsed from response.
    Returns:
        Result (containing status, logging message and args, and vars dict for updates).
    '''
    _from = kwargs.pop('from', None)
    _type = kwargs.pop('type', None)
    _id = kwargs.pop('id', None)
    _class = kwargs.pop('class', None)
    _get = kwargs.pop('get', None)
    _get_filter = kwargs.pop('get_filter', None)
    _as = kwargs.pop('as', 'last_result')
    log.debug('Select from "%s": tag=%r, id=%r', _from, _type, _id)

    source = config.get_val_from_any_var(_from)
    if isinstance(source, list):
        found = []
        for source_item in source:
            result_item = html_entity_search(source_item, _type, _id, _class, _get, _get_filter, '_tmp_last')
            if result_item.status and result_item.var.get('_tmp_last'):
                found.extend(result_item.var['_tmp_last'])
        log.debug('Found: %r', found)
        if not found:
            if default is not None:
                resp = { _as: default }
                return Result(True, **resp)
            return Result(False, 'Nothing found in any items of %r', source)
        log.debug('Storing all %d result(s) in vars "%s"', len(found), _as)
        resp = { _as: found }
        return Result(True, **resp)
    results = html_entity_search(source, _type, _id, _class, _get, _get_filter, _as)
    log.debug('Found: %r', results)
    return results



############################
## METHODS HELPERS        ##
############################

def html_entity_search(source, _type, _id, _class, _get, _get_filter, _as, default=[]):
    result = None
    possible = []

    if not source:
        return Result(False, "Could not get '%s' from config vars: %r", _from, config.var.keys())
    log.debug('Select source html [%s] with %d children', source.tag, len(source.children))

    if _type:
        res = html_entity_get_by_tag(source, _type)
        log.debug("Found %d of tag '%s'" % (len(res), _type))
        if res:
            possible.extend(res)

    if _id:
        term = None
        new_possible = []
        if _id.startswith('_re='):
            term = re.compile(_id.replace('_re=', ''), re.DOTALL)
        for entity in possible:
            if term:
                for entity_id in entity.attrs.get('id', []):
                    if term.search(entity_id):
                        new_possible.append(entity)
            elif _id in entity.attrs.get('id', []):
                new_possible.append(entity)
        log.debug("Found %d '%s' with id '%s'" % (len(new_possible), _type, _id))
        possible = new_possible

    if _class:
        new_possible = []
        for entity in possible:
            log.debug("class: %r" % entity.attrs.get('class', []))
            if _class in entity.attrs.get('class', []):
                new_possible.append(entity)
        log.debug("Found %d '%s' with class '%s'" % (len(new_possible), _type, _class))
        possible = new_possible

    if possible:
        result = possible
        log.debug('Found %d result(s)', len(result))
    else:
        if default is not None:
            resp = { _as: default }
            return Result(True, **resp)
        return Result(False, 'Could not find anything')
        
    if _get and _get.startswith('element.'):
        get_result = []
        get_select = _get.split('.')[1:]
        for entity in result:
            if get_select[0] == 'text':
                get_result.append(' '.join(entity.data))
            elif get_select[0] == 'attrs':
                attr_result = entity.attrs.get(get_select[1])
                if attr_result:
                    get_result.append(attr_result)
        result = get_result

    if _get_filter:
        filter_result = []
        if _get_filter.startswith('_re='):
            _get_filter = _get_filter.replace('_re=', '')
        term = re.compile(_get_filter, re.DOTALL)
        for result_item in result:
            match = term.search(result_item)
            if match and match.groups():
                filter_result.append(match.groups()[0])
        result = filter_result

    log.debug('Storing result(s) in vars "%s"', _as)
    resp = { _as: result }
    return Result(True, **resp)


def html_entity_get_by_tag(entity, tag):
    res = []
    if entity.tag == tag:
        res.append(entity)
    for child in entity.children:
        child_res = html_entity_get_by_tag(child, tag)
        if child_res:
            res.extend(child_res)
    return res


def os_valid_encode(raw_text):
    text = raw_text[:]
    text = text.replace('|', ' ')
    text = text.replace(':', ' ')
    text = text.replace('\\', '_')
    text = text.replace('/', '_')
    text = text.replace('*', '')
    text = text.replace('?', '')
    text = text.replace('<', '')
    text = text.replace('>', '')
    text = text.replace('\n', '')
    text = text.replace('\r', '')
    return text



############################
## METHODS SETUP          ##
############################

def setup_logging(config):
    level = config['verbosity']
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log.setLevel(level)
    log.addHandler(ch)
    ch.setFormatter(formatter)
    ch.setLevel(level)


def reactor_interupt():
    if reactor.running:
        try:
            reactor.stop()
        except:
            pass



############################
## METHODS INTERACTIVE    ##
############################

def arg_parse():
    arg_param = {
        'verbosity': logging.WARNING,
        'config_filename': USER_CONFIG_FILE
    }
    for arg in sys.argv[1:]:
        if not arg:
            continue

        if arg_param['config_filename'] is None:
            arg_param['config_filename'] = arg
            continue

        if arg.startswith('-v'):
            arg_param['verbosity'] -= (len(arg) - 1) * 10
            if arg_param['verbosity'] < logging.DEBUG:
                arg_param['verbosity'] = logging.DEBUG
        elif arg == '-c':
            # Set config_filename as None to set next loop
            arg_param['config_filename'] = None
        elif arg.startswith('--config='):
            arg_param['config_filename'] = arg.replace('--config=', '')
        elif arg == '-h' or arg == '--help':
            print_version()
            print_help()
            exit(0)
        elif arg == '--version':
            print_version()
            exit(0)
        else:
            print('UNEXPECTED ARGUMENT: %s' % arg)
            print_help()
            exit(1)
    return arg_param


def print_version():
    print('Generic HTML Scraper version %s' % __version__)


def print_help():
    print('Usage:')
    print('\t./generic_scraper.py [OPTIONS]')
    print('\tpython steam_scraper.py [OPTIONS]')
    print('\tOPTIONS:')
    print('\t-h --help : Show this message')
    print('\t--version : Show current version')
    print('\t-v : Adjust log level;',
        'Number of v\'s - 1: Info - 2: Debug')
    print('\t-c <file-path> --config=<file-path> : Specify config file.',
        'Config JSON file used to instruct scraper process (see README for details)')



############################
## TERMINAL ENTRY         ##
############################

if __name__ == '__main__':
    start_interactive()
