.. _api:

Thug API
========


Thug provides a Python Application Program Interface (API) which can be used by external 
tools to easily interface with Thug. Basic usage of the Thug API is simple and just
requires subclassing the ThugAPI class. Thug class (defined in *src/thug.py*) is a
great example of such basic usage and it clearly illustrates all the details that should
be needed in almost every scenario.

Using Thug API is really straightforward as you can see below

.. code-block:: sh

    ~ $ python
    Python 2.7.10 (default, Nov 18 2015, 17:37:17) 
    [GCC 4.8.5] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> from thug.ThugAPI import ThugAPI
    >>> dir(ThugAPI)
    ['_ThugAPI__run', '__call__', '__class__', '__delattr__', '__dict__', '__doc__', '__format__', '__getattribute__', '__hash__', '__implemented__', '__init__', '__module__', '__new__', '__providedBy__', '__provides__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'add_jsclassifier', 'add_sampleclassifier', 'add_urlclassifier', 'analyze', 'disable_acropdf', 'disable_honeyagent', 'disable_javaplugin', 'disable_shockwave_flash', 'get_broken_url', 'get_delay', 'get_elasticsearch_logging', 'get_events', 'get_extensive', 'get_file_logging', 'get_json_logging', 'get_maec11_logging', 'get_mongodb_address', 'get_proxy', 'get_referer', 'get_threshold', 'get_timeout', 'get_useragent', 'get_vt_runtime_apikey', 'get_web_tracking', 'log_event', 'log_init', 'run_local', 'run_remote', 'set_acropdf_pdf', 'set_ast_debug', 'set_broken_url', 'set_debug', 'set_delay', 'set_elasticsearch_logging', 'set_events', 'set_extensive', 'set_file_logging', 'set_http_debug', 'set_javaplugin', 'set_json_logging', 'set_log_dir', 'set_log_output', 'set_log_quiet', 'set_maec11_logging', 'set_mongodb_address', 'set_no_cache', 'set_no_fetch', 'set_proxy', 'set_referer', 'set_shockwave_flash', 'set_threshold', 'set_timeout', 'set_useragent', 'set_verbose', 'set_vt_query', 'set_vt_runtime_apikey', 'set_vt_submit', 'set_web_tracking', 'usage', 'version']


The following example explains how to properly make a basic use of the Thug API. Take
a look at the interface definition below for more advanced scenarios.

.. code-block:: python

    from thug.ThugAPI import ThugAPI

    class TestAPI(ThugAPI):
        def __init__(self):
            ThugAPI.__init__(self)

        def analyze(self, url):
            # Set useragent to Internet Explorer 9.0 (Windows 7)
            self.set_useragent('win7ie90')

            # Set referer to http://www.honeynet.org
            self.set_referer('http://www.honeynet.org')

            # Enable file logging mode
            self.set_file_logging()

            # Enable JSON logging mode (requires file logging mode enabled)
            self.set_json_logging()

            # Enable MAEC 1.1 logging mode (requires file logging mode enabled)
            self.set_maec11_logging()

            # [IMPORTANT] The following three steps should be implemented (in the exact
            # order of this example) almost in every situation when you are going to
            # analyze a remote site.

            # Initialize logging
            self.log_init(url)

            # Run analysis
            self.run_remote(url)

            # Log analysis results
            self.log_event()

    if __name__ == "__main__":
        t = TestAPI()
        t.analyze("http://www.google.com")


Take a look at how the test suite automation scripts in *samples/steps/* directory make 
use of the Thug API for an example of how to perform a local file analysis.

Thug API interface definition is reported below for convenience.

.. code-block:: python


    class IThugAPI(zope.interface.Interface):
        def version():
            """
            Print Thug version and exit

            @return: None
            """

        def get_useragent():
            """
            get_useragent

            Return the emulated user agent

            @return: user agent string
            """

        def set_useragent(useragent):
            """
            set_useragent

            Set the user agent to emulate

            @param useragent: the user agent to emulate
            @type useragent: C{str}
            @return: None
            """

        def get_events():
            """
            get_events

            Return the DOM events to emulate
            Note: the load and mousemove are emulated by default and are not included in
            the returned list

            @return: List of the DOM events to emulate
            """

        def set_events(events):
            """
            set_events

            Set the DOM events to emulate
            Note: the load and mousemove events are emulated by default and do not
            need to be added through set_events

            @param events: comma separated list of DOM events to emulate
            @type events: C{str}
            @return: None
            """

        def get_delay():
            """
            get_delay

            Return the maximum setTimeout/setInterval delay value (in milliseconds)

            @return: maximum delay value (in milliseconds)
            """

        def set_delay(delay):
            """
            set_delay

            Set a maximum setTimeout/setInterval delay value (in milliseconds)

            @param delay: maximum delay value (in milliseconds)
            @type delay: C{int}
            @return: None
            """

        def get_file_logging():
            """
            get_file_logging

            Return True if file logging mode is enabled, False otherwise.

            @return: boolean
            """

        def set_file_logging():
            """
            set_file_logging

            Enable file logging mode

            @return: None
            """

        def get_json_logging():
            """
            get_json_logging

            Return True if JSON logging mode is enabled, False otherwise.

            @return: boolean
            """

        def set_json_logging():
            """
            set_JSON_logging

            Enable JSON logging mode

            @return: None
            """

        def get_maec11_logging():
            """
            get_maec11_logging

            Return True if MAEC 1.1 logging mode is enabled, False otherwise.

            @return: boolean
            """

        def set_maec11_logging():
            """
            set_maec11_logging

            Enable MAEC 1.1 logging mode

            @return: None
            """

        def get_referer():
            """
            get_referer

            Return the emulated referer

            @return: referer value
            """

        def set_referer(referer):
            """
            set_referer

            Set the referer to be emulated

            @param referer: referer
            @type referer: C{str}
            @return: None
            """

        def get_proxy():
            """
            get_proxy

            Get the proxy server to be used for estabilishing the connection

            @return: proxy server
            """

        def set_proxy(proxy):
            """
            set_proxy

            Set the proxy server to be used for estabilishing the connection

            @param proxy: proxy server
            @type proxy: C{str}
            @return: None
            """

        def set_no_fetch():
            """
            set_no_fetch

            Prevent remote content fetching in any case

            @return: None
            """

        def set_verbose():
            """
            set_verbose

            Enable Thug verbose mode

            @return: None
            """

        def set_debug():
            """
            set_debug

            Enable Thug debug mode

            @return: None
            """

        def set_no_cache():
            """
            set_no_cache

            Disable local web cache

            @return: None
            """

        def set_ast_debug():
            """
            set_ast_debug

            Enable Thug AST debug mode

            @return: None
            """

        def set_http_debug():
            """
            set_http_debug

            Enable Thug HTTP debug mode

            @return: None
            """

        def set_acropdf_pdf(acropdf_pdf):
            """
            set_acropdf_pdf

            Set the Adobe Acrobat Reader version

            @param acropdf_pdf: Adobe Acrobat Reader version
            @type acropdf_pdf: C{str}
            @return: None
            """

        def disable_acropdf():
            """
            disable_acropdf

            Disable Adobe Acrobat Reader

            @return: None
            """

        def set_shockwave_flash(shockwave):
            """
            set_shockwave_flash

            Set the Shockwave Flash version (supported versions: 8, 9, 10, 11, 12)

            @param shockwave: Shockwave Flash version
            @type shockwave: C{str}
            @return: None
            """

        def disable_shockwave_flash():
            """
            disable_shockwave_flash

            Disable Shockwave Flash

            @return: None
            """

        def set_javaplugin(javaplugin):
            """
            set_javaplugin

            Set the Java plugin version

            @param javaplugin: Java plugin version
            @type javaplugin: C{str}
            @return: None
            """

        def disable_javaplugin():
            """
            disable_javaplugin

            Disable Java plugin

            @return: None
            """

        def get_threshold():
            """
            get_threshold

            Get the maximum number of pages to fetch

            @return: the maximum number of pages to fetch
            """

        def set_threshold(threshold):
            """
            set_threshold

            Set the maximum number of pages to fetch

            @param threshold: the maximum number of pages to fetch
            @type threshold: C{int}
            @return: None
            """

        def get_extensive():
            """
            get_extensive

            Get the current extensive fetch of linked pages mode

            @return: None
            """

        def set_extensive():
            """
            set_extensive

            Set the extensive fetch of linked pages mode

            @return: None
            """

        def get_timeout():
            """
            get_timeout

            Get the analysis timeout (in seconds)

            @return: the analysis timeout (in seconds)
            """

        def set_timeout(timeout):
            """
            set_timeout

            Set the analysis timeout (in seconds)

            @param timeout: the analysis timeout (in seconds)
            @type timeout: C{int}
            @return: None
            """

        def get_broken_url():
            """
            get_broken_url

            Get the broken URL mode

            @return mode: broken URL mode
            """

        def set_broken_url():
            """
            set_broken_url

            Set the broken URL mode

            @return: None
            """

        def disable_honeyagent():
            """
            disable_honeyagent

            Disable HoneyAgent Java sandbox analysis

            @return: None
            """

        def log_init(url):
            """
            log_init

            Initialize logging subsystem

            @param url: URL to analyze
            @type url: C{str}
            @return: None
            """

        def set_log_dir(logdir):
            """
            set_log_dir

            Set the log output directory

            @param logdir: the log output directory
            @type logdir: C{str}
            @return: None
            """

        def set_log_output(output):
            """
            set_log_output

            Set the log output file

            @param output: the log output file
            @type output: C{str}
            @return: None
            """

        def set_log_quiet():
            """
            set_log_quiet

            Disable console logging

            @return: None
            """

        def set_vt_query():
            """
            set_vt_query

            Enable VirusTotal queries for sample analysis

            @return: None
            """

        def set_vt_submit():
            """
            set_vt_submit

            Enable VirusTotal samples submit

            @return: None
            """

         def get_vt_runtime_apikey():
            """
            get_vt_runtime_apikey

            Get the VirusTotal API key set as runtime parameter (not the one defined in
            the configuration file)

            @return: string
            """

        def set_vt_runtime_apikey():
            """
            set_vt_runtime_apikey

            Set the key to be used when interacting with VirusTotal APIs, overriding
            any static value defined in virustotal.conf

            @return: None
            """

        def get_mongodb_instance():
            """
            get_mongodb_instance

            Get the address ("host:port") of the MongoDB instance specified at runtime
            (not the one from the logging.conf file)
            """

        def set_mongodb_instance():
            """
            set_mongodb_instance

            Set the address ("host:port") of a running MongoDB instance to be used at runtime

            @return: None
            """

        def get_web_tracking():
            """
            get_web_tracking

            Return True if web client tracking inspection is enabled, False otherwise.

            @return: bool
            """

        def set_web_tracking():
            """
            set_web_tracking

            Enable web client tracking inspection

            @return: None
            """

        def add_urlclassifier(rule):
            """
            add_urlclassifier

            Add an additional URL classifier rule file

            @param rule: URL classifier rule file
            @type rule: C{str}
            @return: None
            """

        def add_jsclassifier(rule):
            """
            add_jsclassifier

            Add an additional JS classifier rule file

            @param rule: JS classifier rule file
            @type rule: C{str}
            @return: None
            """

        def add_sampleclassifier(rule):
            """
            add_sampleclassifier

            Add an additional Sample classifier rule file

            @param rule: Sample classifier rule file
            @type rule: C{str}
            @return: None
            """

        def log_event():
            """
            log_event

            Log the URL analysis results

            @return None
            """

        def run_local(url):
            """
            run_local

            This method should be invoked by 'analyze' method for local file analysis

            @param url: URL to analyze
            @type url: C{str}
            """

        def run_remote(url):
            """
            run_remote

            This method should be invoked by 'analyze' method for URL analysis

            @param url: URL to analyze
            @type url: C{str}
            """

        def analyze():
            """
            analyze

            This method is implicitely called when the ThugAPI instance is directly called
            (take a look at thug/thug.py for an example). It is a good practice to implement
            this method in any case as entry point and invoke it directly or by calling the
            instance (in such case implementing it is mandatory) on your requirements. This
            method can reference just  the (optional) 'args' attribute. Returning something
            from this method is up to you if needed.
            """
