import re
import os


class FileMetadata():
    def __init__(self, filepath=None, filename=None, mime=None):
        self.file_info = {}
        self.filename: str = filename     # filename only
        self.filepath: str = filepath     # full filepath
        self.mime_type = mime
        self.extension = None             # file extension
        self.suspicious_tags = []
        self.extracted_results = {}
        self.is_malicious = False
        self.ast = None
        self.is_plugin = None
        self.plugin_name = None

    def reset(self):
        self.suspicious_tags = []

    def clearMemory(self):
        self.file_info = {}
        self.ast = None


class Plugin():
    def __init__(self, plugin_name = None, plugin_path = None, platform = "Unknown", source = "Unknown"):
        self.plugin_name = plugin_name
        self.plugin_base_path = os.path.abspath(plugin_path)
        self.download_platform = platform
        self.download_source = source
        self.files = {}
        self.version = None
        self.author = None
        self.author_uri = None
        self.plugin_uri = None
        self.num_files = None
        self.plugin_score = None
        self.license = None
        self.description = None
        self.is_mal = None
        self.is_theme = None
        self.num_mal_p_files = 0
        self.theme_name = None
        self.error = False
        self.mal_files = {}


class PluginFile():
    def __init__(self, filepath = None, mime = None, plugin_name = None):
        self.plugin_name = plugin_name
        self.filepath = filepath    # full filepath
        self.version = None
        self.mime_type = mime
        self.suspicious_tags = [] 
        self.is_malicious = None
        self.extracted_results = {} # Key suspicious tag. Nested dictionary of values
        self.ast = None