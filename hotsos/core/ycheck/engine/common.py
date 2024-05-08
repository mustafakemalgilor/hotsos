import abc
import os
import re

import yaml
from hotsos.core.config import HotSOSConfig
from hotsos.core.log import log
from hotsos.core.ycheck.engine.properties.common import YPropertyBase



class YPropertyLoader(YPropertyBase):
    pass

class YHotsosYamlLoader(yaml.SafeLoader):
    """This class is just the regular yaml.SafeLoader but also resolves the
    variable names to their values in YAML, e.g.;
        x:
            y: abc
            z: def
        foo : ${x.y} ${x.z}
    # foo's value would be "abc def"
    """

    matchers = None
    property_loader = YPropertyLoader("","","","")

    @classmethod
    def initialize_constructor_matchers(cls):
        cls.matchers = {}
        cls.matchers["!prop"] = re.compile(r'\$\[([^\s]+)\]')

    @classmethod
    def register_constructors(cls):
        cls.add_constructor("!prop", cls._prop_constructor)

    @classmethod
    def register_implicit_resolvers(cls):
        cls.add_implicit_resolver("!prop", cls.matchers["!prop"], None)

    def __init__(self, stream):
        super().__init__(stream)
        if not self.matchers:
            self.initialize_constructor_matchers()
            self.register_constructors()
            self.register_implicit_resolvers()

    # we override this method to remember the root node,
    # so that we can later resolve paths relative to it
    def get_single_node(self):
        self.cur_root = super().get_single_node()
        return self.cur_root

    @classmethod
    def _prop_constructor(cls, loader, node):
        var = cls.matchers["!prop"].search(node.value)
        if not var:
            pass
            #print("something is wrong")

        property_name = var.group(1)
        print(f"pname ${property_name}")
        v = cls.property_loader.get_property(property_name)
        print(f"\t returning {v}")
        return v 


class YDefsLoader(object):
    """ Load yaml definitions. """

    def __init__(self, ytype):
        """
        @param ytype: the type of defs we are loading i.e. defs/<ytype>
        """
        self.ytype = ytype
        self._loaded_defs = None
        self.stats_num_files_loaded = 0

    def _load_yaml(self, fd):
        return yaml.load(fd, Loader=YHotsosYamlLoader) or {}

    def _is_def(self, abs_path):
        return abs_path.endswith('.yaml')

    def _get_yname(self, path):
        return os.path.basename(path).partition('.yaml')[0]

    def _get_defs_recursive(self, path):
        """ Recursively find all yaml/files beneath a directory. """
        defs = {}
        for entry in os.listdir(path):
            abs_path = os.path.join(path, entry)
            if os.path.isdir(abs_path):
                subdefs = self._get_defs_recursive(abs_path)
                if subdefs:
                    defs[os.path.basename(abs_path)] = subdefs
            else:
                if not self._is_def(abs_path):
                    continue

                if self._get_yname(abs_path) == os.path.basename(path):
                    with open(abs_path) as fd:
                        log.debug("applying dir globals %s", entry)
                        defs.update(self._load_yaml(fd))

                    # NOTE: these files do not count towards the total loaded
                    # since they are only supposed to contain directory-level
                    # globals that apply to other definitions in or below this
                    # directory.
                    continue

                with open(abs_path) as fd:
                    self.stats_num_files_loaded += 1
                    _content = self._load_yaml(fd)
                    defs[self._get_yname(abs_path)] = _content

        return defs

    @property
    def plugin_defs(self):
        """ Load yaml defs for the current plugin and type. """
        log.debug('loading %s definitions for plugin=%s', self.ytype,
                  HotSOSConfig.plugin_name)

        if self._loaded_defs:
            return self._loaded_defs

        path = os.path.join(HotSOSConfig.plugin_yaml_defs, self.ytype,
                            HotSOSConfig.plugin_name)
        # reset
        self.stats_num_files_loaded = 0
        if os.path.isdir(path):
            loaded = self._get_defs_recursive(path)
            log.debug("YDefsLoader: plugin %s loaded %s file(s)",
                      HotSOSConfig.plugin_name, self.stats_num_files_loaded)
            # only return if we loaded actual definitions (not just globals)
            if self.stats_num_files_loaded:
                self._loaded_defs = loaded
                return loaded


class YHandlerBase(object):

    @property
    @abc.abstractmethod
    def searcher(self):
        """
        @return: FileSearcher object to be used by this handler.
        """

    @abc.abstractmethod
    def run(self):
        """ Process operations. """
