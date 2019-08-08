# This code is in the public domain, it comes with absolutely no
# warranty and you can do absolutely whatever you want with it.

__date__ = '17 May 2007'
__version__ = '1.7'
__doc__ = """
This is markup.py - a Python module that attempts to
make it easier to generate HTML/XML from a Python program
in an intuitive, lightweight, customizable and pythonic way.

The code is in the public domain.

Version: %s as of %s.

Documentation and further info is at http://markup.sourceforge.net/

Please send bug reports, feature requests, enhancement
ideas or questions to nogradi at gmail dot com.

Installation: drop markup.py somewhere into your Python path.
""" % ( __version__, __date__ )


class element:

    """This class handles the addition of a new element."""

    def __init__(self, tag, case='lower', parent=None):
        self.parent = parent

        if case == 'lower':
            self.tag = tag.lower()
        else:
            self.tag = tag.upper()

    def __call__(self, *args, **kwargs):
        if len(args) > 1:
            raise ArgumentError(self.tag)

        # If class_ was defined in parent, it should be added to every element.
        if self.parent is not None and self.parent.class_ is not None:
            if 'class_' not in kwargs:
                kwargs['class_'] = self.parent.class_

        if self.parent is None and len(args) == 1:
            x = [self.render(self.tag, False, myarg, mydict)
                 for myarg, mydict in _argsdicts(args, kwargs)]
            return '\n'.join(x)
        elif self.parent is None and len(args) == 0:
            x = [self.render(self.tag, True, myarg, mydict)
                 for myarg, mydict in _argsdicts(args, kwargs)]
            return '\n'.join(x)

        if self.tag in self.parent.twotags:
            for myarg, mydict in _argsdicts(args, kwargs):
                self.render(self.tag, False, myarg, mydict)
        elif self.tag in self.parent.onetags:
            if len(args) == 0:
                for myarg, mydict in _argsdicts(args, kwargs):
                    # Here myarg is always None, because len( args ) = 0.
                    self.render(self.tag, True, myarg, mydict)
            else:
                raise ClosingError(self.tag)
        elif self.parent.mode == 'strict_html' and self.tag in self.parent.deptags:
            raise DeprecationError(self.tag)
        else:
            raise InvalidElementError(self.tag, self.parent.mode)

    def render(self, tag, single, between, kwargs):
        """Append the actual tags to content."""

        out = "<%s" % tag
        for key, value in kwargs.items():
            # When value is None, that means stuff like <... checked>.
            if value is not None:
                # Strip this so class_ will mean class, etc.
                key = key.strip('_')
                # Special cases, maybe change _ to - overall?
                if key == 'http_equiv':
                    key = 'http-equiv'
                elif key == 'accept_charset':
                    key = 'accept-charset'
                out = "%s %s=\"%s\"" % (out, key, escape(value))
            else:
                out = "%s %s" % (out, key)
        if between is not None:
            out = "%s>%s</%s>" % (out, between, tag)
        else:
            if single:
                out = "%s />" % out
            else:
                out = "%s>" % out
        if self.parent is not None:
            self.parent.content.append(out)
        else:
            return out

    def close(self):
        """Append a closing tag unless element has only opening tag."""

        if self.tag in self.parent.twotags:
            self.parent.content.append("</%s>" % self.tag)
        elif self.tag in self.parent.onetags:
            raise ClosingError(self.tag)
        elif self.parent.mode == 'strict_html' and self.tag in self.parent.deptags:
            raise DeprecationError(self.tag)

    def open(self, **kwargs):
        """Append an opening tag."""

        if self.tag in self.parent.twotags or self.tag in self.parent.onetags:
            self.render(self.tag, False, None, kwargs)
        elif self.mode == 'strict_html' and self.tag in self.parent.deptags:
            raise DeprecationError(self.tag)


class page:

    """This is our main class representing a document. Elements are added as
    attributes of an instance of this class."""

    def __init__(self, mode='strict_html', case='lower',
                 onetags=None, twotags=None, separator='\n', class_=None):
        """Stuff that effects the whole document.

        mode -- 'strict_html'   for HTML 4.01 (default)
                'html'          alias for 'strict_html'
                'loose_html'    to allow some deprecated elements
                'xml'           to allow arbitrary elements

        case -- 'lower'         element names will be printed in lower case (default)
                'upper'         they will be printed in upper case

        onetags --              list or tuple of valid elements with opening tags only
        twotags --              list or tuple of valid elements with both opening and closing tags
                                these two keyword arguments may be used to select
                                the set of valid elements in 'xml' mode
                                invalid elements will raise appropriate exceptions

        separator --            string to place between added elements, defaults to newline

        class_ --               a class that will be added to every element if defined"""

        valid_onetags = [
            "AREA",
            "BASE",
            "BR",
            "COL",
            "FRAME",
            "HR",
            "IMG",
            "INPUT",
            "LINK",
            "META",
            "PARAM"]
        valid_twotags = [
            "A", "ABBR", "ACRONYM", "ADDRESS", "B", "BDO", "BIG", "BLOCKQUOTE", "BODY", "BUTTON",
            "CAPTION", "CITE", "CODE", "COLGROUP", "DD", "DEL", "DFN", "DIV", "DL", "DT", "EM", "FIELDSET",
            "FORM", "FRAMESET", "H1", "H2", "H3", "H4", "H5", "H6", "HEAD", "HTML", "I", "IFRAME", "INS",
            "KBD", "LABEL", "LEGEND", "LI", "MAP", "NOFRAMES", "NOSCRIPT", "OBJECT", "OL", "OPTGROUP",
            "OPTION", "P", "PRE", "Q", "SAMP", "SCRIPT", "SELECT", "SMALL", "SPAN", "STRONG", "STYLE",
            "SUB", "SUP", "TABLE", "TBODY", "TD", "TEXTAREA", "TFOOT", "TH", "THEAD", "TITLE", "TR",
            "TT", "UL", "VAR"]
        deprecated_onetags = ["BASEFONT", "ISINDEX"]
        deprecated_twotags = [
            "APPLET",
            "CENTER",
            "DIR",
            "FONT",
            "MENU",
            "S",
            "STRIKE",
            "U"]

        self.header = []
        self.content = []
        self.footer = []
        self.case = case
        self.separator = separator

        # init( ) sets it to True so we know that </body></html> has to be printed at the end.
        self._full = False
        self.class_ = class_

        if mode == 'strict_html' or mode == 'html':
            self.onetags = valid_onetags
            self.onetags += [str.lower(x) for x in self.onetags]
            self.twotags = valid_twotags
            self.twotags += [str.lower(x) for x in self.twotags]
            self.deptags = deprecated_onetags + deprecated_twotags
            self.deptags += [str.lower(x) for x in self.deptags]
            self.mode = 'strict_html'
        elif mode == 'loose_html':
            self.onetags = valid_onetags + deprecated_onetags
            self.onetags += [str.lower(x) for x in self.onetags]
            self.twotags = valid_twotags + deprecated_twotags
            self.onetags += [str.lower(x) for x in self.twotags]
            self.mode = mode
        elif mode == 'xml':
            if onetags and twotags:
                self.onetags = onetags
                self.twotags = twotags
            elif (onetags and not twotags) or (twotags and not onetags):
                raise CustomizationError()
            else:
                self.onetags = russell()
                self.twotags = russell()
            self.mode = mode
        else:
            raise ModeError(mode)

    def __getattr__(self, attr):
        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError(attr)
        return element(attr, case=self.case, parent=self)

    def __str__(self):

        if self._full and (self.mode == 'strict_html' or self.mode == 'loose_html'):
            end = ['</body>', '</html>']
        else:
            end = []

        return (
            self.separator.join(
                self.header +
                self.content +
                self.footer +
                end)
        )

    def __call__(self, escape=False):
        """Return the document as a string.

        escape --   False   print normally
                    True    replace < and > by &lt; and &gt;
                            the default escape sequences in most browsers"""

        if escape:
            return _escape(self.__str__())
        else:
            return self.__str__()

    def add(self, text):
        """This is an alias to addcontent."""
        self.addcontent(text)

    def addfooter(self, text):
        """Add some text to the bottom of the document"""
        self.footer.append(text)

    def addheader(self, text):
        """Add some text to the top of the document"""
        self.header.append(text)

    def addcontent(self, text):
        """Add some text to the main part of the document"""
        self.content.append(text)

    def init(self, lang='en', css=None, metainfo=None, title=None, header=None,
             footer=None, charset=None, encoding=None, doctype=None, bodyattrs=None, script=None):
        """This method is used for complete documents with appropriate
        doctype, encoding, title, etc information. For an HTML/XML snippet
        omit this method.

        lang --     language, usually a two character string, will appear
                    as <html lang='en'> in html mode (ignored in xml mode)

        css --      Cascading Style Sheet filename as a string or a list of
                    strings for multiple css files (ignored in xml mode)

        metainfo -- a dictionary in the form { 'name':'content' } to be inserted
                    into meta element(s) as <meta name='name' content='content'>
                    (ignored in xml mode)

        bodyattrs --a dictionary in the form { 'key':'value', ... } which will be added
                    as attributes of the <body> element as <body key='value' ... >
                    (ignored in xml mode)

        script --   dictionary containing src:type pairs, <script type='text/type' src=src></script>

        title --    the title of the document as a string to be inserted into
                    a title element as <title>my title</title> (ignored in xml mode)

        header --   some text to be inserted right after the <body> element
                    (ignored in xml mode)

        footer --   some text to be inserted right before the </body> element
                    (ignored in xml mode)

        charset --  a string defining the character set, will be inserted into a
                    <meta http-equiv='Content-Type' content='text/html; charset=myset'>
                    element (ignored in xml mode)

        encoding -- a string defining the encoding, will be put into to first line of
                    the document as <?xml version='1.0' encoding='myencoding' ?> in
                    xml mode (ignored in html mode)

        doctype --  the document type string, defaults to
                    <!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 4.01 Transitional//EN'>
                    in html mode (ignored in xml mode)"""

        self._full = True

        if self.mode == 'strict_html' or self.mode == 'loose_html':
            if doctype is None:
                doctype = "<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 4.01 Transitional//EN'>"
            self.header.append(doctype)
            self.html(lang=lang)
            self.head()
            if charset is not None:
                self.meta(
                    http_equiv='Content-Type',
                    content="text/html; charset=%s" %
                    charset)
            if metainfo is not None:
                self.metainfo(metainfo)
            if css is not None:
                self.css(css)
            if title is not None:
                self.title(title)
            if script is not None:
                self.scripts(script)
            self.head.close()
            if bodyattrs is not None:
                self.body(**bodyattrs)
            else:
                self.body()
            if header is not None:
                self.content.append(header)
            if footer is not None:
                self.footer.append(footer)

        elif self.mode == 'xml':
            if doctype is None:
                if encoding is not None:
                    doctype = "<?xml version='1.0' encoding='%s' ?>" % encoding
                else:
                    doctype = "<?xml version='1.0' ?>"
            self.header.append(doctype)

    def css(self, filelist):
        """This convenience function is only useful for html. It adds CSS
        stylesheet(s) to the document via the <link> element."""

        if isinstance(filelist, str):
            self.link(
                href=filelist,
                rel='stylesheet',
                type='text/css',
                media='all')
        else:
            for file in filelist:
                self.link(
                    href=file,
                    rel='stylesheet',
                    type='text/css',
                    media='all')

    def metainfo(self, mydict):
        """This convenience function is only useful for html. It adds meta
        information via the <meta> element, the argument is a dictionary of
        the form { 'name':'content' }."""

        if isinstance(mydict, dict):
            for name, content in mydict.items():
                self.meta(name=name, content=content)
        else:
            raise TypeError(
                "Metainfo should be called with a dictionary argument of name:content pairs.")

    def scripts(self, mydict):
        """Only useful in html, mydict is dictionary of src:type pairs will
        be rendered as <script type='text/type' src=src></script>"""

        if isinstance(mydict, dict):
            for src, type in mydict.items():
                self.script('', src=src, type='text/%s' % type)
        else:
            raise TypeError(
                "Script should be given a dictionary of src:type pairs.")


class _oneliner:

    """An instance of oneliner returns a string corresponding to one element.
    This class can be used to write 'oneliners' that return a string
    immediately so there is no need to instantiate the page class."""

    def __init__(self, case='lower'):
        self.case = case

    def __getattr__(self, attr):
        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError(attr)
        return element(attr, case=self.case, parent=None)


oneliner = _oneliner(case='lower')
upper_oneliner = _oneliner(case='upper')


def _argsdicts(args, mydict):
    """A utility generator that pads argument list and dictionary values, will
    only be called with len( args ) = 0, 1."""

    if len(args) == 0:
        args = None,
    elif len(args) == 1:
        args = _totuple(args[0])
    else:
        raise Exception("We should have never gotten here.")

    mykeys = list(mydict.keys())
    myvalues = list(map(_totuple, list(mydict.values())))
    maxlength = max(list(map(len, [args] + myvalues)))
    for i in range(maxlength):
        thisdict = {}
        for key, value in zip(mykeys, myvalues):
            try:
                thisdict[key] = value[i]
            except IndexError:
                thisdict[key] = value[-1]
        try:
            thisarg = args[i]
        except IndexError:
            thisarg = args[-1]

        yield thisarg, thisdict


def _totuple(x):
    """Utility stuff to convert string, int, float, None or anything to a usable tuple."""

    if isinstance(x, str):
        out = x,
    elif isinstance(x, (int, float)):
        out = str(x),
    elif x is None:
        out = None,
    else:
        out = tuple(x)

    return out


def escape(text, newline=False):
    """Escape special html characters."""

    if isinstance(text, str):
        if '&' in text:
            text = text.replace('&', '&amp;')
        if '>' in text:
            text = text.replace('>', '&gt;')
        if '<' in text:
            text = text.replace('<', '&lt;')
        if '\"' in text:
            text = text.replace('\"', '&quot;')
        if '\'' in text:
            text = text.replace('\'', '&quot;')
        if newline:
            if '\n' in text:
                text = text.replace('\n', '<br>')

    return text


_escape = escape


def unescape(text):
    """Inverse of escape."""

    if isinstance(text, str):
        if '&amp;' in text:
            text = text.replace('&amp;', '&')
        if '&gt;' in text:
            text = text.replace('&gt;', '>')
        if '&lt;' in text:
            text = text.replace('&lt;', '<')
        if '&quot;' in text:
            text = text.replace('&quot;', '\"')

    return text


class dummy:

    """A dummy class for attaching attributes."""
    pass

doctype = dummy()
doctype.frameset = "<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 4.01 Frameset//EN' 'http://www.w3.org/TR/html4/frameset.dtd'>"
doctype.strict = "<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 4.01//EN' 'http://www.w3.org/TR/html4/strict.dtd'>"
doctype.loose = "<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 4.01 Transitional//EN' 'http://www.w3.org/TR/html4/loose.dtd'>"


class russell:

    """A dummy class that contains anything."""

    def __contains__(self, item):
        return True


class MarkupError(Exception):

    """All our exceptions subclass this."""

    def __str__(self):
        return self.message


class ClosingError(MarkupError):

    def __init__(self, tag):
        self.message = "The element '%s' does not accept non-keyword arguments (has no closing tag)." % tag


class OpeningError(MarkupError):

    def __init__(self, tag):
        self.message = "The element '%s' can not be opened." % tag


class ArgumentError(MarkupError):

    def __init__(self, tag):
        self.message = "The element '%s' was called with more than one non-keyword argument." % tag


class InvalidElementError(MarkupError):

    def __init__(self, tag, mode):
        self.message = "The element '%s' is not valid for your mode '%s'." % (
            tag,
            mode)


class DeprecationError(MarkupError):

    def __init__(self, tag):
        self.message = "The element '%s' is deprecated, instantiate markup.page with mode='loose_html' to allow it." % tag


class ModeError(MarkupError):

    def __init__(self, mode):
        self.message = "Mode '%s' is invalid, possible values: strict_html, loose_html, xml." % mode


class CustomizationError(MarkupError):

    def __init__(self):
        self.message = "If you customize the allowed elements, you must define both types 'onetags' and 'twotags'."


if __name__ == '__main__':
    print(__doc__)
