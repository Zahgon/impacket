# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
"""Python Enumerations"""

import sys as _sys

__all__ = ['Enum', 'IntEnum', 'unique']

pyver = float('%s.%s' % _sys.version_info[:2])

try:
    any
except NameError:
    def any(iterable):
        pass


class _RouteClassAttributeToGetattr(object):
    """Route attribute access on a class to __getattr__.

    This is a descriptor, used to define attributes that act differently when
    accessed through an instance and through a class.  Instance access remains
    normal, but access to an attribute through a class will be routed to the
    class's __getattr__ method; this is done by raising AttributeError.

    """
    def __init__(self, fget=None):
        self.fget = fget

    def __get__(self, instance, ownerclass=None):
        if instance is None:
            raise AttributeError()
        return self.fget(instance)

    def __set__(self, instance, value):
        raise AttributeError("can't set attribute")

    def __delete__(self, instance):
        raise AttributeError("can't delete attribute")


def _is_descriptor(obj):
    """Returns True if obj is a descriptor, False otherwise."""
    pass


def _is_dunder(name):
    """Returns True if a __dunder__ name, False otherwise."""
    pass


def _is_sunder(name):
    """Returns True if a _sunder_ name, False otherwise."""
    pass


def _make_class_unpicklable(cls):
    """Make the given class un-picklable."""
    pass


class _EnumDict(dict):
    """Track enum member order and ensure member names are not reused.

    EnumMeta will use the names found in self._member_names as the
    enumeration member names.

    """
    def __init__(self):
        super(_EnumDict, self).__init__()
        self._member_names = []

    def __setitem__(self, key, value):
        """Changes anything not dundered or not a descriptor.

        If a descriptor is added with the same name as an enum member, the name
        is removed from _member_names (this may leave a hole in the numerical
        sequence of values).

        If an enum member name is used twice, an error is raised; duplicate
        values are not checked for.

        Single underscore (sunder) names are reserved.

        Note:   in 3.x __order__ is simply discarded as a not necessary piece
                leftover from 2.x

        """
        if pyver >= 3.0 and key == '__order__':
                return
        if _is_sunder(key):
            raise ValueError('_names_ are reserved for future Enum use')
        elif _is_dunder(key):
            pass
        elif key in self._member_names:
            # descriptor overwriting an enum?
            raise TypeError('Attempted to reuse key: %r' % key)
        elif not _is_descriptor(value):
            if key in self:
                # enum overwriting a descriptor?
                raise TypeError('Key already defined as: %r' % self[key])
            self._member_names.append(key)
        super(_EnumDict, self).__setitem__(key, value)


# Dummy value for Enum as EnumMeta explicitly checks for it, but of course until
# EnumMeta finishes running the first time the Enum class doesn't exist.  This
# is also why there are checks in EnumMeta like `if Enum is not None`
Enum = None


class EnumMeta(type):
    """Metaclass for Enum"""
    @classmethod
    def __prepare__(metacls, cls, bases):
        return _EnumDict()

    def __new__(metacls, cls, bases, classdict):
        # an Enum class is final once enumeration items have been defined; it
        # cannot be mixed with other types (int, float, etc.) if it has an
        # inherited __new__ unless a new __new__ is defined (or the resulting
        # class will fail).
        if type(classdict) is dict:
            original_dict = classdict
            classdict = _EnumDict()
            for k, v in original_dict.items():
                classdict[k] = v

        member_type, first_enum = metacls._get_mixins_(bases)
        #if member_type is object:
        #    use_args = False
        #else:
        #    use_args = True
        __new__, save_new, use_args = metacls._find_new_(classdict, member_type,
                                                        first_enum)
        # save enum items into separate mapping so they don't get baked into
        # the new class
        members = dict((k, classdict[k]) for k in classdict._member_names)
        for name in classdict._member_names:
            del classdict[name]

        # py2 support for definition order
        __order__ = classdict.get('__order__')
        if __order__ is None:
            __order__ = classdict._member_names
            if pyver < 3.0:
                order_specified = False
            else:
                order_specified = True
        else:
            del classdict['__order__']
            order_specified = True
            if pyver < 3.0:
                __order__ = __order__.replace(',', ' ').split()
                aliases = [name for name in members if name not in __order__]
                __order__ += aliases

        # check for illegal enum names (any others?)
        invalid_names = set(members) & set(['mro'])
        if invalid_names:
            raise ValueError('Invalid enum member name(s): %s' % (
                ', '.join(invalid_names), ))

        # create our new Enum type
        enum_class = super(EnumMeta, metacls).__new__(metacls, cls, bases, classdict)
        enum_class._member_names_ = []               # names in random order
        enum_class._member_map_ = {}                 # name->value map
        enum_class._member_type_ = member_type

        # Reverse value->name map for hashable values.
        enum_class._value2member_map_ = {}

        # check for a __getnewargs__, and if not present sabotage
        # pickling, since it won't work anyway
        if (member_type is not object and
            member_type.__dict__.get('__getnewargs__') is None
            ):
            _make_class_unpicklable(enum_class)

        # instantiate them, checking for duplicates as we go
        # we instantiate first instead of checking for duplicates first in case
        # a custom __new__ is doing something funky with the values -- such as
        # auto-numbering ;)
        if __new__ is None:
            __new__ = enum_class.__new__
        for member_name in __order__:
            value = members[member_name]
            if not isinstance(value, tuple):
                args = (value, )
            else:
                args = value
            if member_type is tuple:   # special case for tuple enums
                args = (args, )     # wrap it one more time
            if not use_args or not args:
                enum_member = __new__(enum_class)
                if not hasattr(enum_member, '_value_'):
                    enum_member._value_ = value
            else:
                enum_member = __new__(enum_class, *args)
                if not hasattr(enum_member, '_value_'):
                    enum_member._value_ = member_type(*args)
            value = enum_member._value_
            enum_member._name_ = member_name
            enum_member.__objclass__ = enum_class
            enum_member.__init__(*args)
            # If another member with the same value was already defined, the
            # new member becomes an alias to the existing one.
            for name, canonical_member in enum_class._member_map_.items():
                if canonical_member.value == enum_member._value_:
                    enum_member = canonical_member
                    break
            else:
                # Aliases don't appear in member names (only in __members__).
                enum_class._member_names_.append(member_name)
            enum_class._member_map_[member_name] = enum_member
            try:
                # This may fail if value is not hashable. We can't add the value
                # to the map, and by-value lookups for this value will be
                # linear.
                enum_class._value2member_map_[value] = enum_member
            except TypeError:
                pass

        # in Python2.x we cannot know definition order, so go with value order
        # unless __order__ was specified in the class definition
        if not order_specified:
            enum_class._member_names_ = [
                e[0] for e in sorted(
                [(name, enum_class._member_map_[name]) for name in enum_class._member_names_],
                 key=lambda t: t[1]._value_
                        )]

        # double check that repr and friends are not the mixin's or various
        # things break (such as pickle)
        if Enum is not None:
            setattr(enum_class, '__getnewargs__', Enum.__getnewargs__)
        for name in ('__repr__', '__str__', '__format__'):
            class_method = getattr(enum_class, name)
            obj_method = getattr(member_type, name, None)
            enum_method = getattr(first_enum, name, None)
            if obj_method is not None and obj_method is class_method:
                setattr(enum_class, name, enum_method)

        # method resolution and int's are not playing nice
        # Python's less than 2.6 use __cmp__

        if pyver < 2.6:

            if issubclass(enum_class, int):
                setattr(enum_class, '__cmp__', getattr(int, '__cmp__'))

        elif pyver < 3.0:

            if issubclass(enum_class, int):
                for method in (
                        '__le__',
                        '__lt__',
                        '__gt__',
                        '__ge__',
                        '__eq__',
                        '__ne__',
                        '__hash__',
                        ):
                    setattr(enum_class, method, getattr(int, method))

        # replace any other __new__ with our own (as long as Enum is not None,
        # anyway) -- again, this is to support pickle
        if Enum is not None:
            # if the user defined their own __new__, save it before it gets
            # clobbered in case they subclass later
            if save_new:
                setattr(enum_class, '__member_new__', enum_class.__dict__['__new__'])
            setattr(enum_class, '__new__', Enum.__dict__['__new__'])
        return enum_class

    def __call__(cls, value, names=None, module=None, type=None):
        """Either returns an existing member, or creates a new enum class.

        This method is used both when an enum class is given a value to match
        to an enumeration member (i.e. Color(3)) and for the functional API
        (i.e. Color = Enum('Color', names='red green blue')).

        When used for the functional API: `module`, if set, will be stored in
        the new class' __module__ attribute; `type`, if set, will be mixed in
        as the first base class.

        Note: if `module` is not set this routine will attempt to discover the
        calling module by walking the frame stack; if this is unsuccessful
        the resulting class will not be pickleable.

        """
        if names is None:  # simple value lookup
            return cls.__new__(cls, value)
        # otherwise, functional API: we're creating a new Enum type
        return cls._create_(value, names, module=module, type=type)

    def __contains__(cls, member):
        return isinstance(member, cls) and member.name in cls._member_map_

    def __delattr__(cls, attr):
        # nicer error message when someone tries to delete an attribute
        # (see issue19025).
        if attr in cls._member_map_:
            raise AttributeError(
                    "%s: cannot delete Enum member." % cls.__name__)
        super(EnumMeta, cls).__delattr__(attr)

    def __dir__(self):
        return (['__class__', '__doc__', '__members__', '__module__'] +
                self._member_names_)

    @property
    def __members__(cls):
        """Returns a mapping of member name->value.

        This mapping lists all enum members, including aliases. Note that this
        is a copy of the internal mapping.

        """
        return cls._member_map_.copy()

    def __getattr__(cls, name):
        """Return the enum member matching `name`

        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.

        """
        if _is_dunder(name):
            raise AttributeError(name)
        try:
            return cls._member_map_[name]
        except KeyError:
            raise AttributeError(name)

    def __getitem__(cls, name):
        return cls._member_map_[name]

    def __iter__(cls):
        return (cls._member_map_[name] for name in cls._member_names_)

    def __reversed__(cls):
        return (cls._member_map_[name] for name in reversed(cls._member_names_))

    def __len__(cls):
        return len(cls._member_names_)

    def __repr__(cls):
        return "<enum %r>" % cls.__name__

    def __setattr__(cls, name, value):
        """Block attempts to reassign Enum members.

        A simple assignment to the class namespace only changes one of the
        several possible ways to get an Enum member from the Enum class,
        resulting in an inconsistent Enumeration.

        """
        member_map = cls.__dict__.get('_member_map_', {})
        if name in member_map:
            raise AttributeError('Cannot reassign members.')
        super(EnumMeta, cls).__setattr__(name, value)

    def _create_(cls, class_name, names=None, module=None, type=None):
        """Convenience method to create a new Enum class.

        `names` can be:

        * A string containing member names, separated either with spaces or
          commas.  Values are auto-numbered from 1.
        * An iterable of member names.  Values are auto-numbered from 1.
        * An iterable of (member name, value) pairs.
        * A mapping of member name -> value.

        """
        pass

    @staticmethod
    def _get_mixins_(bases):
        """Returns the type for creating enum members, and the first inherited
        enum class.

        bases: the tuple of bases that was given to __new__

        """
        pass

    if pyver < 3.0:
        @staticmethod
        def _find_new_(classdict, member_type, first_enum):
            """Returns the __new__ to be used for creating the enum members.

            classdict: the class dictionary given to __new__
            member_type: the data type whose __new__ will be used by default
            first_enum: enumeration to check for an overriding __new__

            """
            pass
    else:
        @staticmethod
        def _find_new_(classdict, member_type, first_enum):
            """Returns the __new__ to be used for creating the enum members.

            classdict: the class dictionary given to __new__
            member_type: the data type whose __new__ will be used by default
            first_enum: enumeration to check for an overriding __new__

            """
            pass


########################################################
# In order to support Python 2 and 3 with a single
# codebase we have to create the Enum methods separately
# and then use the `type(name, bases, dict)` method to
# create the class.
########################################################
temp_enum_dict = {}
temp_enum_dict['__doc__'] = "Generic enumeration.\n\n    Derive from this class to define new enumerations.\n\n"

def __new__(cls, value):
    # all enum instances are actually created during class construction
    # without calling this method; this method is called by the metaclass'
    # __call__ (i.e. Color(3) ), and by pickle
    if type(value) is cls:
        # For lookups like Color(Color.red)
        value = value.value
        #return value
    # by-value search for a matching enum member
    # see if it's in the reverse mapping (for hashable values)
    try:
        if value in cls._value2member_map_:
            return cls._value2member_map_[value]
    except TypeError:
        # not there, now do long search -- O(n) behavior
        for member in cls._member_map_.values():
            if member.value == value:
                return member
    raise ValueError("%s is not a valid %s" % (value, cls.__name__))
temp_enum_dict['__new__'] = __new__
del __new__

def __repr__(self):
    return "<%s.%s: %r>" % (
            self.__class__.__name__, self._name_, self._value_)
temp_enum_dict['__repr__'] = __repr__
del __repr__

def __str__(self):
    return "%s.%s" % (self.__class__.__name__, self._name_)
temp_enum_dict['__str__'] = __str__
del __str__

def __dir__(self):
    added_behavior = [m for m in self.__class__.__dict__ if m[0] != '_']
    return (['__class__', '__doc__', '__module__', 'name', 'value'] + added_behavior)
temp_enum_dict['__dir__'] = __dir__
del __dir__

def __format__(self, format_spec):
    # mixed-in Enums should use the mixed-in type's __format__, otherwise
    # we can get strange results with the Enum name showing up instead of
    # the value

    # pure Enum branch
    if self._member_type_ is object:
        cls = str
        val = str(self)
    # mix-in branch
    else:
        cls = self._member_type_
        val = self.value
    return cls.__format__(val, format_spec)
temp_enum_dict['__format__'] = __format__
del __format__


####################################
# Python's less than 2.6 use __cmp__

if pyver < 2.6:

    def __cmp__(self, other):
        if type(other) is self.__class__:
            if self is other:
                return 0
            return -1
        return NotImplemented
        raise TypeError("unorderable types: %s() and %s()" % (self.__class__.__name__, other.__class__.__name__))
    temp_enum_dict['__cmp__'] = __cmp__
    del __cmp__

else:

    def __le__(self, other):
        raise TypeError("unorderable types: %s() <= %s()" % (self.__class__.__name__, other.__class__.__name__))
    temp_enum_dict['__le__'] = __le__
    del __le__

    def __lt__(self, other):
        raise TypeError("unorderable types: %s() < %s()" % (self.__class__.__name__, other.__class__.__name__))
    temp_enum_dict['__lt__'] = __lt__
    del __lt__

    def __ge__(self, other):
        raise TypeError("unorderable types: %s() >= %s()" % (self.__class__.__name__, other.__class__.__name__))
    temp_enum_dict['__ge__'] = __ge__
    del __ge__

    def __gt__(self, other):
        raise TypeError("unorderable types: %s() > %s()" % (self.__class__.__name__, other.__class__.__name__))
    temp_enum_dict['__gt__'] = __gt__
    del __gt__
    

def __eq__(self, other):
    if type(other) is self.__class__:
        return self is other
    return NotImplemented
temp_enum_dict['__eq__'] = __eq__
del __eq__

def __ne__(self, other):
    if type(other) is self.__class__:
        return self is not other
    return NotImplemented
temp_enum_dict['__ne__'] = __ne__
del __ne__

def __getnewargs__(self):
    return (self._value_, )
temp_enum_dict['__getnewargs__'] = __getnewargs__
del __getnewargs__

def __hash__(self):
    return hash(self._name_)
temp_enum_dict['__hash__'] = __hash__
del __hash__

# _RouteClassAttributeToGetattr is used to provide access to the `name`
# and `value` properties of enum members while keeping some measure of
# protection from modification, while still allowing for an enumeration
# to have members named `name` and `value`.  This works because enumeration
# members are not set directly on the enum class -- __getattr__ is
# used to look them up.

@_RouteClassAttributeToGetattr
def name(self):
    pass
temp_enum_dict['name'] = name
del name

@_RouteClassAttributeToGetattr
def value(self):
    pass
temp_enum_dict['value'] = value
del value

Enum = EnumMeta('Enum', (object, ), temp_enum_dict)
del temp_enum_dict

# Enum has now been created
###########################

class IntEnum(int, Enum):
    """Enum where members are also (and must be) ints"""


def unique(enumeration):
    """Class decorator that ensures only unique members exist in an enumeration."""
    pass
