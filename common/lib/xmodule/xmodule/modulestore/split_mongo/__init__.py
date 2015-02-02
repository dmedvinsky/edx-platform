"""
General utilities
"""

from collections import namedtuple
from contracts import contract, check
from opaque_keys.edx.locator import BlockUsageLocator


class BlockKey(namedtuple('BlockKey', 'type id')):
    __slots__ = ()

    @contract(type="string[>0]")
    def __new__(cls, type, id):
        return super(BlockKey, cls).__new__(cls, type, id)

    @classmethod
    @contract(usage_key=BlockUsageLocator)
    def from_usage_key(cls, usage_key):
        return cls(usage_key.block_type, usage_key.block_id)


CourseEnvelope = namedtuple('CourseEnvelope', 'course_key structure')


class EditInfo(object):
    """
    Encapsulates the editing info of a block.
    """
    def __init__(self, edit_info={}):  # pylint: disable=dangerous-default-value
        self.from_storable(edit_info)

        # For details, see caching_descriptor_system.py get_subtree_edited_by/on.
        self._subtree_edited_on = edit_info.get('_subtree_edited_on', None)
        self._subtree_edited_by = edit_info.get('_subtree_edited_by', None)

    def to_storable(self):
        """
        Serialize to a Mongo-storable format.
        """
        return {
            'previous_version': self.previous_version,
            'update_version': self.update_version,
            'source_version': self.source_version,
            'edited_on': self.edited_on,
            'edited_by': self.edited_by,
            'original_usage': self.original_usage,
            'original_usage_version': self.original_usage_version,
        }

    def from_storable(self, edit_info):
        """
        De-serialize from Mongo-storable format to an object.
        """
        # Guid for the structure which previously changed this XBlock.
        # (Will be the previous value of 'update_version'.)
        self.previous_version = edit_info.get('previous_version', None)

        # Guid for the structure where this XBlock got its current field values.
        # May point to a structure not in this structure's history (e.g., to a draft
        # branch from which this version was published).
        self.update_version = edit_info.get('update_version', None)

        self.source_version = edit_info.get('source_version', None)

        # Datetime when this XBlock's fields last changed.
        self.edited_on = edit_info.get('edited_on', None)
        # User ID which changed this XBlock last.
        self.edited_by = edit_info.get('edited_by', None)

        self.original_usage = edit_info.get('original_usage', None)
        self.original_usage_version = edit_info.get('original_usage_version', None)

    def __str__(self):
        return ("EditInfo(previous_version={0.previous_version}, "
                "update_version={0.update_version}, "
                "source_version={0.source_version}, "
                "edited_on={0.edited_on}, "
                "edited_by={0.edited_by}, "
                "original_usage={0.original_usage}, "
                "original_usage_version={0.original_usage_version}, "
                "_subtree_edited_on={0._subtree_edited_on}, "
                "_subtree_edited_by={0._subtree_edited_by})").format(self)


class BlockData(object):
    """
    Wrap the block data in an object instead of using a straight Python dictionary.
    Allows the storing of meta-information about a structure that doesn't persist along with
    the structure itself.
    """
    @contract(block_dict=dict)
    def __init__(self, block_dict={}):  # pylint: disable=dangerous-default-value
        # Has the definition been loaded?
        self.definition_loaded = False
        self.from_storable(block_dict)

    def to_storable(self):
        """
        Serialize to a Mongo-storable format.
        """
        return {
            'fields': self.fields,
            'block_type': self.block_type,
            'definition': self.definition,
            'defaults': self.defaults,
            'edit_info': self.edit_info.to_storable()
        }

    @contract(stored=dict)
    def from_storable(self, stored):
        """
        De-serialize from Mongo-storable format to an object.
        """
        # Contains the Scope.settings and 'children' field values.
        # 'children' are stored as a list of (block_type, block_id) pairs.
        self.fields = stored.get('fields', {})

        # XBlock type ID.
        self.block_type = stored.get('block_type', None)

        # DB id of the record containing the content of this XBlock.
        self.definition = stored.get('definition', None)

        # Scope.settings default values copied from a template block (used e.g. when
        # blocks are copied from a library to a course)
        self.defaults = stored.get('defaults', {})

        # EditInfo object containing all versioning/editing data.
        self.edit_info = EditInfo(stored.get('edit_info', {}))

    def __str__(self):
        return ("BlockData(fields={0.fields}, "
                "block_type={0.block_type}, "
                "definition={0.definition}, "
                "definition_loaded={0.definition_loaded}, "
                "defaults={0.defaults}, "
                "edit_info={0.edit_info})").format(self)

    def __contains__(self, item):
        return hasattr(self, item)

    def __getitem__(self, key):
        """
        Dict-like '__getitem__'.
        """
        if not hasattr(self, key):
            raise KeyError
        else:
            return getattr(self, key)
