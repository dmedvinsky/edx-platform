# pylint: disable=E1101
# pylint: disable=W0212
# pylint: disable=E0611
from nose.tools import assert_equals, assert_raises, \
    assert_not_equals, assert_false, assert_true, assert_greater, assert_is_instance, assert_is_none
# pylint: enable=E0611
from path import path
import pymongo
import logging
import shutil
from tempfile import mkdtemp
from uuid import uuid4
from datetime import datetime
from pytz import UTC
import unittest
from xblock.core import XBlock
from ddt import ddt, data

from xblock.fields import Scope, Reference, ReferenceList, ReferenceValueDict
from xblock.runtime import KeyValueStore
from xblock.exceptions import InvalidScopeError
from xblock.plugin import Plugin

from xmodule.tests import DATA_DIR
from opaque_keys.edx.locations import Location
from xmodule.modulestore import ModuleStoreEnum
from xmodule.modulestore.mongo import MongoKeyValueStore
from xmodule.modulestore.draft import DraftModuleStore
from opaque_keys.edx.locations import SlashSeparatedCourseKey, AssetLocation
from opaque_keys.edx.keys import UsageKey
from xmodule.modulestore.xml_exporter import export_to_xml
from xmodule.modulestore.xml_importer import import_from_xml, perform_xlint
from xmodule.contentstore.mongo import MongoContentStore
from xmodule.assetstore import AssetMetadata, AssetThumbnailMetadata

from nose.tools import assert_in
from xmodule.exceptions import NotFoundError
from git.test.lib.asserts import assert_not_none
from xmodule.x_module import XModuleMixin
from xmodule.modulestore.mongo.base import as_draft
from xmodule.modulestore.tests.mongo_connection import MONGO_PORT_NUM, MONGO_HOST
from xmodule.modulestore.edit_info import EditInfoMixin

log = logging.getLogger(__name__)

HOST = MONGO_HOST
PORT = MONGO_PORT_NUM
DB = 'test_mongo_%s' % uuid4().hex[:5]
COLLECTION = 'modulestore'
ASSET_COLLECTION = 'assetstore'
FS_ROOT = DATA_DIR  # TODO (vshnayder): will need a real fs_root for testing load_item
DEFAULT_CLASS = 'xmodule.raw_module.RawDescriptor'
RENDER_TEMPLATE = lambda t_n, d, ctx = None, nsp = 'main': ''


class ReferenceTestXBlock(XBlock, XModuleMixin):
    """
    Test xblock type to test the reference field types
    """
    has_children = True
    reference_link = Reference(default=None, scope=Scope.content)
    reference_list = ReferenceList(scope=Scope.content)
    reference_dict = ReferenceValueDict(scope=Scope.settings)


class TestMongoModuleStore(unittest.TestCase):
    '''Tests!'''
    # Explicitly list the courses to load (don't want the big one)
    courses = ['toy', 'simple', 'simple_with_draft', 'test_unicode']

    @classmethod
    def setupClass(cls):
        cls.connection = pymongo.MongoClient(
            host=HOST,
            port=PORT,
            tz_aware=True,
            document_class=dict,
        )

        # NOTE: Creating a single db for all the tests to save time.  This
        # is ok only as long as none of the tests modify the db.
        # If (when!) that changes, need to either reload the db, or load
        # once and copy over to a tmp db for each test.
        cls.content_store, cls.draft_store = cls.initdb()

    @classmethod
    def teardownClass(cls):
#         cls.patcher.stop()
        if cls.connection:
            cls.connection.drop_database(DB)
            cls.connection.close()

    @classmethod
    def initdb(cls):
        # connect to the db
        doc_store_config = {
            'host': HOST,
            'port': PORT,
            'db': DB,
            'collection': COLLECTION,
            'asset_collection': ASSET_COLLECTION,
        }
        # since MongoModuleStore and MongoContentStore are basically assumed to be together, create this class
        # as well
        content_store = MongoContentStore(HOST, DB, port=PORT)
        #
        # Also test draft store imports
        #
        draft_store = DraftModuleStore(
            content_store,
            doc_store_config, FS_ROOT, RENDER_TEMPLATE,
            default_class=DEFAULT_CLASS,
            branch_setting_func=lambda: ModuleStoreEnum.Branch.draft_preferred,
            xblock_mixins=(EditInfoMixin,)

        )
        import_from_xml(
            draft_store,
            999,
            DATA_DIR,
            cls.courses,
            static_content_store=content_store
        )

        # also test a course with no importing of static content
        import_from_xml(
            draft_store,
            999,
            DATA_DIR,
            ['test_import_course'],
            static_content_store=content_store,
            do_import_static=False,
            verbose=True
        )

        return content_store, draft_store

    @staticmethod
    def destroy_db(connection):
        # Destroy the test db.
        connection.drop_database(DB)

    @classmethod
    def setUp(cls):
        cls.dummy_user = ModuleStoreEnum.UserID.test

    @classmethod
    def tearDown(cls):
        pass

    def test_init(self):
        '''Make sure the db loads'''
        ids = list(self.connection[DB][COLLECTION].find({}, {'_id': True}))
        assert_greater(len(ids), 12)

    def test_mongo_modulestore_type(self):
        store = DraftModuleStore(
            None,
            {'host': HOST, 'db': DB, 'port': PORT, 'collection': COLLECTION},
            FS_ROOT, RENDER_TEMPLATE, default_class=DEFAULT_CLASS
        )
        assert_equals(store.get_modulestore_type(''), ModuleStoreEnum.Type.mongo)

    def test_get_courses(self):
        '''Make sure the course objects loaded properly'''
        courses = self.draft_store.get_courses()
        assert_equals(len(courses), 6)
        course_ids = [course.id for course in courses]
        for course_key in [

            SlashSeparatedCourseKey(*fields)
            for fields in [
                ['edX', 'simple', '2012_Fall'], ['edX', 'simple_with_draft', '2012_Fall'],
                ['edX', 'test_import_course', '2012_Fall'], ['edX', 'test_unicode', '2012_Fall'],
                ['edX', 'toy', '2012_Fall']
            ]
        ]:
            assert_in(course_key, course_ids)
            course = self.draft_store.get_course(course_key)
            assert_not_none(course)
            assert_true(self.draft_store.has_course(course_key))
            mix_cased = SlashSeparatedCourseKey(
                course_key.org.upper(), course_key.course.upper(), course_key.run.lower()
            )
            assert_false(self.draft_store.has_course(mix_cased))
            assert_true(self.draft_store.has_course(mix_cased, ignore_case=True))

    def test_no_such_course(self):
        """
        Test get_course and has_course with ids which don't exist
        """
        for course_key in [

            SlashSeparatedCourseKey(*fields)
            for fields in [
                ['edX', 'simple', 'no_such_course'], ['edX', 'no_such_course', '2012_Fall'],
                ['NO_SUCH_COURSE', 'Test_iMport_courSe', '2012_Fall'],
            ]
        ]:
            course = self.draft_store.get_course(course_key)
            assert_is_none(course)
            assert_false(self.draft_store.has_course(course_key))
            mix_cased = SlashSeparatedCourseKey(
                course_key.org.lower(), course_key.course.upper(), course_key.run.upper()
            )
            assert_false(self.draft_store.has_course(mix_cased))
            assert_false(self.draft_store.has_course(mix_cased, ignore_case=True))

    def test_loads(self):
        assert_not_none(
            self.draft_store.get_item(Location('edX', 'toy', '2012_Fall', 'course', '2012_Fall'))
        )

        assert_not_none(
            self.draft_store.get_item(Location('edX', 'simple', '2012_Fall', 'course', '2012_Fall')),
        )

        assert_not_none(
            self.draft_store.get_item(Location('edX', 'toy', '2012_Fall', 'video', 'Welcome')),
        )

    def test_unicode_loads(self):
        """
        Test that getting items from the test_unicode course works
        """
        assert_not_none(
            self.draft_store.get_item(Location('edX', 'test_unicode', '2012_Fall', 'course', '2012_Fall')),
        )
        # All items with ascii-only filenames should load properly.
        assert_not_none(
            self.draft_store.get_item(Location('edX', 'test_unicode', '2012_Fall', 'video', 'Welcome')),
        )
        assert_not_none(
            self.draft_store.get_item(Location('edX', 'test_unicode', '2012_Fall', 'video', 'Welcome')),
        )
        assert_not_none(
            self.draft_store.get_item(Location('edX', 'test_unicode', '2012_Fall', 'chapter', 'Overview')),
        )

    def test_find_one(self):
        assert_not_none(
            self.draft_store._find_one(Location('edX', 'toy', '2012_Fall', 'course', '2012_Fall')),
        )

        assert_not_none(
            self.draft_store._find_one(Location('edX', 'simple', '2012_Fall', 'course', '2012_Fall')),
        )

        assert_not_none(
            self.draft_store._find_one(Location('edX', 'toy', '2012_Fall', 'video', 'Welcome')),
        )

    def test_xlinter(self):
        '''
        Run through the xlinter, we know the 'toy' course has violations, but the
        number will continue to grow over time, so just check > 0
        '''
        assert_not_equals(perform_xlint(DATA_DIR, ['toy']), 0)

    def test_get_courses_has_no_templates(self):
        courses = self.draft_store.get_courses()
        for course in courses:
            assert_false(
                course.location.org == 'edx' and course.location.course == 'templates',
                '{0} is a template course'.format(course)
            )

    def test_static_tab_names(self):

        def get_tab_name(index):
            """
            Helper function for pulling out the name of a given static tab.

            Assumes the information is desired for courses[4] ('toy' course).
            """
            course = self.draft_store.get_course(SlashSeparatedCourseKey('edX', 'toy', '2012_Fall'))
            return course.tabs[index]['name']

        # There was a bug where model.save was not getting called after the static tab name
        # was set set for tabs that have a URL slug. 'Syllabus' and 'Resources' fall into that
        # category, but for completeness, I'm also testing 'Course Info' and 'Discussion' (no url slug).
        assert_equals('Course Info', get_tab_name(1))
        assert_equals('Syllabus', get_tab_name(2))
        assert_equals('Resources', get_tab_name(3))
        assert_equals('Discussion', get_tab_name(4))

    def test_contentstore_attrs(self):
        """
        Test getting, setting, and defaulting the locked attr and arbitrary attrs.
        """
        location = Location('edX', 'toy', '2012_Fall', 'course', '2012_Fall')
        course_content, __ = self.content_store.get_all_content_for_course(location.course_key)
        assert_true(len(course_content) > 0)
        # a bit overkill, could just do for content[0]
        for content in course_content:
            assert not content.get('locked', False)
            asset_key = AssetLocation._from_deprecated_son(content.get('content_son', content['_id']), location.run)
            assert not self.content_store.get_attr(asset_key, 'locked', False)
            attrs = self.content_store.get_attrs(asset_key)
            assert_in('uploadDate', attrs)
            assert not attrs.get('locked', False)
            self.content_store.set_attr(asset_key, 'locked', True)
            assert self.content_store.get_attr(asset_key, 'locked', False)
            attrs = self.content_store.get_attrs(asset_key)
            assert_in('locked', attrs)
            assert attrs['locked'] is True
            self.content_store.set_attrs(asset_key, {'miscel': 99})
            assert_equals(self.content_store.get_attr(asset_key, 'miscel'), 99)

        asset_key = AssetLocation._from_deprecated_son(
            course_content[0].get('content_son', course_content[0]['_id']),
            location.run
        )
        assert_raises(
            AttributeError, self.content_store.set_attr, asset_key,
            'md5', 'ff1532598830e3feac91c2449eaa60d6'
        )
        assert_raises(
            AttributeError, self.content_store.set_attrs, asset_key,
            {'foo': 9, 'md5': 'ff1532598830e3feac91c2449eaa60d6'}
        )
        assert_raises(
            NotFoundError, self.content_store.get_attr,
            Location('bogus', 'bogus', 'bogus', 'asset', 'bogus'),
            'displayname'
        )
        assert_raises(
            NotFoundError, self.content_store.set_attr,
            Location('bogus', 'bogus', 'bogus', 'asset', 'bogus'),
            'displayname', 'hello'
        )
        assert_raises(
            NotFoundError, self.content_store.get_attrs,
            Location('bogus', 'bogus', 'bogus', 'asset', 'bogus')
        )
        assert_raises(
            NotFoundError, self.content_store.set_attrs,
            Location('bogus', 'bogus', 'bogus', 'asset', 'bogus'),
            {'displayname': 'hello'}
        )
        assert_raises(
            NotFoundError, self.content_store.set_attrs,
            Location('bogus', 'bogus', 'bogus', 'asset', None),
            {'displayname': 'hello'}
        )

    def test_get_courses_for_wiki(self):
        """
        Test the get_courses_for_wiki method
        """
        for course_number in self.courses:
            course_locations = self.draft_store.get_courses_for_wiki(course_number)
            assert_equals(len(course_locations), 1)
            assert_equals(SlashSeparatedCourseKey('edX', course_number, '2012_Fall'), course_locations[0])

        course_locations = self.draft_store.get_courses_for_wiki('no_such_wiki')
        assert_equals(len(course_locations), 0)

        # set toy course to share the wiki with simple course
        toy_course = self.draft_store.get_course(SlashSeparatedCourseKey('edX', 'toy', '2012_Fall'))
        toy_course.wiki_slug = 'simple'
        self.draft_store.update_item(toy_course, ModuleStoreEnum.UserID.test)

        # now toy_course should not be retrievable with old wiki_slug
        course_locations = self.draft_store.get_courses_for_wiki('toy')
        assert_equals(len(course_locations), 0)

        # but there should be two courses with wiki_slug 'simple'
        course_locations = self.draft_store.get_courses_for_wiki('simple')
        assert_equals(len(course_locations), 2)
        for course_number in ['toy', 'simple']:
            assert_in(SlashSeparatedCourseKey('edX', course_number, '2012_Fall'), course_locations)

        # configure simple course to use unique wiki_slug.
        simple_course = self.draft_store.get_course(SlashSeparatedCourseKey('edX', 'simple', '2012_Fall'))
        simple_course.wiki_slug = 'edX.simple.2012_Fall'
        self.draft_store.update_item(simple_course, ModuleStoreEnum.UserID.test)
        # it should be retrievable with its new wiki_slug
        course_locations = self.draft_store.get_courses_for_wiki('edX.simple.2012_Fall')
        assert_equals(len(course_locations), 1)
        assert_in(SlashSeparatedCourseKey('edX', 'simple', '2012_Fall'), course_locations)

    @Plugin.register_temp_plugin(ReferenceTestXBlock, 'ref_test')
    def test_reference_converters(self):
        """
        Test that references types get deserialized correctly
        """
        course_key = SlashSeparatedCourseKey('edX', 'toy', '2012_Fall')

        def setup_test():
            course = self.draft_store.get_course(course_key)
            # can't use item factory as it depends on django settings
            p1ele = self.draft_store.create_item(
                99,
                course_key,
                'problem',
                block_id='p1',
                runtime=course.runtime
            )
            p2ele = self.draft_store.create_item(
                99,
                course_key,
                'problem',
                block_id='p2',
                runtime=course.runtime
            )
            self.refloc = course.id.make_usage_key('ref_test', 'ref_test')
            self.draft_store.create_item(
                99,
                self.refloc.course_key,
                self.refloc.block_type,
                block_id=self.refloc.block_id,
                runtime=course.runtime,
                fields={
                    'reference_link': p1ele.location,
                    'reference_list': [p1ele.location, p2ele.location],
                    'reference_dict': {'p1': p1ele.location, 'p2': p2ele.location},
                    'children': [p1ele.location, p2ele.location],
                }
            )

        def check_xblock_fields():
            def check_children(xblock):
                for child in xblock.children:
                    assert_is_instance(child, UsageKey)

            course = self.draft_store.get_course(course_key)
            check_children(course)

            refele = self.draft_store.get_item(self.refloc)
            check_children(refele)
            assert_is_instance(refele.reference_link, UsageKey)
            assert_greater(len(refele.reference_list), 0)
            for ref in refele.reference_list:
                assert_is_instance(ref, UsageKey)
            assert_greater(len(refele.reference_dict), 0)
            for ref in refele.reference_dict.itervalues():
                assert_is_instance(ref, UsageKey)

        def check_mongo_fields():
            def get_item(location):
                return self.draft_store._find_one(as_draft(location))

            def check_children(payload):
                for child in payload['definition']['children']:
                    assert_is_instance(child, basestring)

            refele = get_item(self.refloc)
            check_children(refele)
            assert_is_instance(refele['definition']['data']['reference_link'], basestring)
            assert_greater(len(refele['definition']['data']['reference_list']), 0)
            for ref in refele['definition']['data']['reference_list']:
                assert_is_instance(ref, basestring)
            assert_greater(len(refele['metadata']['reference_dict']), 0)
            for ref in refele['metadata']['reference_dict'].itervalues():
                assert_is_instance(ref, basestring)

        setup_test()
        check_xblock_fields()
        check_mongo_fields()

    def test_export_course_image(self):
        """
        Test to make sure that we have a course image in the contentstore,
        then export it to ensure it gets copied to both file locations.
        """
        course_key = SlashSeparatedCourseKey('edX', 'simple', '2012_Fall')
        location = course_key.make_asset_key('asset', 'images_course_image.jpg')

        # This will raise if the course image is missing
        self.content_store.find(location)

        root_dir = path(mkdtemp())
        try:
            export_to_xml(self.draft_store, self.content_store, course_key, root_dir, 'test_export')
            assert_true(path(root_dir / 'test_export/static/images/course_image.jpg').isfile())
            assert_true(path(root_dir / 'test_export/static/images_course_image.jpg').isfile())
        finally:
            shutil.rmtree(root_dir)

    def test_export_course_image_nondefault(self):
        """
        Make sure that if a non-default image path is specified that we
        don't export it to the static default location
        """
        course = self.draft_store.get_course(SlashSeparatedCourseKey('edX', 'toy', '2012_Fall'))
        assert_true(course.course_image, 'just_a_test.jpg')

        root_dir = path(mkdtemp())
        try:
            export_to_xml(self.draft_store, self.content_store, course.id, root_dir, 'test_export')
            assert_true(path(root_dir / 'test_export/static/just_a_test.jpg').isfile())
            assert_false(path(root_dir / 'test_export/static/images/course_image.jpg').isfile())
        finally:
            shutil.rmtree(root_dir)

    def test_course_without_image(self):
        """
        Make sure we elegantly passover our code when there isn't a static
        image
        """
        course = self.draft_store.get_course(SlashSeparatedCourseKey('edX', 'simple_with_draft', '2012_Fall'))
        root_dir = path(mkdtemp())
        try:
            export_to_xml(self.draft_store, self.content_store, course.id, root_dir, 'test_export')
            assert_false(path(root_dir / 'test_export/static/images/course_image.jpg').isfile())
            assert_false(path(root_dir / 'test_export/static/images_course_image.jpg').isfile())
        finally:
            shutil.rmtree(root_dir)

    def _create_test_tree(self, name, user_id=None):
        """
        Creates and returns a tree with the following structure:
        Grandparent
            Parent Sibling
            Parent
                Child
                Child Sibling

        """
        if user_id is None:
            user_id = self.dummy_user

        org = 'edX'
        course = 'tree{}'.format(name)
        run = name

        if not self.draft_store.has_course(SlashSeparatedCourseKey(org, course, run)):
            self.draft_store.create_course(org, course, run, user_id)

            locations = {
                'grandparent': Location(org, course, run, 'chapter', 'grandparent'),
                'parent_sibling': Location(org, course, run, 'sequential', 'parent_sibling'),
                'parent': Location(org, course, run, 'sequential', 'parent'),
                'child_sibling': Location(org, course, run, 'vertical', 'child_sibling'),
                'child': Location(org, course, run, 'vertical', 'child'),
            }

            for key in locations:
                self.draft_store.create_item(
                    user_id,
                    locations[key].course_key,
                    locations[key].block_type,
                    block_id=locations[key].block_id
                )

            grandparent = self.draft_store.get_item(locations['grandparent'])
            grandparent.children += [locations['parent_sibling'], locations['parent']]
            self.draft_store.update_item(grandparent, user_id=user_id)

            parent = self.draft_store.get_item(locations['parent'])
            parent.children += [locations['child_sibling'], locations['child']]
            self.draft_store.update_item(parent, user_id=user_id)

            self.draft_store.publish(locations['parent'], user_id)
            self.draft_store.publish(locations['parent_sibling'], user_id)

        return locations

    def test_migrate_published_info(self):
        """
        Tests that blocks that were storing published_date and published_by through CMSBlockMixin are loaded correctly
        """

        # Insert the test block directly into the module store
        location = Location('edX', 'migration', '2012_Fall', 'html', 'test_html')
        published_date = datetime(1970, 1, 1, tzinfo=UTC)
        published_by = 123
        self.draft_store._update_single_item(
            as_draft(location),
            {
                'definition.data': {},
                'metadata': {
                    # published_date was previously stored as a list of time components, not a datetime
                    'published_date': list(published_date.timetuple()),
                    'published_by': published_by,
                },
            },
            allow_not_found=True,
        )

        # Retrieve the block and verify its fields
        component = self.draft_store.get_item(location)
        self.assertEqual(component.published_on, published_date)
        self.assertEqual(component.published_by, published_by)

    def test_export_course_with_peer_component(self):
        """
        Test export course when link_to_location is given in peer grading interface settings.
        """

        name = "export_peer_component"

        locations = self._create_test_tree(name)

        # Insert the test block directly into the module store
        problem_location = Location('edX', 'tree{}'.format(name), name, 'combinedopenended', 'test_peer_problem')

        self.draft_store.create_child(
            self.dummy_user,
            locations["child"],
            problem_location.block_type,
            block_id=problem_location.block_id
        )

        interface_location = Location('edX', 'tree{}'.format(name), name, 'peergrading', 'test_peer_interface')

        self.draft_store.create_child(
            self.dummy_user,
            locations["child"],
            interface_location.block_type,
            block_id=interface_location.block_id
        )

        self.draft_store._update_single_item(
            as_draft(interface_location),
            {
                'definition.data': {},
                'metadata': {
                    'link_to_location': unicode(problem_location),
                    'use_for_single_location': True,
                },
            },
        )

        component = self.draft_store.get_item(interface_location)
        self.assertEqual(unicode(component.link_to_location), unicode(problem_location))

        root_dir = path(mkdtemp())

        # export_to_xml should work.
        try:
            export_to_xml(self.draft_store, self.content_store, interface_location.course_key, root_dir, 'test_export')
        finally:
            shutil.rmtree(root_dir)


@ddt
class TestMongoAssetMetadataStorage(TestMongoModuleStore):
    """
    Tests for storing/querying course asset metadata from Mongo storage.
    """
    def _make_asset_metadata(self, asset_loc):
        return AssetMetadata(asset_loc, internal_name='EKMND332DDBK',
                             basename='pictures/historical', contenttype='image/jpeg',
                             locked=False, md5='77631ca4f0e08419b70726a447333ab6',
                             edited_by='CourseAuthor', edited_on=datetime.now(),
                             curr_version='v1.0', prev_version='v0.95')

    def _make_asset_thumbnail_metadata(self, asset_key):
        return AssetThumbnailMetadata(asset_key, internal_name='ABC39XJUDN2')

    @classmethod
    def setupClass(cls):
        super(TestMongoAssetMetadataStorage, cls).setupClass()

    @classmethod
    def teardownClass(cls):
        super(TestMongoAssetMetadataStorage, cls).teardownClass()

    def setUp(self):
        """
        Set up a quantity of test asset metadata for testing purposes.
        """
        super(TestMongoAssetMetadataStorage, self).setUp()
        ASSET_FIELDS = ('filename', 'internal_name', 'basename', 'locked', 'edited_by', 'edited_on', 'curr_version', 'prev_version')
        ASSET1_VALS = ('pic1.jpg', 'EKMND332DDBK', 'pix/archive', False, 'Author1', datetime.now(), '14', '13')
        ASSET2_VALS = ('shout.ogg', 'KFMDONSKF39K', 'sounds', True, 'Author1', datetime.now(), '1', None)
        ASSET3_VALS = ('code.tgz', 'ZZB2333YBDMW', 'exercises/14', False, 'Author2', datetime.now(), 'AB', 'AA')
        ASSET4_VALS = ('dog.png', 'PUPY4242X', 'pictures/animals', True, 'Author3', datetime.now(), '5', '4')
        ASSET5_VALS = ('not_here.txt', 'JJJCCC747', '/dev/null', False, 'Author4', datetime.now(), '50', '49')

        ASSET1 = dict(zip(ASSET_FIELDS, ASSET1_VALS))
        ASSET2 = dict(zip(ASSET_FIELDS, ASSET2_VALS))
        ASSET3 = dict(zip(ASSET_FIELDS, ASSET3_VALS))
        ASSET4 = dict(zip(ASSET_FIELDS, ASSET4_VALS))
        NON_EXISTENT_ASSET = dict(zip(ASSET_FIELDS, ASSET5_VALS))

        THUMBNAIL_FIELDS = ('filename', 'internal_name')
        THUMBNAIL1_VALS = ('cat_thumb.jpg', 'XYXYXYXYXYXY')
        THUMBNAIL2_VALS = ('kitten_thumb.jpg', '123ABC123ABC')
        THUMBNAIL3_VALS = ('puppy_thumb.jpg', 'ADAM12ADAM12')
        THUMBNAIL4_VALS = ('meerkat_thumb.jpg', 'CHIPSPONCH14')
        THUMBNAIL5_VALS = ('corgi_thumb.jpg', 'RON8LDXFFFF10')

        THUMBNAIL1 = dict(zip(THUMBNAIL_FIELDS, THUMBNAIL1_VALS))
        THUMBNAIL2 = dict(zip(THUMBNAIL_FIELDS, THUMBNAIL2_VALS))
        THUMBNAIL3 = dict(zip(THUMBNAIL_FIELDS, THUMBNAIL3_VALS))
        THUMBNAIL4 = dict(zip(THUMBNAIL_FIELDS, THUMBNAIL4_VALS))
        NON_EXISTENT_THUMBNAIL = dict(zip(THUMBNAIL_FIELDS, THUMBNAIL5_VALS))

        # The asset and thumbnail below have equivalent information on purpose.
        ASSET6_VALS = ('asset.txt', 'JJJCCC747858', '/dev/null', False, 'Author4', datetime.now(), '50', '49')
        THUMBNAIL6_VALS = ('asset.txt', 'JJJCCC747858')
        ASSET6 = dict(zip(ASSET_FIELDS, ASSET6_VALS))
        THUMBNAIL6 = dict(zip(THUMBNAIL_FIELDS, THUMBNAIL6_VALS))

        courses = self.draft_store.get_courses()
        self.course1 = courses[0]
        self.course2 = courses[1]

        asset1_key = self.course1.id.make_asset_key('asset', ASSET1['filename'])
        asset2_key = self.course1.id.make_asset_key('asset', ASSET2['filename'])
        asset3_key = self.course2.id.make_asset_key('asset', ASSET3['filename'])
        asset4_key = self.course2.id.make_asset_key('asset', ASSET4['filename'])
        asset5_key = self.course2.id.make_asset_key('asset', NON_EXISTENT_ASSET['filename'])
        asset6_key = self.course2.id.make_asset_key('asset', ASSET6['filename'])

        self.asset1_md = AssetMetadata(asset1_key, **ASSET1)
        self.asset2_md = AssetMetadata(asset2_key, **ASSET2)
        self.asset3_md = AssetMetadata(asset3_key, **ASSET3)
        self.asset4_md = AssetMetadata(asset4_key, **ASSET4)
        self.asset5_md = AssetMetadata(asset5_key, **NON_EXISTENT_ASSET)
        self.asset6_md = AssetMetadata(asset6_key, **ASSET6)

        self.assertTrue(self.draft_store.save_asset_metadata(self.course1.id, self.asset1_md))
        self.assertTrue(self.draft_store.save_asset_metadata(self.course1.id, self.asset2_md))
        self.assertTrue(self.draft_store.save_asset_metadata(self.course2.id, self.asset3_md))
        self.assertTrue(self.draft_store.save_asset_metadata(self.course2.id, self.asset4_md))
        # asset5 and asset6 are not saved on purpose!

        thumb1_key = self.course1.id.make_asset_key('thumbnail', THUMBNAIL1['filename'])
        thumb2_key = self.course1.id.make_asset_key('thumbnail', THUMBNAIL2['filename'])
        thumb3_key = self.course2.id.make_asset_key('thumbnail', THUMBNAIL3['filename'])
        thumb4_key = self.course2.id.make_asset_key('thumbnail', THUMBNAIL4['filename'])
        thumb5_key = self.course2.id.make_asset_key('thumbnail', NON_EXISTENT_THUMBNAIL['filename'])
        thumb6_key = self.course2.id.make_asset_key('thumbnail', THUMBNAIL6['filename'])

        self.thumb1_md = AssetThumbnailMetadata(thumb1_key, **THUMBNAIL1)
        self.thumb2_md = AssetThumbnailMetadata(thumb2_key, **THUMBNAIL2)
        self.thumb3_md = AssetThumbnailMetadata(thumb3_key, **THUMBNAIL3)
        self.thumb4_md = AssetThumbnailMetadata(thumb4_key, **THUMBNAIL4)
        self.thumb5_md = AssetThumbnailMetadata(thumb5_key, **NON_EXISTENT_THUMBNAIL)
        self.thumb6_md = AssetThumbnailMetadata(thumb6_key, **THUMBNAIL6)

        self.assertTrue(self.draft_store.save_asset_thumbnail_metadata(self.course1.id, self.thumb1_md))
        self.assertTrue(self.draft_store.save_asset_thumbnail_metadata(self.course1.id, self.thumb2_md))
        self.assertTrue(self.draft_store.save_asset_thumbnail_metadata(self.course2.id, self.thumb3_md))
        self.assertTrue(self.draft_store.save_asset_thumbnail_metadata(self.course2.id, self.thumb4_md))
        # thumb5 and thumb6 are not saved on purpose!

    def tearDown(self):
        self.draft_store.delete_all_asset_metadata(self.course1.id)
        self.draft_store.delete_all_asset_metadata(self.course2.id)

    def test_save_one_and_confirm(self):
        courses = self.draft_store.get_courses()
        course = courses[0]
        ASSET_FILENAME = 'burnside.jpg'
        new_asset_loc = course.id.make_asset_key('asset', ASSET_FILENAME)
        # Confirm that the asset's metadata is not present.
        self.assertIsNone(self.draft_store.find_asset_metadata(new_asset_loc))
        # Save the asset's metadata.
        new_asset_md = self._make_asset_metadata(new_asset_loc)
        self.assertTrue(self.draft_store.save_asset_metadata(course.id, new_asset_md))
        # Find the asset's metadata and confirm it's the same.
        found_asset_md = self.draft_store.find_asset_metadata(new_asset_loc)
        self.assertIsNotNone(found_asset_md)
        self.assertEquals(new_asset_md, found_asset_md)
        # Confirm that only two setup plus one asset's metadata exists.
        self.assertEquals(len(self.draft_store.get_all_asset_metadata(course.id)), 3)
        # Delete all metadata and confirm it's gone.
        self.draft_store.delete_all_asset_metadata(course.id)
        self.assertEquals(len(self.draft_store.get_all_asset_metadata(course.id)), 0)

    def test_delete_all_without_creation(self):
        courses = self.draft_store.get_courses()
        course = courses[0]
        # Confirm that only setup asset metadata exists.
        self.assertEquals(len(self.draft_store.get_all_asset_metadata(course.id)), 2)
        # Now delete the metadata.
        self.draft_store.delete_all_asset_metadata(course.id)
        self.assertEquals(len(self.draft_store.get_all_asset_metadata(course.id)), 0)
        # Now delete the non-existent metadata.
        self.draft_store.delete_all_asset_metadata(course.id)
        self.assertEquals(len(self.draft_store.get_all_asset_metadata(course.id)), 0)

    def test_save_many_and_delete_one(self):
        # Make sure there's two assets.
        self.assertEquals(len(self.draft_store.get_all_asset_metadata(self.course1.id)), 2)
        # Delete one of the assets.
        self.assertEquals(self.draft_store.delete_asset_metadata(self.asset1_md.asset_id), 1)
        self.assertEquals(len(self.draft_store.get_all_asset_metadata(self.course1.id)), 1)
        # Attempt to delete an asset that doesn't exist.
        self.assertEquals(self.draft_store.delete_asset_metadata(self.asset5_md.asset_id), 0)
        self.assertEquals(len(self.draft_store.get_all_asset_metadata(self.course1.id)), 1)

    def test_find_existing_and_non_existing_assets(self):
        # Find existing asset metadata.
        asset_md = self.draft_store.find_asset_metadata(self.asset1_md.asset_id)
        self.assertIsNotNone(asset_md)
        # Find non-existent asset metadata.
        asset_md = self.draft_store.find_asset_metadata(self.asset5_md.asset_id)
        self.assertIsNone(asset_md)

    def test_add_same_asset_twice(self):
        courses = self.draft_store.get_courses()
        course = courses[0]
        ASSET_FILENAME = 'burnside.jpg'
        new_asset_loc = course.id.make_asset_key('asset', ASSET_FILENAME)
        new_asset_md = self._make_asset_metadata(new_asset_loc)
        # Only the setup stuff here?
        self.assertEquals(len(self.draft_store.get_all_asset_metadata(course.id)), 2)
        # Add asset metadata.
        self.assertTrue(self.draft_store.save_asset_metadata(course.id, new_asset_md))
        self.assertEquals(len(self.draft_store.get_all_asset_metadata(course.id)), 3)
        # Add *the same* asset metadata.
        self.assertTrue(self.draft_store.save_asset_metadata(course.id, new_asset_md))
        # Still one here?
        self.assertEquals(len(self.draft_store.get_all_asset_metadata(course.id)), 3)
        self.draft_store.delete_all_asset_metadata(course.id)
        self.assertEquals(len(self.draft_store.get_all_asset_metadata(course.id)), 0)

    def test_lock_unlock_assets(self):
        # Find a course asset and check its locked status.
        asset_md = self.draft_store.find_asset_metadata(self.asset1_md.asset_id)
        self.assertIsNotNone(asset_md)
        locked_state = asset_md.locked
        # Flip the course asset's locked status.
        self.draft_store.set_asset_metadata_attr(self.asset1_md.asset_id, "locked", not locked_state)
        # Find the same course and check its locked status.
        updated_asset_md = self.draft_store.find_asset_metadata(self.asset1_md.asset_id)
        self.assertIsNotNone(updated_asset_md)
        self.assertEquals(updated_asset_md.locked, not locked_state)
        # Now flip it back.
        self.draft_store.set_asset_metadata_attr(self.asset1_md.asset_id, "locked", locked_state)
        reupdated_asset_md = self.draft_store.find_asset_metadata(self.asset1_md.asset_id)
        self.assertIsNotNone(reupdated_asset_md)
        self.assertEquals(reupdated_asset_md.locked, locked_state)

    ALLOWED_ATTRS = (
        ('basename', '/new/path'),
        ('internal_name', 'new_filename.txt'),
        ('locked', True),
        ('contenttype', 'image/png'),
        ('md5', '5346682d948cc3f683635b6918f9b3d0'),
        ('curr_version', 'v1.01'),
        ('prev_version', 'v1.0'),
        ('edited_by', 'Mork'),
        ('edited_on', datetime(1969, 1, 1, tzinfo=UTC)),
    )

    DISALLOWED_ATTRS = (
        ('asset_id', 'IAmBogus'),
    )

    UNKNOWN_ATTRS = (
        ('lunch_order', 'burger_and_fries'),
        ('villain', 'Khan')
    )

    @data(*ALLOWED_ATTRS)
    def test_set_all_attrs(self, attrPair):
        # Find a course asset.
        asset_md = self.draft_store.find_asset_metadata(self.asset1_md.asset_id)
        self.assertIsNotNone(asset_md)
        # Set the course asset's attr.
        self.draft_store.set_asset_metadata_attr(self.asset1_md.asset_id, *attrPair)
        # Find the same course asset and check its changed attr.
        updated_asset_md = self.draft_store.find_asset_metadata(self.asset1_md.asset_id)
        self.assertIsNotNone(updated_asset_md)
        self.assertIsNotNone(getattr(updated_asset_md, attrPair[0], None))
        self.assertEquals(getattr(updated_asset_md, attrPair[0], None), attrPair[1])

    @data(*DISALLOWED_ATTRS)
    def test_set_disallowed_attrs(self, attrPair):
        # Find a course asset.
        asset_md = self.draft_store.find_asset_metadata(self.asset1_md.asset_id)
        self.assertIsNotNone(asset_md)
        original_attr_val = getattr(asset_md, attrPair[0])
        # Set the course asset's attr.
        self.draft_store.set_asset_metadata_attr(self.asset1_md.asset_id, *attrPair)
        # Find the same course and check its changed attr.
        updated_asset_md = self.draft_store.find_asset_metadata(self.asset1_md.asset_id)
        self.assertIsNotNone(updated_asset_md)
        self.assertIsNotNone(getattr(updated_asset_md, attrPair[0], None))
        # Make sure that the attr is unchanged from its original value.
        self.assertEquals(getattr(updated_asset_md, attrPair[0], None), original_attr_val)

    @data(*UNKNOWN_ATTRS)
    def test_set_unknown_attrs(self, attrPair):
        # Find a course asset.
        asset_md = self.draft_store.find_asset_metadata(self.asset1_md.asset_id)
        self.assertIsNotNone(asset_md)
        # Set the course asset's attr.
        self.draft_store.set_asset_metadata_attr(self.asset1_md.asset_id, *attrPair)
        # Find the same course and check its changed attr.
        updated_asset_md = self.draft_store.find_asset_metadata(self.asset1_md.asset_id)
        self.assertIsNotNone(updated_asset_md)
        # Make sure the unknown field was *not* added.
        with self.assertRaises(AttributeError):
            self.assertEquals(getattr(updated_asset_md, attrPair[0]), attrPair[1])

    def test_save_one_thumbnail_and_delete_one_thumbnail(self):
        THUMBNAIL_FILENAME = 'burn_thumb.jpg'
        asset_key = self.course1.id.make_asset_key('thumbnail', THUMBNAIL_FILENAME)
        new_asset_thumbnail = self._make_asset_thumbnail_metadata(asset_key)
        self.assertEquals(len(self.draft_store.get_all_asset_thumbnail_metadata(self.course1.id)), 2)
        self.assertTrue(self.draft_store.save_asset_thumbnail_metadata(self.course1.id, new_asset_thumbnail))
        self.assertEquals(len(self.draft_store.get_all_asset_thumbnail_metadata(self.course1.id)), 3)
        self.assertEquals(self.draft_store.delete_asset_thumbnail_metadata(asset_key), 1)
        self.assertEquals(len(self.draft_store.get_all_asset_thumbnail_metadata(self.course1.id)), 2)

    def test_find_thumbnail(self):
        self.assertIsNotNone(self.draft_store.find_asset_thumbnail_metadata(self.thumb1_md.asset_id))
        self.assertIsNone(self.draft_store.find_asset_thumbnail_metadata(self.thumb5_md.asset_id))

    def test_delete_all_thumbnails(self):
        self.assertEquals(len(self.draft_store.get_all_asset_thumbnail_metadata(self.course1.id)), 2)
        self.draft_store.delete_all_asset_metadata(self.course1.id)
        self.assertEquals(len(self.draft_store.get_all_asset_thumbnail_metadata(self.course1.id)), 0)

    def test_asset_object_equivalence(self):
        # Assets are not equivalent to thumbnails - even if all their info is the same.
        self.assertTrue(self.asset6_md != self.thumb6_md)
        # Ensure asset object ordering.
        self.assertTrue(self.asset1_md < self.asset2_md)
        self.assertFalse(self.asset1_md > self.asset2_md)
        self.assertFalse(self.asset1_md == self.asset2_md)
        self.assertTrue(self.asset3_md < self.asset4_md)
        self.assertFalse(self.asset3_md > self.asset4_md)
        self.assertFalse(self.asset3_md == self.asset4_md)
        self.assertEquals(self.asset1_md, self.asset1_md)
        # Ensure thumbnail object ordering.
        self.assertTrue(self.thumb1_md < self.thumb2_md)
        self.assertFalse(self.thumb1_md > self.thumb2_md)
        self.assertFalse(self.thumb1_md == self.thumb2_md)

    def test_get_all_assets_with_paging(self):
        pass

    def test_copy_all_assets(self):
        pass


class TestMongoKeyValueStore(object):
    """
    Tests for MongoKeyValueStore.
    """

    def setUp(self):
        self.data = {'foo': 'foo_value'}
        self.course_id = SlashSeparatedCourseKey('org', 'course', 'run')
        self.children = [self.course_id.make_usage_key('child', 'a'), self.course_id.make_usage_key('child', 'b')]
        self.metadata = {'meta': 'meta_val'}
        self.kvs = MongoKeyValueStore(self.data, self.children, self.metadata)

    def test_read(self):
        assert_equals(self.data['foo'], self.kvs.get(KeyValueStore.Key(Scope.content, None, None, 'foo')))
        assert_equals(self.children, self.kvs.get(KeyValueStore.Key(Scope.children, None, None, 'children')))
        assert_equals(self.metadata['meta'], self.kvs.get(KeyValueStore.Key(Scope.settings, None, None, 'meta')))
        assert_equals(None, self.kvs.get(KeyValueStore.Key(Scope.parent, None, None, 'parent')))

    def test_read_invalid_scope(self):
        for scope in (Scope.preferences, Scope.user_info, Scope.user_state):
            key = KeyValueStore.Key(scope, None, None, 'foo')
            with assert_raises(InvalidScopeError):
                self.kvs.get(key)
            assert_false(self.kvs.has(key))

    def test_read_non_dict_data(self):
        self.kvs = MongoKeyValueStore('xml_data', self.children, self.metadata)
        assert_equals('xml_data', self.kvs.get(KeyValueStore.Key(Scope.content, None, None, 'data')))

    def _check_write(self, key, value):
        self.kvs.set(key, value)
        assert_equals(value, self.kvs.get(key))

    def test_write(self):
        yield (self._check_write, KeyValueStore.Key(Scope.content, None, None, 'foo'), 'new_data')
        yield (self._check_write, KeyValueStore.Key(Scope.children, None, None, 'children'), [])
        yield (self._check_write, KeyValueStore.Key(Scope.settings, None, None, 'meta'), 'new_settings')

    def test_write_non_dict_data(self):
        self.kvs = MongoKeyValueStore('xml_data', self.children, self.metadata)
        self._check_write(KeyValueStore.Key(Scope.content, None, None, 'data'), 'new_data')

    def test_write_invalid_scope(self):
        for scope in (Scope.preferences, Scope.user_info, Scope.user_state, Scope.parent):
            with assert_raises(InvalidScopeError):
                self.kvs.set(KeyValueStore.Key(scope, None, None, 'foo'), 'new_value')

    def _check_delete_default(self, key, default_value):
        self.kvs.delete(key)
        assert_equals(default_value, self.kvs.get(key))
        assert self.kvs.has(key)

    def _check_delete_key_error(self, key):
        self.kvs.delete(key)
        with assert_raises(KeyError):
            self.kvs.get(key)
        assert_false(self.kvs.has(key))

    def test_delete(self):
        yield (self._check_delete_key_error, KeyValueStore.Key(Scope.content, None, None, 'foo'))
        yield (self._check_delete_default, KeyValueStore.Key(Scope.children, None, None, 'children'), [])
        yield (self._check_delete_key_error, KeyValueStore.Key(Scope.settings, None, None, 'meta'))

    def test_delete_invalid_scope(self):
        for scope in (Scope.preferences, Scope.user_info, Scope.user_state, Scope.parent):
            with assert_raises(InvalidScopeError):
                self.kvs.delete(KeyValueStore.Key(scope, None, None, 'foo'))