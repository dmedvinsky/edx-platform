"""
Test for export all courses.
"""
import shutil
from tempfile import mkdtemp

from contentstore.management.commands.export_all_courses import export_courses_to_output_path

from xmodule.modulestore import ModuleStoreEnum
from xmodule.modulestore.django import modulestore
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from xmodule.modulestore.tests.factories import CourseFactory


class ExportAllCourses(ModuleStoreTestCase):
    """
    Tests exporting all courses.
    """
    def setUp(self):
        """ Common setup. """
        super(ExportAllCourses, self).setUp()
        self.store = modulestore()._get_modulestore_by_type(ModuleStoreEnum.Type.mongo)
        self.temp_dir = mkdtemp()
        self.first_course = CourseFactory.create(org="test", course="course1", display_name="run1")
        self.second_course = CourseFactory.create(org="test", course="course2", display_name="run2")

    def test_export_all_courses(self):
        """
        Test exporting good and faulty courses
        """
        # check that both courses exported successfully
        courses, failed_export_courses = export_courses_to_output_path(self.temp_dir)
        self.assertEqual(len(courses), 2)
        self.assertEqual(len(failed_export_courses), 0)

        # manually make second course faulty and check that it fails on export
        second_course_id = self.second_course.id
        self.store.collection.update(
            {'_id.org': second_course_id.org, '_id.course': second_course_id.course, '_id.name': second_course_id.run},
            {'$set': {'metadata.tags': 'crash'}}
        )
        courses, failed_export_courses = export_courses_to_output_path(self.temp_dir)
        self.assertEqual(len(courses), 2)
        self.assertEqual(len(failed_export_courses), 1)
        self.assertEqual(failed_export_courses[0], unicode(second_course_id))

    def tearDown(self):
        """ Common cleanup. """
        shutil.rmtree(self.temp_dir)
