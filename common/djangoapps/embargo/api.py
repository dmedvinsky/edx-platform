"""
The Python API layer of the country access settings. Essentially the middle tier of the project, responsible for all
business logic that is not directly tied to the data itself.

This API is exposed via the middleware(emabargo/middileware.py) layer but may be used directly in-process.

"""
import logging
import pygeoip

from django.core.cache import cache
from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponseForbidden
from embargo.models import CountryAccessRule, IPFilter, RestrictedCourse

log = logging.getLogger(__name__)

# Reasons a user might be blocked.
# These are used to generate info messages in the logs.
REASONS = {
    "ip_blacklist": u"Restricting IP address {ip_addr} {from_course} because IP is blacklisted.",
    "ip_country": u"Restricting IP address {ip_addr} {from_course} because IP is from country {ip_country}.",
    "profile_country": (
        u"Restricting user {user_id} {from_course} because "
        u"the user set the profile country to {profile_country}."
    )
}


def _from_course_msg(course_id, course_is_embargoed):
    """
    Format a message indicating whether the user was blocked from a specific course.
    This can be used in info messages, but should not be used in user-facing messages.

    Args:
        course_id (unicode): The ID of the course being accessed.
        course_is_embarged (boolean): Whether the course being accessed is embargoed.

    Returns:
        unicode

    """
    return (
        u"from course {course_id}".format(course_id=course_id)
        if course_is_embargoed
        else u""
    )


def _embargo_redirect_response():
    """
    The HTTP response to send when the user is blocked from a course.
    This will either be a redirect to a URL configured in Django settings
    or a forbidden response.

    Returns:
        HTTPResponse

    """
    redirect_url = getattr(settings, 'EMBARGO_SITE_REDIRECT_URL', None)
    response = (
        HttpResponseRedirect(redirect_url)
        if redirect_url
        else HttpResponseForbidden('Access Denied')
    )

    return response


def _check_ip_lists(ip_addr):
    """
    Check whether the user is embargoed based on the IP address.

    Args:
        ip_addr (str): The IP address the request originated from.

    Returns:
        A True if the user is not blacklisted, otherwise False

    """
    # If blacklisted, immediately fail
    if ip_addr in IPFilter.current().blacklist_ips:
        return False

    # If we're white-listed, then allow access
    if ip_addr in IPFilter.current().whitelist_ips:
        return True

    return True
    # If none of the other checks caught anything,
    # implicitly return True to indicate that the user can access the course


def _check_user_country(country_code, course_id=u""):
    """
    Check the user country has access on the course
    Args:
        country_code (str): The user country.
        course_id (unicode): The course the user is trying to access.
    """

    return CountryAccessRule.check_country_access(course_id, country_code)


def get_user_country_from_profile(user):
    """
    Check whether the user is embargoed based on the country code in the user's profile.

    Args:
        user (User): The user attempting to access courseware.

    Returns:
        user country from profile.

    """
    cache_key = u'user.{user_id}.profile.country'.format(user_id=user.id)
    profile_country = cache.get(cache_key)
    if profile_country is None:
        profile = getattr(user, 'profile', None)
        if profile is not None and profile.country.code is not None:
            profile_country = profile.country.code.upper()
        else:
            profile_country = ""
        cache.set(cache_key, profile_country)

    return profile_country


def _country_code_from_ip(ip_addr):
    """
    Return the country code associated with an IP address.
    Handles both IPv4 and IPv6 addresses.

    Args:
        ip_addr (str): The IP address to look up.

    Returns:
        str: A 2-letter country code.

    """
    if ip_addr.find(':') >= 0:
        return pygeoip.GeoIP(settings.GEOIPV6_PATH).country_code_by_addr(ip_addr)
    else:
        return pygeoip.GeoIP(settings.GEOIP_PATH).country_code_by_addr(ip_addr)


def check_course_access(user, ip_address, course_key):
    """
    Check is the user with this ip_address has access to the given course

    Params:
        user (User): Currently logged in user object
        ip_address (str): The ip_address of user
        course_key (CourseLocator): CourseLocator object the user is trying to access

    Returns:
        The return will be `None` if the user passes the check and can access the course.
        if any constraints fails Redirect to a URL configured in Django settings or a forbidden response
    """
    course_is_restricted = RestrictedCourse.is_restricted_course(course_key)
    # If they're trying to access a course that cares about embargoes

    # If course is not restricted then return immediately return True
    # no need for further checking
    if not course_is_restricted:
        return True

    # If ipaddress has access return True
    if not _check_ip_lists(ip_address):
        return False

    # Retrieve the country code from the IP address
    # and check it against the allowed countries list for a course

    user_country_from_ip = _country_code_from_ip(ip_address)
    # if user country has access to course return True
    if not _check_user_country(user_country_from_ip, course_key):
        return False
    #
    # Retrieve the country code from the user profile.
    user_country_from_profile = get_user_country_from_profile(user)
    # if profile country has access return True
    if not _check_user_country(user_country_from_profile, course_key):
        return False

    return True

    # If all the check functions pass, implicitly return True
