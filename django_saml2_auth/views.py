#!/usr/bin/env python
# -*- coding:utf-8 -*-

import logging

logger = logging.getLogger(__name__)

from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from django import get_version
from pkg_resources import parse_version
from django.conf import settings
from django.contrib.auth.models import Group
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, get_user_model
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.template import TemplateDoesNotExist
from django.http import HttpResponseRedirect
from django.utils.http import is_safe_url

from rest_auth.utils import jwt_encode


# default User or custom User. Now both will work.
User = get_user_model()

try:
    import urllib2 as _urllib
except:
    import urllib.request as _urllib
    import urllib.error
    import urllib.parse

if parse_version(get_version()) >= parse_version('1.7'):
    from django.utils.module_loading import import_string
else:
    from django.utils.module_loading import import_by_path as import_string


def _default_next_url():
    if 'DEFAULT_NEXT_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['DEFAULT_NEXT_URL']
    # Lazily evaluate this in case we don't have admin loaded.
    return get_reverse('admin:index')


def get_current_domain(r):
    if 'ASSERTION_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['ASSERTION_URL']
    return '{scheme}://{host}'.format(
        scheme='https' if r.is_secure() else 'http',
        host=r.get_host(),
    )


def get_reverse(objs):
    '''In order to support different django version, I have to do this '''
    if parse_version(get_version()) >= parse_version('2.0'):
        from django.urls import reverse
    else:
        from django.core.urlresolvers import reverse
    if objs.__class__.__name__ not in ['list', 'tuple']:
        objs = [objs]

    for obj in objs:
        try:
            return reverse(obj)
        except:
            pass
    raise Exception('We got a URL reverse issue: %s. This is a known issue but please still submit a ticket at https://github.com/fangli/django-saml2-auth/issues/new' % str(objs))


def _get_metadata():
    if 'METADATA_LOCAL_FILE_PATH' in settings.SAML2_AUTH:
        return {
            'local': [settings.SAML2_AUTH['METADATA_LOCAL_FILE_PATH']]
        }
    else:
        return {
            'remote': [
                {
                    "url": settings.SAML2_AUTH['METADATA_AUTO_CONF_URL'],
                },
            ]
        }


def _get_saml_client(domain):
    acs_url = domain + get_reverse([acs, 'acs', 'django_saml2_auth:acs'])
    metadata = _get_metadata()

    saml_settings = {
        'metadata': metadata,
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST)
                    ],
                },
                'allow_unsolicited': True,
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }

    if 'ENTITY_ID' in settings.SAML2_AUTH:
        saml_settings['entityid'] = settings.SAML2_AUTH['ENTITY_ID']

    if 'NAME_ID_FORMAT' in settings.SAML2_AUTH:
        saml_settings['service']['sp']['name_id_format'] = settings.SAML2_AUTH['NAME_ID_FORMAT']

    logger.warn("DEBUG SAML_SETTINGS {}".format(saml_settings))
    
    spConfig = Saml2Config()
    spConfig.load(saml_settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client


@login_required
def welcome(r):
    try:
        return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
    except TemplateDoesNotExist:
        return HttpResponseRedirect(_default_next_url())


def denied(r):
    return render(r, 'django_saml2_auth/denied.html')


def _create_new_user(user_name, user_email, user_first_name, user_last_name, user_groups, user_group_names):
    user = User.objects.create_user(user_name, user_email)
    user.first_name = user_first_name
    user.last_name = user_last_name
    AD_SUPERUSER_GROUPS =  getattr(settings, "AD_SUPERUSER_GROUPS", [])
    AD_STAFF_GROUPS =  getattr(settings, "AD_STAFF_GROUPS", [])
    in_super = False
    in_staff = False

    if AD_SUPERUSER_GROUPS in user_group_names:
        user_object.is_superuser =False

    if AD_STAFF_GROUPS in user_group_names:
        user_object.is_staff =False

    if parse_version(get_version()) >= parse_version('2.0'):
        user.groups.set(user_groups)
    else:
        user.groups = user_groups

    user.is_active = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('ACTIVE_STATUS', True)
#    user.is_staff = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('STAFF_STATUS', True)
#    user.is_superuser = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('SUPERUSER_STATUS', False)
    user.save()
    return user


@csrf_exempt
def acs(r):
    saml_client = _get_saml_client(get_current_domain(r))
    resp = r.POST.get('SAMLResponse', None)
    next_url = r.session.get('login_next_url', _default_next_url())

    if not resp:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    authn_response = saml_client.parse_authn_request_response(
        resp, entity.BINDING_HTTP_POST)

    user_email = authn_response.name_id.text
    logger.error("authn_response.name_id.text {}".format(authn_response.name_id.text))
    #logger.error("authn_response.name_id {}".format(authn_response.name_id))
    #   logger.error("authn_response.name_id {}".format(dir(authn_response.name_id)))
    #logger.error("authn_response.name_id {}".format(authn_response.name_id.__dict__))
    #logger.error("authn_response {}".format(authn_response))
    #logger.error("authn_response {}".format(dir(authn_response)))
    #logger.error("authn_response {}".format(authn_response.__dict__))
    if authn_response is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    user_identity = authn_response.get_identity()
    logger.error("USER_IDENTITY {}".format(user_identity))
    if user_identity is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    my_attrs = { x : "unknown" for x in ['user_email','user_first_name', 'user_last_name', 'user_name'] }
    my_attrs['user_email'] = user_email
    try :
        my_attrs['user_first_name'] = user_email.split(".")[0]
        my_attrs['user_last_name'] = user_email.split(".")[1].split("@")[0]
        my_attrs['user_name'] = my_attrs['user_first_name'][0] + my_attrs['user_last_name'].lower()
    except Exception as e:
        logger.error("error {}".format(e))

    user_groups = []
    user_groups_names = []
    if 'Groups' in user_identity:
        for group in user_identity['Groups']:
            group_name = group.lower().replace(' ','_').replace('-','_')
            ogrp = Group.objects.get_or_create(name=group_name)
            user_groups.append(ogrp)
            user_group_names.append(group)
    my_attrs['user_groups'] = user_groups
    my_attrs['user_group_names'] = user_group_names

    logger.warning("attrs {}".format(my_attrs))

    
    lookup = {
        'user_email' : ('email', 'Email'),
        'user_name': ('username', 'UserName'),
        'user_first_name': ('first_name', 'FirstName'),
        'user_last_name' : ('last_name', 'LastName'),
    }

    attrs = settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {})
    
    for x in lookup :
        name = attrs.get(lookup[x])
        if name in user_identity:
            v = user_identity[name]
            if v:
                my_attrs[x] = v[0]
    logger.warning("attrs2 {}".format(my_attrs))
    target_user = None
    is_new_user = False

    try:
        target_user = User.objects.get(username=my_attrs['user_name'])
        if settings.SAML2_AUTH.get('TRIGGER', {}).get('BEFORE_LOGIN', None):
            import_string(settings.SAML2_AUTH['TRIGGER']['BEFORE_LOGIN'])(user_identity)
    except User.DoesNotExist:
        new_user_should_be_created = settings.SAML2_AUTH.get('CREATE_USER', True)
        if new_user_should_be_created:
            target_user = _create_new_user(**my_attrs)
            if settings.SAML2_AUTH.get('TRIGGER', {}).get('CREATE_USER', None):
                import_string(settings.SAML2_AUTH['TRIGGER']['CREATE_USER'])(user_identity)
            is_new_user = True
        else:
            return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    r.session.flush()

    if target_user.is_active:
        target_user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(r, target_user)
    else:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    if settings.SAML2_AUTH.get('USE_JWT') is True:
        # We use JWT auth send token to frontend
        jwt_token = jwt_encode(target_user)
        query = '?uid={}&token={}'.format(target_user.id, jwt_token)

        frontend_url = settings.SAML2_AUTH.get(
            'FRONTEND_URL', next_url)

        return HttpResponseRedirect(frontend_url+query)

    if is_new_user:
        try:
            return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
        except TemplateDoesNotExist:
            return HttpResponseRedirect(next_url)
    else:
        return HttpResponseRedirect(next_url)


def signin(r):
    try:
        import urlparse as _urlparse
        from urllib import unquote
    except:
        import urllib.parse as _urlparse
        from urllib.parse import unquote
    next_url = r.GET.get('next', _default_next_url())

    try:
        if 'next=' in unquote(next_url):
            next_url = _urlparse.parse_qs(_urlparse.urlparse(unquote(next_url)).query)['next'][0]
    except:
        next_url = r.GET.get('next', _default_next_url())

    # Only permit signin requests where the next_url is a safe URL
    if parse_version(get_version()) >= parse_version('2.0'):
        url_ok = is_safe_url(next_url, None)
    else:
        url_ok = is_safe_url(next_url)

    if not url_ok:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    r.session['login_next_url'] = next_url

    saml_client = _get_saml_client(get_current_domain(r))
    _, info = saml_client.prepare_for_authenticate()

    redirect_url = None

    for key, value in info['headers']:
        if key == 'Location':
            redirect_url = value
            break

    return HttpResponseRedirect(redirect_url)


def signout(r):
    logout(r)
    return render(r, 'django_saml2_auth/signout.html')
