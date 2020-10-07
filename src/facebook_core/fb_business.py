import requests
import json
from facebook_business.adobjects.productcatalog import ProductCatalog
from facebook_business.api import FacebookAdsApi
from rauth import OAuth2Service

from src.django_projects.merchant_facebook.apps.facebook_login.models import User
from src.facebook_core.utils import Utils


class FBBusiness(object):
    def __init__(self, logger=None, user_access_token=None):
        self.log_obj = logger if logger else Utils.get_logger(self.__class__.__name__)
        self.__config = Utils.load_config(file_path='src/config/login_app_config.yaml')['config']
        self.graph_api_version = self.__config['graph_api_version']
        self.__app_id = self.__config['app_id']
        self.__app_secret = self.__config['app_secret']
        self.__app_access_token = self.__config['app_access_token']
        (self.__user_access_token) = (user_access_token
                                      if user_access_token else self.__config['user_access_token'])
        self.graph_uri_base = 'https://graph.facebook.com'
        self.redirect_uri = ''

    def get_product_catalog(self, access_token, catalog_id):
        """Get product catalog object

        Args:
            access_token (str): any kind of access token whicc has permissions
            catalog_id (str): catalog id

        Returns:
            obj: ProductCatalog object
        """
        FacebookAdsApi.init(app_id=self.__app_id,
                            app_secret=self.__app_secret,
                            access_token=access_token)

        return ProductCatalog(fbid=catalog_id)

    def product_catalog_add_new_product(self, data, access_token, catalog_id):
        """Add new product to product catalog

        Args:
            data (dict): product data
            access_token (str): any access token that has permission
            catalog_id (str): catalog id

        Returns:
            str: log
        """
        self.log_obj.info('Start product_catalog_add_new_product...')
        product_catalog = self.get_product_catalog(access_token=access_token,
                                                   catalog_id=catalog_id)

        return product_catalog.create_product(fields=[],
                                              params=data)

    def product_catalog_get_all_products(self, catalog_id, access_token):
        """
        Get all products from catalog
        :param catalog_id: catalog id
        :param access_token: access token
        :return: list dict of products
        """
        self.log_obj.info(f'Start {self.product_catalog_get_all_products.__name__}....')
        product_catalog = self.get_product_catalog(access_token=access_token,
                                                   catalog_id=catalog_id)
        return product_catalog.get_products()

    def get_pages(self, user_id, access_token=None):
        """
        Get all pages that user has permissions
        :param user_id:
        :param access_token:
        :return: list of pages
        """
        self.log_obj.info(f'Start {self.get_pages.__name__}...')
        url = f'https://graph.facebook.com/{self.graph_api_version}/{user_id}/accounts'
        params = {'access_token': self.__user_access_token if access_token is None else access_token}

        resp = requests.request(method='GET',
                                url=url,
                                params=params)
        self.log_obj.info('%s : %s', self.get_pages.__name__, resp.url)
        resp = resp.json()
        if 'data' in resp.keys():
            pages = resp['data']
            self.log_obj.info('Pages: %s', pages)

            return pages

        self.log_obj.info('ERROR: %s', resp['error'])
        return

    def get_page_access_token(self, page_id, user_access_token=None):
        """
        Get page access token
        If you used a short-lived User access token, the Page access token is valid for only 1 hour.
        If you used a long-lived User access token, the Page access token has no expiration date.
        :param page_id: page id
        :param user_access_token: user access token
        :return: page access token
        """
        self.log_obj.info('Start get_page_access_token...')
        url = f'https://graph.facebook.com/{page_id}'
        params = {'fields': 'name, access_token',
                  'access_token': user_access_token}

        resp = requests.request(method='GET',
                                url=url,
                                params=params)
        self.log_obj.info(f'Url: {resp.url}')
        resp = resp.json()

        if 'access_token' in resp.keys():
            page_access_token = resp['access_token']
            self.log_obj.info(f'Page access token: {page_access_token}')
            return page_access_token

        self.log_obj.info('There is no access token')
        return

    def get_catalog_ids(self, page_id, access_token=None):
        """
        Get product catalog ids from page id
        :param page_id: page id
        :param access_token: access token
        :return: dict {catalog_name: catalog_id}
        """
        self.log_obj.info(f'Start {self.get_catalog_ids.__name__}...')
        url = f'https://graph.facebook.com/{self.graph_api_version}/{str(page_id)}/product_catalogs'

        params = {'access_token': access_token if access_token else self.__user_access_token}
        resp = requests.request(method='GET',
                                url=url,
                                params=params).json()

        if 'data' in resp.keys() and len(resp['data']) != 0:
            return [{r['name']: r['id']} for r in resp['data']]
        self.log_obj.info('There is no catalog ids')
        return

    def extend_user_access_token(self, user_access_token):
        """
        Extend short live user access token
        :param user_access_token: short live user access token
        :return: extended, long live token
        """
        self.log_obj.info('Start extend_user_access_token...')
        url = f'https://graph.facebook.com/{self.graph_api_version}/oauth/access_token'
        params = {'grant_type': 'fb_exchange_token',
                  'client_id': self.__app_id,
                  'client_secret': self.__app_secret,
                  'fb_exchange_token': user_access_token}

        resp = requests.request(method='GET',
                                url=url,
                                params=params)
        self.log_obj.info(f'Url: {resp.url}')
        resp = resp.json()

        if 'access_token' in resp.keys():
            extended_token = resp['access_token']
            self.log_obj.info(f'Extended token: {extended_token}')
            return extended_token

        self.log_obj.info('Cannot extend token!')
        return

    def extend_page_access_token(self, page_access_token, user_id):
        """
        Extend page access token
        :param page_access_token: page access token
        :param user_id: user id of app
        :return: page access token
        """
        self.log_obj.info('Start extend_page_access_token...')
        url = f'https://graph.facebook.com/{self.graph_api_version}/{user_id}/accounts'
        params = {'access_token': page_access_token}
        resp = requests.request(method='GET',
                                url=url,
                                params=params)

        self.log_obj.info(f'Url: {resp.url}')
        resp = resp.json()

        if 'access_token' in resp.keys():
            extended_token = resp['access_token']
            self.log_obj.info(f'Extended token: {extended_token}')
            return extended_token

        self.log_obj.info('Cannot extend token!')
        return

    def check_valid_access_token(self, input_access_token):
        """
        Valid token = expired time > 600, is_valid = True
        :param input_access_token: input token
        :return: False if invalid else True and user id
        """
        self.log_obj.info('Start check_valid_access_token...')
        url = 'https://graph.facebook.com/debug_token'
        params = {'input_token': input_access_token,
                  'access_token': self.__app_access_token}

        resp = requests.request(method='GET',
                                url=url,
                                params=params)
        self.log_obj.info(f'Url: {resp.url}')
        resp = resp.json()
        self.log_obj.info(resp)
        try:
            expired_time = resp['data']['expires_at'] if 'data' in resp.keys() else None
            if expired_time and expired_time > 6000 and resp['data']['is_valid'] is True:
                self.log_obj.info('This token has a lot of time')
                return True, resp['data']['user_id']

            if resp['data']['expires_at'] == 0:
                self.log_obj.info('This token is never expired')
                return True, resp['data']['user_id']

        except Exception as e:
            print('Refreshing token error: %s' % resp['error'])
            raise e

        return False, resp['data']['user_id']

    def get_refreshing_code(self, redirect_url, long_lived_user_access_token):
        """
        Get refreshing code for refreshing access token
        :param long_lived_user_access_token:
        :param redirect_url: redirect url
        :return: refreshing code
        """
        self.log_obj.info('Start get_refreshing_code...')
        url = f'https://graph.facebook.com/{self.graph_api_version}/oauth/client_code'
        params = {'client_id': self.__app_id,
                  'client_secret': self.__app_secret,
                  'redirect_uri': redirect_url,
                  'access_token': long_lived_user_access_token}

        resp = requests.request(method='GET',
                                url=url,
                                params=params)
        self.log_obj.info(f'URL: {resp.url}')
        resp = resp.json()
        self.log_obj.info(resp)

        if 'code' in resp.keys():
            refreshing_code = resp['code']
            self.log_obj.info(f'Refreshing code: {refreshing_code}')
            return refreshing_code

        self.log_obj.info(f'ERROR: {resp["error"]}')
        return

    def refresh_access_token(self, long_lived_user_access_token, redirect_url):
        self.log_obj.info('Start refresh_access_token....')
        is_valid, user_id = self.check_valid_access_token(input_access_token=long_lived_user_access_token)
        if is_valid:
            self.log_obj.info('This token is valid')
            return
        refreshing_code = self.get_refreshing_code(redirect_url=redirect_url,
                                                   long_lived_user_access_token=long_lived_user_access_token)

        if refreshing_code and refreshing_code != '':
            url = f'https://graph.facebook.com/{self.graph_api_version}/oauth/access_token'
            params = {'code': refreshing_code,
                      'client_id': self.__app_id,
                      'redirect_uri': redirect_url,
                      'machine_id': user_id}
            resp = requests.request(method='GET',
                                    url=url,
                                    params=params)
            self.log_obj.info(f'URL: {resp.url}')
            resp = resp.json()

            if 'access_token' in resp.keys():
                access_token = resp['access_token']
                self.log_obj.info(f'Access token: {access_token}')
                return access_token

            self.log_obj.info('Cannot refresh access token')
            self.log_obj.info(resp)
            return

    def facebook_login(self):
        """
        login facebook
        :return: redirect login url
        """
        facebook = OAuth2Service(client_id=self.__app_id,
                                 client_secret=self.__app_secret,
                                 name=self.__class__.__name__,
                                 authorize_url='https://www.facebook.com/dialog/oauth',
                                 access_token_url='https://graph.facebook.com/oauth/access_token',
                                 base_url=self.graph_uri_base)

        # redirect URL https://www.facebook.com/connect/login_success.html
        redirect_uri = f'https://{"ff7e3ac981ca"}.ngrok.io/merchant/facebook/token'
        params = {'redirect_uri': 'https://ff7e3ac981ca.ngrok.io/merchant/facebook/token',
                  'scope': 'catalog_management, ads_management, pages_manage_posts, instagram_basic',
                  'auth_type': 'reauthorize'}
        authorize_url = facebook.get_authorize_url(**params)

        return authorize_url

    def authorized(self, code, redirect_uri):
        """
        facebook login authorize
        :param code: response code authorize
        :param redirect_uri: redirect url
        :return: user data
        """
        facebook = OAuth2Service(client_id=self.__app_id,
                                 client_secret=self.__app_secret,
                                 name=self.__class__.__name__,
                                 authorize_url='https://www.facebook.com/dialog/oauth',
                                 access_token_url='https://graph.facebook.com/oauth/access_token',
                                 base_url=self.graph_uri_base)
        data = dict(code=code,
                    redirect_uri=redirect_uri)
        fb_session = facebook.get_auth_session(data=data,
                                               decoder=self._oauth_decoder)
        extended_user_access_token = self.extend_user_access_token(fb_session.access_token)
        print(f'Facebook access token: {fb_session.access_token}')
        # self.check_valid_access_token(input_access_token=extended_user_access_token)
        user_data = fb_session.get('me').json()
        data = {'username': user_data['name'],
                'user_id': user_data['id'],
                'user_access_token': extended_user_access_token}
        user = User(**data)
        user.save()

        return data

    @staticmethod
    def _oauth_decoder(data):
        new_data = data.decode("utf-8", "strict")

        return json.loads(new_data)

    @property
    def user_access_token(self):
        return self.__user_access_token

    @user_access_token.setter
    def user_access_token(self, value):
        self.__user_access_token = value
