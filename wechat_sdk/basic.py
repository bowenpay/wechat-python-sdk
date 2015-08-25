# -*- coding: utf-8 -*-

import hashlib
import requests
import time
import json
import cgi
import urllib
from StringIO import StringIO
from random import Random
import xmltodict

from xml.dom import minidom

from .messages import MESSAGE_TYPES, UnknownMessage
from .exceptions import ParseError, NeedParseError, NeedParamError, OfficialAPIError
from .reply import TextReply, ImageReply, VoiceReply, VideoReply, MusicReply, Article, ArticleReply
from .lib import disable_urllib3_warning, XMLStore


class WechatBasic(object):
    """
    微信基本功能类

    仅包含官方 API 中所包含的内容, 如需高级功能支持请移步 ext.py 中的 WechatExt 类
    """
    def __init__(self, token=None, appid=None, appsecret=None, partnerid=None,
                 partnerkey=None, paysignkey=None, notify_url='',
                 access_token=None, access_token_expires_at=None, get_access_token=None, set_access_token=None,
                 jsapi_ticket=None, jsapi_ticket_expires_at=None, get_jsapi_ticket=None, set_jsapi_ticket=None,
                 checkssl=False):
        """
        :param token: 微信 Token
        :param appid: App ID
        :param appsecret: App Secret
        :param partnerid: 财付通商户身份标识, 支付权限专用
        :param partnerkey: 财付通商户权限密钥 Key, 支付权限专用
        :param paysignkey: 商户签名密钥 Key, 支付权限专用
        :param notify_url: 微信支付成功回调url, 支付权限专用
        :param access_token: 直接导入的 access_token 值, 该值需要在上一次该类实例化之后手动进行缓存并在此处传入, 如果不传入, 将会在需要时自动重新获取
        :param access_token_expires_at: 直接导入的 access_token 的过期日期，该值需要在上一次该类实例化之后手动进行缓存并在此处传入, 如果不传入, 将会在需要时自动重新获取
        :param get_access_token: 获取access_token的方法
        :param set_access_token: 设置access_token的方法
        :param jsapi_ticket: 直接导入的 jsapi_ticket 值, 该值需要在上一次该类实例化之后手动进行缓存并在此处传入, 如果不传入, 将会在需要时自动重新获取
        :param jsapi_ticket_expires_at: 直接导入的 jsapi_ticket 的过期日期，该值需要在上一次该类实例化之后手动进行缓存并在此处传入, 如果不传入, 将会在需要时自动重新获取
        :param get_jsapi_ticket: 获取jsapi_ticket的方法
        :param set_jsapi_ticket: 设置jsapi_ticket的方法
        :param checkssl: 是否检查 SSL, 默认为 False, 可避免 urllib3 的 InsecurePlatformWarning 警告
        """
        if not checkssl:
            disable_urllib3_warning()  # 可解决 InsecurePlatformWarning 警告

        self.__token = token
        self.__appid = appid
        self.__appsecret = appsecret
        self.__partnerid = partnerid
        self.__partnerkey = partnerkey
        self.__paysignkey = paysignkey
        self.__notify_url = notify_url

        def default_get_access_token():
            return self.__access_token, self.__access_token_expires_at

        def default_set_access_token(access_token, access_token_expires_at):
            self.__access_token = access_token
            self.__access_token_expires_at = access_token_expires_at

        self.__access_token = access_token
        self.__access_token_expires_at = access_token_expires_at
        self.__get_access_token = get_access_token or default_get_access_token
        self.__set_access_token = set_access_token or default_set_access_token

        def defaul_get_jsapi_ticket():
            return self.__jsapi_ticket, self.__jsapi_ticket_expires_at

        def default_set_jsapi_ticket(jsapi_ticket, jsapi_ticket_expires_at):
            self.__jsapi_ticket = jsapi_ticket
            self.__jsapi_ticket_expires_at = jsapi_ticket_expires_at

        self.__jsapi_ticket = jsapi_ticket
        self.__jsapi_ticket_expires_at = jsapi_ticket_expires_at
        self.__get_jsapi_ticket = get_jsapi_ticket or defaul_get_jsapi_ticket
        self.__set_jsapi_ticket = set_jsapi_ticket or default_set_jsapi_ticket

        self.__is_parse = False
        self.__message = None

    def check_signature(self, signature, timestamp, nonce):
        """
        验证微信消息真实性
        :param signature: 微信加密签名
        :param timestamp: 时间戳
        :param nonce: 随机数
        :return: 通过验证返回 True, 未通过验证返回 False
        """
        self._check_token()

        if not signature or not timestamp or not nonce:
            return False

        tmp_list = [self.__token, timestamp, nonce]
        tmp_list.sort()
        tmp_str = ''.join(tmp_list)
        if signature == hashlib.sha1(tmp_str.encode('utf-8')).hexdigest():
            return True
        else:
            return False

    def generate_jsapi_signature(self, timestamp, noncestr, url, jsapi_ticket=None):
        """
        使用 jsapi_ticket 对 url 进行签名
        :param timestamp: 时间戳
        :param noncestr: 随机数
        :param url: 要签名的 url，不包含 # 及其后面部分
        :param jsapi_ticket: (可选参数) jsapi_ticket 值 (如不提供将自动通过 appid 和 appsecret 获取)
        :return: 返回sha1签名的hexdigest值
        """
        if not jsapi_ticket:
            jsapi_ticket = self.jsapi_ticket
        data = {
            'jsapi_ticket': jsapi_ticket,
            'noncestr': noncestr,
            'timestamp': timestamp,
            'url': url,
        }
        keys = data.keys()
        keys.sort()
        data_str = '&'.join(['%s=%s' % (key, data[key]) for key in keys])
        signature = hashlib.sha1(data_str.encode('utf-8')).hexdigest()
        return signature

    def parse_data(self, data):
        """
        解析微信服务器发送过来的数据并保存类中
        :param data: HTTP Request 的 Body 数据
        :raises ParseError: 解析微信服务器数据错误, 数据不合法
        """
        result = {}
        if type(data) == unicode:
            data = data.encode('utf-8')
        elif type(data) == str:
            pass
        else:
            raise ParseError()

        try:
            xml = XMLStore(xmlstring=data)
        except Exception:
            raise ParseError()

        result = xml.xml2dict
        result['raw'] = data
        result['type'] = result.pop('MsgType').lower()

        message_type = MESSAGE_TYPES.get(result['type'], UnknownMessage)
        self.__message = message_type(result)
        self.__is_parse = True

    @property
    def message(self):
        return self.get_message()

    def get_message(self):
        """
        获取解析好的 WechatMessage 对象
        :return: 解析好的 WechatMessage 对象
        """
        self._check_parse()

        return self.__message

    def get_access_token(self):
        """
        获取 Access Token 及 Access Token 过期日期, 仅供缓存使用, 如果希望得到原生的 Access Token 请求数据请使用 :func:`grant_token`
        :return: dict 对象, key 包括 `access_token` 及 `access_token_expires_at`
        """
        self._check_appid_appsecret()

        access_token = self.access_token
        access_token, access_token_expires_at = self.__get_access_token()
        return {
            'access_token': access_token,
            'access_token_expires_at': access_token_expires_at,
        }

    def get_jsapi_ticket(self):
        """
        获取 Jsapi Ticket 及 Jsapi Ticket 过期日期, 仅供缓存使用, 如果希望得到原生的 Jsapi Ticket 请求数据请使用 :func:`grant_jsapi_ticket`
        :return: dict 对象, key 包括 `jsapi_ticket` 及 `jsapi_ticket_expires_at`
        """
        self._check_appid_appsecret()

        jsapi_ticket = self.jsapi_ticket
        jsapi_ticket, jsapi_ticket_expires_at = self.__get_jsapi_ticket()
        return {
            'jsapi_ticket': jsapi_ticket,
            'jsapi_ticket_expires_at': jsapi_ticket_expires_at,
        }

    def response_text(self, content, escape=False):
        """
        将文字信息 content 组装为符合微信服务器要求的响应数据
        :param content: 回复文字
        :param escape: 是否转义该文本内容 (默认不转义)
        :return: 符合微信服务器要求的 XML 响应数据
        """
        self._check_parse()
        content = self._transcoding(content)
        if escape:
            content = cgi.escape(content)

        return TextReply(message=self.__message, content=content).render()

    def response_image(self, media_id):
        """
        将 media_id 所代表的图片组装为符合微信服务器要求的响应数据
        :param media_id: 图片的 MediaID
        :return: 符合微信服务器要求的 XML 响应数据
        """
        self._check_parse()

        return ImageReply(message=self.__message, media_id=media_id).render()

    def response_voice(self, media_id):
        """
        将 media_id 所代表的语音组装为符合微信服务器要求的响应数据
        :param media_id: 语音的 MediaID
        :return: 符合微信服务器要求的 XML 响应数据
        """
        self._check_parse()

        return VoiceReply(message=self.__message, media_id=media_id).render()

    def response_video(self, media_id, title=None, description=None):
        """
        将 media_id 所代表的视频组装为符合微信服务器要求的响应数据
        :param media_id: 视频的 MediaID
        :param title: 视频消息的标题
        :param description: 视频消息的描述
        :return: 符合微信服务器要求的 XML 响应数据
        """
        self._check_parse()
        title = self._transcoding(title)
        description = self._transcoding(description)

        return VideoReply(message=self.__message, media_id=media_id, title=title, description=description).render()

    def response_music(self, music_url, title=None, description=None, hq_music_url=None, thumb_media_id=None):
        """
        将音乐信息组装为符合微信服务器要求的响应数据
        :param music_url: 音乐链接
        :param title: 音乐标题
        :param description: 音乐描述
        :param hq_music_url: 高质量音乐链接, WIFI环境优先使用该链接播放音乐
        :param thumb_media_id: 缩略图的 MediaID
        :return: 符合微信服务器要求的 XML 响应数据
        """
        self._check_parse()
        music_url = self._transcoding(music_url)
        title = self._transcoding(title)
        description = self._transcoding(description)
        hq_music_url = self._transcoding(hq_music_url)

        return MusicReply(message=self.__message, title=title, description=description, music_url=music_url,
                          hq_music_url=hq_music_url, thumb_media_id=thumb_media_id).render()

    def response_news(self, articles):
        """
        将新闻信息组装为符合微信服务器要求的响应数据
        :param articles: list 对象, 每个元素为一个 dict 对象, key 包含 `title`, `description`, `picurl`, `url`
        :return: 符合微信服务器要求的 XML 响应数据
        """
        self._check_parse()
        for article in articles:
            if article.get('title'):
                article['title'] = self._transcoding(article['title'])
            if article.get('description'):
                article['description'] = self._transcoding(article['description'])
            if article.get('picurl'):
                article['picurl'] = self._transcoding(article['picurl'])
            if article.get('url'):
                article['url'] = self._transcoding(article['url'])

        news = ArticleReply(message=self.__message)
        for article in articles:
            article = Article(**article)
            news.add_article(article)
        return news.render()

    def grant_token(self, override=True):
        """
        获取 Access Token
        详情请参考 http://mp.weixin.qq.com/wiki/11/0e4b294685f817b95cbed85ba5e82b8f.html
        :param override: 是否在获取的同时覆盖已有 access_token (默认为True)
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        response_json = self._get(
            url="https://api.weixin.qq.com/cgi-bin/token",
            params={
                "grant_type": "client_credential",
                "appid": self.__appid,
                "secret": self.__appsecret,
            }
        )
        if override:
            access_token = response_json['access_token']
            access_token_expires_at = int(time.time()) + response_json['expires_in']
            self.__set_access_token(access_token, access_token_expires_at)
        return response_json

    def grant_jsapi_ticket(self, override=True):
        """
        获取 Jsapi Ticket
        详情请参考 http://mp.weixin.qq.com/wiki/7/aaa137b55fb2e0456bf8dd9148dd613f.html#.E9.99.84.E5.BD.951-JS-SDK.E4.BD.BF.E7.94.A8.E6.9D.83.E9.99.90.E7.AD.BE.E5.90.8D.E7.AE.97.E6.B3.95
        :param override: 是否在获取的同时覆盖已有 jsapi_ticket (默认为True)
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()
        # force to grant new access_token to avoid invalid credential issue
        self.grant_token()

        response_json = self._get(
            url="https://api.weixin.qq.com/cgi-bin/ticket/getticket",
            params={
                "access_token": self.access_token,
                "type": "jsapi",
            }
        )
        if override:
            jsapi_ticket = response_json['ticket']
            jsapi_ticket_expires_at = int(time.time()) + response_json['expires_in']
            self.__set_jsapi_ticket(jsapi_ticket, jsapi_ticket_expires_at)
        return response_json

    def create_menu(self, menu_data):
        """
        创建自定义菜单 ::

            # -*- coding: utf-8 -*-
            wechat = WechatBasic(appid='appid', appsecret='appsecret')
            wechat.create_menu({
                'button':[
                    {
                        'type': 'click',
                        'name': '今日歌曲',
                        'key': 'V1001_TODAY_MUSIC'
                    },
                    {
                        'type': 'click',
                        'name': '歌手简介',
                        'key': 'V1001_TODAY_SINGER'
                    },
                    {
                        'name': '菜单',
                        'sub_button': [
                            {
                                'type': 'view',
                                'name': '搜索',
                                'url': 'http://www.soso.com/'
                            },
                            {
                                'type': 'view',
                                'name': '视频',
                                'url': 'http://v.qq.com/'
                            },
                            {
                                'type': 'click',
                                'name': '赞一下我们',
                                'key': 'V1001_GOOD'
                            }
                        ]
                    }
                ]})

        详情请参考 http://mp.weixin.qq.com/wiki/13/43de8269be54a0a6f64413e4dfa94f39.html
        :param menu_data: Python 字典
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        menu_data = self._transcoding_dict(menu_data)
        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/menu/create',
            data=menu_data
        )

    def get_menu(self):
        """
        查询自定义菜单
        详情请参考 http://mp.weixin.qq.com/wiki/16/ff9b7b85220e1396ffa16794a9d95adc.html
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._get('https://api.weixin.qq.com/cgi-bin/menu/get')

    def delete_menu(self):
        """
        删除自定义菜单
        详情请参考 http://mp.weixin.qq.com/wiki/16/8ed41ba931e4845844ad6d1eeb8060c8.html
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._get('https://api.weixin.qq.com/cgi-bin/menu/delete')

    def upload_media(self, media_type, media_file, extension=''):
        """
        上传多媒体文件
        详情请参考 http://mp.weixin.qq.com/wiki/10/78b15308b053286e2a66b33f0f0f5fb6.html
        :param media_type: 媒体文件类型，分别有图片（image）、语音（voice）、视频（video）和缩略图（thumb）
        :param media_file: 要上传的文件，一个 File object 或 StringIO object
        :param extension: 如果 media_file 传入的为 StringIO object，那么必须传入 extension 显示指明该媒体文件扩展名，如 ``mp3``, ``amr``；如果 media_file 传入的为 File object，那么该参数请留空
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()
        if not isinstance(media_file, file) and not isinstance(media_file, StringIO):
            raise ValueError('Parameter media_file must be file object or StringIO.StringIO object.')
        if isinstance(media_file, StringIO) and extension.lower() not in ['jpg', 'jpeg', 'amr', 'mp3', 'mp4']:
            raise ValueError('Please provide \'extension\' parameters when the type of \'media_file\' is \'StringIO.StringIO\'.')
        if isinstance(media_file, file):
            extension = media_file.name.split('.')[-1]
            if extension.lower() not in ['jpg', 'jpeg', 'amr', 'mp3', 'mp4']:
                raise ValueError('Invalid file type.')

        ext = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'amr': 'audio/amr',
            'mp3': 'audio/mpeg',
            'mp4': 'video/mp4',
        }
        if isinstance(media_file, StringIO):
            filename = 'temp.' + extension
        else:
            filename = media_file.name

        return self._post(
            url='http://file.api.weixin.qq.com/cgi-bin/media/upload',
            params={
                'access_token': self.access_token,
                'type': media_type,
            },
            files={
                'media': (filename, media_file, ext[extension])
            }
        )

    def download_media(self, media_id):
        """
        下载多媒体文件
        详情请参考 http://mp.weixin.qq.com/wiki/10/78b15308b053286e2a66b33f0f0f5fb6.html
        :param media_id: 媒体文件 ID
        :return: requests 的 Response 实例
        """
        self._check_appid_appsecret()

        return requests.get(
            'http://file.api.weixin.qq.com/cgi-bin/media/get',
            params={
                'access_token': self.access_token,
                'media_id': media_id,
            },
            stream=True,
        )

    def create_group(self, name):
        """
        创建分组
        详情请参考 http://mp.weixin.qq.com/wiki/13/be5272dc4930300ba561d927aead2569.html
        :param name: 分组名字（30个字符以内）
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/groups/create',
            data={
                'group': {
                    'name': name,
                },
            }
        )

    def get_groups(self):
        """
        查询所有分组
        详情请参考 http://mp.weixin.qq.com/wiki/13/be5272dc4930300ba561d927aead2569.html
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._get('https://api.weixin.qq.com/cgi-bin/groups/get')

    def get_group_by_id(self, openid):
        """
        查询用户所在分组
        详情请参考 http://mp.weixin.qq.com/wiki/13/be5272dc4930300ba561d927aead2569.html
        :param openid: 用户的OpenID
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/groups/getid',
            data={
                'openid': openid,
            }
        )

    def update_group(self, group_id, name):
        """
        修改分组名
        详情请参考 http://mp.weixin.qq.com/wiki/13/be5272dc4930300ba561d927aead2569.html
        :param group_id: 分组id，由微信分配
        :param name: 分组名字（30个字符以内）
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/groups/update',
            data={
                'group': {
                    'id': int(group_id),
                    'name': name,
                }
            }
        )

    def move_user(self, user_id, group_id):
        """
        移动用户分组
        详情请参考 http://mp.weixin.qq.com/wiki/13/be5272dc4930300ba561d927aead2569.html
        :param user_id: 用户 ID 。 就是你收到的 WechatMessage 的 source
        :param group_id: 分组 ID
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/groups/members/update',
            data={
                'openid': user_id,
                'to_groupid': group_id,
            }
        )

    def get_oauth2_userinfo_one_step(self, code):
        """
        一步网页授权获取用户基本信息
        详情请参考 http://mp.weixin.qq.com/wiki/17/c0f37d5704f0b64713d5d2c37b468d75.html
        :param code: 通过oauth2 authorize获取的code
        :return: JSON 数据包，包含用户的基本信息
        :raises: HTTPError: 微信api http 请求失败
                 OfficialAPIError: 获取信息api出错
        """
        access_token_data = self.get_oauth2_access_token(code)
        if access_token_data.get('errcode', None):
            raise OfficialAPIError('oauth2 获取access_token失败。 %s' % access_token_data)
        user_info = self.get_oauth2_userinfo(access_token_data.get('access_token'), access_token_data.get('openid'))
        if user_info.get('errcode', None):
            raise OfficialAPIError('oauth2 拉取用户信息失败。 %s' % user_info)
        return user_info

    def generate_oauth2_authorize_url(self, redirect_uri, response_type="code", scope="snsapi_userinfo", state=""):
        """
        生成获取用户信息的url
        详情请参考 http://mp.weixin.qq.com/wiki/17/c0f37d5704f0b64713d5d2c37b468d75.html#.E7.AC.AC.E4.B8.80.E6.AD.A5.EF.BC.9A.E7.94.A8.E6.88.B7.E5.90.8C.E6.84.8F.E6.8E.88.E6.9D.83.EF.BC.8C.E8.8E.B7.E5.8F.96code
        :param redirect_uri: 授权后重定向的回调链接地址，该方法内自动使用urlencode对链接进行处理
        :param response_type: 返回类型，默认为code
        :param scope: 应用授权作用域，snsapi_base （不弹出授权页面，直接跳转，只能获取用户openid），
            snsapi_userinfo （弹出授权页面，可通过openid拿到昵称、性别、所在地。
            并且，即使在未关注的情况下，只要用户授权，也能获取其信息）。
            默认为snsapi_userinfo
        :param state: 重定向后会带上state参数，开发者可以填写a-zA-Z0-9的参数值，最多128字节
        :return: 用户授权的url链接字符串
        """
        redirect_uri = urllib.quote(redirect_uri)
        url = "https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=%s&scope=%s&state=%s#wechat_redirect" % (
            self.__appid,
            redirect_uri,
            response_type,
            scope,
            state
        )
        return url

    def get_oauth2_access_token(self, code, grant_type="authorization_code"):
        """
        通过code换取网页授权access_token
        详情请参考 http://mp.weixin.qq.com/wiki/17/c0f37d5704f0b64713d5d2c37b468d75.html#.E7.AC.AC.E4.BA.8C.E6.AD.A5.EF.BC.9A.E9.80.9A.E8.BF.87code.E6.8D.A2.E5.8F.96.E7.BD.91.E9.A1.B5.E6.8E.88.E6.9D.83access_token
        :param code: 通过oauth2 authorize获取的code
        :param grant_type: 授权类型，默认为authorization_code
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._get(
            url='https://api.weixin.qq.com/sns/oauth2/access_token',
            params={
                'appid': self.__appid,
                'secret': self.__appsecret,
                'code': code,
                'grant_type': grant_type
            }
        )

    def refresh_oauth2_access_token(self, code, grant_type="authorization_code"):
        """
        刷新access_token（如果需要）
        详情请参考 http://mp.weixin.qq.com/wiki/17/c0f37d5704f0b64713d5d2c37b468d75.html#.E7.AC.AC.E4.B8.89.E6.AD.A5.EF.BC.9A.E5.88.B7.E6.96.B0access_token.EF.BC.88.E5.A6.82.E6.9E.9C.E9.9C.80.E8.A6.81.EF.BC.89
        :param code: 通过oauth2 authorize获取的code
        :param grant_type: 授权类型，默认为authorization_code
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._get(
            url='https://api.weixin.qq.com/sns/oauth2/access_token',
            params={
                'appid': self.__appid,
                'secret': self.__appsecret,
                'code': code,
                'grant_type': grant_type
            }
        )


    def get_oauth2_userinfo(self, access_token, user_id, lang='zh_CN'):
        """
        拉取用户信息(需scope为 snsapi_userinfo)
        详情请参考 http://mp.weixin.qq.com/wiki/17/c0f37d5704f0b64713d5d2c37b468d75.html#.E7.AC.AC.E5.9B.9B.E6.AD.A5.EF.BC.9A.E6.8B.89.E5.8F.96.E7.94.A8.E6.88.B7.E4.BF.A1.E6.81.AF.28.E9.9C.80scope.E4.B8.BA_snsapi_userinfo.29
        :param access_token: 网页授权接口调用凭证,注意：此access_token与基础支持的access_token不同
        :param user_id: 用户的唯一标识
        :param lang: 返回国家地区语言版本，zh_CN 简体，zh_TW 繁体，en 英语
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        return self._get(
            url='https://api.weixin.qq.com/sns/userinfo',
            params={
                'access_token': access_token,
                'openid': user_id,
                'lang': lang,
            }
        )

    def check_oauth2_access_token(self, access_token, user_id):
        """
        检验授权凭证（oauth2 access_token）是否有效
        详情请参考 http://mp.weixin.qq.com/wiki/17/c0f37d5704f0b64713d5d2c37b468d75.html#.E9.99.84.EF.BC.9A.E6.A3.80.E9.AA.8C.E6.8E.88.E6.9D.83.E5.87.AD.E8.AF.81.EF.BC.88access_token.EF.BC.89.E6.98.AF.E5.90.A6.E6.9C.89.E6.95.88
        :param access_token: 网页授权接口调用凭证,注意：此access_token与基础支持的access_token不同
        :param user_id: 用户的唯一标识
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        return self._get(
            url='https://api.weixin.qq.com/sns/auth',
            params={
                'access_token': access_token,
                'openid': user_id
            }
        )

    def get_user_info(self, user_id, lang='zh_CN'):
        """
        获取用户基本信息
        详情请参考 http://mp.weixin.qq.com/wiki/14/bb5031008f1494a59c6f71fa0f319c66.html
        :param user_id: 用户 ID, 就是你收到的 WechatMessage 的 source
        :param lang: 返回国家地区语言版本，zh_CN 简体，zh_TW 繁体，en 英语
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._get(
            url='https://api.weixin.qq.com/cgi-bin/user/info',
            params={
                'access_token': self.access_token,
                'openid': user_id,
                'lang': lang,
            }
        )

    def get_followers(self, first_user_id=None):
        """
        获取关注者列表
        详情请参考 http://mp.weixin.qq.com/wiki/3/17e6919a39c1c53555185907acf70093.html
        :param first_user_id: 可选。第一个拉取的OPENID，不填默认从头开始拉取
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        params = {
            'access_token': self.access_token,
        }
        if first_user_id:
            params['next_openid'] = first_user_id
        return self._get('https://api.weixin.qq.com/cgi-bin/user/get', params=params)

    def send_text_message(self, user_id, content):
        """
        发送文本消息
        详情请参考 http://mp.weixin.qq.com/wiki/7/12a5a320ae96fecdf0e15cb06123de9f.html
        :param user_id: 用户 ID, 就是你收到的 WechatMessage 的 source
        :param content: 消息正文
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/message/custom/send',
            data={
                'touser': user_id,
                'msgtype': 'text',
                'text': {
                    'content': content,
                },
            }
        )

    def send_image_message(self, user_id, media_id):
        """
        发送图片消息
        详情请参考 http://mp.weixin.qq.com/wiki/7/12a5a320ae96fecdf0e15cb06123de9f.html
        :param user_id: 用户 ID, 就是你收到的 WechatMessage 的 source
        :param media_id: 图片的媒体ID。 可以通过 :func:`upload_media` 上传。
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/message/custom/send',
            data={
                'touser': user_id,
                'msgtype': 'image',
                'image': {
                    'media_id': media_id,
                },
            }
        )

    def send_voice_message(self, user_id, media_id):
        """
        发送语音消息
        详情请参考 http://mp.weixin.qq.com/wiki/7/12a5a320ae96fecdf0e15cb06123de9f.html
        :param user_id: 用户 ID, 就是你收到的 WechatMessage 的 source
        :param media_id: 发送的语音的媒体ID。 可以通过 :func:`upload_media` 上传。
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/message/custom/send',
            data={
                'touser': user_id,
                'msgtype': 'voice',
                'voice': {
                    'media_id': media_id,
                },
            }
        )

    def send_video_message(self, user_id, media_id, title=None, description=None):
        """
        发送视频消息
        详情请参考 http://mp.weixin.qq.com/wiki/7/12a5a320ae96fecdf0e15cb06123de9f.html
        :param user_id: 用户 ID, 就是你收到的 WechatMessage 的 source
        :param media_id: 发送的视频的媒体ID。 可以通过 :func:`upload_media` 上传。
        :param title: 视频消息的标题
        :param description: 视频消息的描述
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        video_data = {
            'media_id': media_id,
        }
        if title:
            video_data['title'] = title
        if description:
            video_data['description'] = description

        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/message/custom/send',
            data={
                'touser': user_id,
                'msgtype': 'video',
                'video': video_data,
            }
        )

    def send_music_message(self, user_id, url, hq_url, thumb_media_id, title=None, description=None):
        """
        发送音乐消息
        详情请参考 http://mp.weixin.qq.com/wiki/7/12a5a320ae96fecdf0e15cb06123de9f.html
        :param user_id: 用户 ID, 就是你收到的 WechatMessage 的 source
        :param url: 音乐链接
        :param hq_url: 高品质音乐链接，wifi环境优先使用该链接播放音乐
        :param thumb_media_id: 缩略图的媒体ID。 可以通过 :func:`upload_media` 上传。
        :param title: 音乐标题
        :param description: 音乐描述
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        music_data = {
            'musicurl': url,
            'hqmusicurl': hq_url,
            'thumb_media_id': thumb_media_id,
        }
        if title:
            music_data['title'] = title
        if description:
            music_data['description'] = description

        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/message/custom/send',
            data={
                'touser': user_id,
                'msgtype': 'music',
                'music': music_data,
            }
        )

    def send_article_message(self, user_id, articles):
        """
        发送图文消息
        详情请参考 http://mp.weixin.qq.com/wiki/7/12a5a320ae96fecdf0e15cb06123de9f.html
        :param user_id: 用户 ID, 就是你收到的 WechatMessage 的 source
        :param articles: list 对象, 每个元素为一个 dict 对象, key 包含 `title`, `description`, `picurl`, `url`
        :return: 返回的 JSON 数据包
        """
        self._check_appid_appsecret()

        articles_data = []
        for article in articles:
            article = Article(**article)
            articles_data.append({
                'title': article.title,
                'description': article.description,
                'url': article.url,
                'picurl': article.picurl,
            })
        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/message/custom/send',
            data={
                'touser': user_id,
                'msgtype': 'news',
                'news': {
                    'articles': articles_data,
                },
            }
        )

    def create_qrcode(self, data):
        """
        创建二维码
        详情请参考 http://mp.weixin.qq.com/wiki/18/28fc21e7ed87bec960651f0ce873ef8a.html
        :param data: 你要发送的参数 dict
        :return: 返回的 JSON 数据包
        :raise HTTPError: 微信api http 请求失败
        """
        self._check_appid_appsecret()

        data = self._transcoding_dict(data)
        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/qrcode/create',
            data=data
        )

    def show_qrcode(self, ticket):
        """
        通过ticket换取二维码
        详情请参考 http://mp.weixin.qq.com/wiki/18/28fc21e7ed87bec960651f0ce873ef8a.html
        :param ticket: 二维码 ticket 。可以通过 :func:`create_qrcode` 获取到
        :return: 返回的 Request 对象
        """
        self._check_appid_appsecret()

        return requests.get(
            url='https://mp.weixin.qq.com/cgi-bin/showqrcode',
            params={
                'ticket': ticket
            }
        )

    def set_template_industry(self, industry_id1, industry_id2):
        """
        设置所属行业
        详情请参考 http://mp.weixin.qq.com/wiki/17/304c1885ea66dbedf7dc170d84999a9d.html
        :param industry_id1: 主营行业代码
        :param industry_id2: 副营行业代码
        :return: 返回的 JSON 数据包
        """
        self._check_appid_appsecret()

        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/template/api_set_industry',
            data={
                'industry_id1': str(industry_id1),
                'industry_id2': str(industry_id2),
            }
        )

    def get_template_id(self, template_id_short):
        """
        获得模板ID
        详情请参考 http://mp.weixin.qq.com/wiki/17/304c1885ea66dbedf7dc170d84999a9d.html
        :param template_id_short: 模板库中模板的编号，有“TM**”和“OPENTMTM**”等形式
        :return: 返回的 JSON 数据包
        """
        self._check_appid_appsecret()

        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/template/api_add_template',
            data={
                'template_id_short': str(template_id_short),
            }
        )

    def send_template_message(self, user_id, template_id, data, url='', topcolor='#FF0000'):
        """
        发送模版消息
        详情请参考 http://mp.weixin.qq.com/wiki/17/304c1885ea66dbedf7dc170d84999a9d.html
        :param user_id: 用户 ID, 就是你收到的 WechatMessage 的 source (OpenID)
        :param template_id: 模板ID
        :param data: 模板消息数据 (dict形式)，示例如下：
        {
            "first": {
               "value": "恭喜你购买成功！",
               "color": "#173177"
            },
            "keynote1":{
               "value": "巧克力",
               "color": "#173177"
            },
            "keynote2": {
               "value": "39.8元",
               "color": "#173177"
            },
            "keynote3": {
               "value": "2014年9月16日",
               "color": "#173177"
            },
            "remark":{
               "value": "欢迎再次购买！",
               "color": "#173177"
            }
        }
        :param url: 跳转地址 (默认为空)
        :param topcolor: 顶部颜色RGB值 (默认 '#FF0000' )
        :return: 返回的 JSON 数据包
        """
        self._check_appid_appsecret()

        unicode_data = {}
        if data:
            unicode_data = self._transcoding_dict(data)

        return self._post(
            url='https://api.weixin.qq.com/cgi-bin/message/template/send',
            data={
                'touser': user_id,
                "template_id": template_id,
                "url": url,
                "topcolor": topcolor,
                "data": unicode_data
            }
        )

    def get_js_config(self, param):
        ticket = self.jsapi_ticket
        nonceStr = self.generate_random_string()
        timestamp = self.get_timestamp()
        signature = self.generate_jsapi_signature(timestamp, nonceStr, param["url"], ticket);
        result = {
            "debug": param.get("debug", False),
            "appId": self.__appid,
            "timestamp": timestamp,
            "nonceStr": nonceStr,
            "signature": signature,
            "jsApiList": param["jsApiList"]
        }
        return result

    ## 微信支付 start
    def build_sign(self, params):
        # 对所有传入参数按照字段名的 ASCII 码从小到大排序（字典序）
        keys = params.keys()
        keys.sort()

        array = []
        for key in keys:
            # 值为空的参数不参与签名
            if params[key] == None or params[key] == '':
                continue
            # sign不参与签名
            if key == 'sign':
                continue
            array.append("%s=%s" % (key, params[key]))
        # 使用 URL 键值对的格式拼接成字符串string1
        string1 = "&".join(array)

        # 在 string1 最后拼接上 key=Key(商户支付密钥)得到 stringSignTemp 字符串
        stringSignTemp = string1 + '&key=' + self.__partnerkey

        # 对 stringSignTemp 进行 md5 运算，再将得到的字符串所有字符转换为大写
        m = hashlib.md5(stringSignTemp.encode('utf-8'))
        return m.hexdigest().upper()

    def build_unifiedorder(self, params):
        base_params = {
            'appid': self.__appid,
            'mch_id': self.__partnerid,
            'nonce_str': self.generate_random_string(),
            'trade_type': 'JSAPI',
            'body': params['body'],
            'out_trade_no': params['out_trade_no'],
            'total_fee': params['total_fee'],
            'spbill_create_ip': params['spbill_create_ip'],
            'notify_url': self.__notify_url,
            'openid': params['openid']
        }

        base_params['sign'] = self.build_sign(base_params)
        return self.dict_to_xml(base_params)

    def get_timestamp(self):
        return str(int(time.time()))

    def generate_random_string(self, randomlength=32):
        str = ''
        chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
        length = len(chars) - 1
        random = Random()
        for i in range(randomlength):
            str += chars[random.randint(0, length)]
        return str

    def dict_to_xml(self, params):
        xml_elements = ["<xml>",]
        for (k, v) in params.items():
            v2 = v.encode("utf-8") if isinstance(v, unicode) else v
            if str(v2).isdigit():
                xml_elements.append('<%s>%s</%s>' % (k, v, k))
            else:
                xml_elements.append('<%s><![CDATA[%s]]></%s>' % (k, v, k))
        xml_elements.append('</xml>')
        return ''.join(xml_elements)

    def build_form_by_prepay_id(self, prepay_id):
        base_params = {
            'appId': self.__appid,
            'timeStamp': self.get_timestamp(),
            'nonceStr': self.generate_random_string(),
            'package': "prepay_id=%s" % prepay_id,
            'signType': "MD5"
        }
        base_params['paySign'] = self.build_sign(base_params)
        return base_params

    def build_form_by_params(self, params):
        headers = {'Content-Type': 'application/xml'}
        xml = self.build_unifiedorder(params).encode('utf-8')
        response = requests.post('https://api.mch.weixin.qq.com/pay/unifiedorder', data=xml, headers=headers)
        response.encoding = 'utf-8'
        response_dict = xmltodict.parse(response.text)['xml']
        if response_dict['return_code'] == 'SUCCESS':
            return self.build_form_by_prepay_id(response_dict['prepay_id'])

    def notify_string_to_params(self, string):
        params = {}
        key_value_array = string.split('&')
        for item in key_value_array:
            key, value = item.split('=')
            params[key] = value
        return params

    def verify_notify_string(self, string):
        params = self.notify_xml_string_to_dict(string)

        notify_sign = params['sign']
        del params['sign']

        if self.build_sign(params) == notify_sign:
            return True
        return False

    def notify_xml_string_to_dict(self, string):
        xml_data = xmltodict.parse(string)['xml']
        params = {}
        for k in xml_data:
            params[k] = xml_data[k]
        return params

    ## 微信支付 end

    @property
    def access_token(self):
        self._check_appid_appsecret()

        access_token, access_token_expires_at = self.__get_access_token()
        if access_token:
            now = time.time()
            if access_token_expires_at - now > 60:
                return access_token
        self.grant_token()
        access_token, access_token_expires_at = self.__get_access_token()
        return access_token

    @property
    def jsapi_ticket(self):
        self._check_appid_appsecret()

        jsapi_ticket, jsapi_ticket_expires_at = self.__get_jsapi_ticket()
        if jsapi_ticket:
            now = time.time()
            if jsapi_ticket_expires_at - now > 60:
                return jsapi_ticket
        self.grant_jsapi_ticket()
        jsapi_ticket, jsapi_ticket_expires_at = self.__get_jsapi_ticket()
        return jsapi_ticket

    def _check_token(self):
        """
        检查 Token 是否存在
        :raises NeedParamError: Token 参数没有在初始化的时候提供
        """
        if not self.__token:
            raise NeedParamError('Please provide Token parameter in the construction of class.')

    def _check_appid_appsecret(self):
        """
        检查 AppID 和 AppSecret 是否存在
        :raises NeedParamError: AppID 或 AppSecret 参数没有在初始化的时候完整提供
        """
        if not self.__appid or not self.__appsecret:
            raise NeedParamError('Please provide app_id and app_secret parameters in the construction of class.')

    def _check_parse(self):
        """
        检查是否成功解析微信服务器传来的数据
        :raises NeedParseError: 需要解析微信服务器传来的数据
        """
        if not self.__is_parse:
            raise NeedParseError()

    def _check_official_error(self, json_data):
        """
        检测微信公众平台返回值中是否包含错误的返回码
        :raises OfficialAPIError: 如果返回码提示有错误，抛出异常；否则返回 True
        """
        if "errcode" in json_data and json_data["errcode"] != 0:
            raise OfficialAPIError("{}: {}".format(json_data["errcode"], json_data["errmsg"]))

    def _request(self, method, url, **kwargs):
        """
        向微信服务器发送请求
        :param method: 请求方法
        :param url: 请求地址
        :param kwargs: 附加数据
        :return: 微信服务器响应的 json 数据
        :raise HTTPError: 微信api http 请求失败
        """
        if "params" not in kwargs:
            kwargs["params"] = {
                "access_token": self.access_token,
            }
        if isinstance(kwargs.get("data", ""), dict):
            body = json.dumps(kwargs["data"], ensure_ascii=False)
            body = body.encode('utf8')
            kwargs["data"] = body

        r = requests.request(
            method=method,
            url=url,
            **kwargs
        )
        r.raise_for_status()
        r.encoding = "utf-8"
        response_json = r.json()

        self._check_official_error(response_json)
        return response_json

    def _get(self, url, **kwargs):
        """
        使用 GET 方法向微信服务器发出请求
        :param url: 请求地址
        :param kwargs: 附加数据
        :return: 微信服务器响应的 json 数据
        :raise HTTPError: 微信api http 请求失败
        """
        return self._request(
            method="get",
            url=url,
            **kwargs
        )

    def _post(self, url, **kwargs):
        """
        使用 POST 方法向微信服务器发出请求
        :param url: 请求地址
        :param kwargs: 附加数据
        :return: 微信服务器响应的 json 数据
        :raise HTTPError: 微信api http 请求失败
        """
        return self._request(
            method="post",
            url=url,
            **kwargs
        )

    def _transcoding(self, data):
        """
        编码转换
        :param data: 需要转换的数据
        :return: 转换好的数据
        """
        if not data:
            return data

        result = None
        if isinstance(data, str):
            result = data.decode('utf-8')
        else:
            result = data
        return result

    def _transcoding_list(self, data):
        """
        编码转换 for list
        :param data: 需要转换的 list 数据
        :return: 转换好的 list
        """
        if not isinstance(data, list):
            raise ValueError('Parameter data must be list object.')

        result = []
        for item in data:
            if isinstance(item, dict):
                result.append(self._transcoding_dict(item))
            elif isinstance(item, list):
                result.append(self._transcoding_list(item))
            else:
                result.append(item)
        return result

    def _transcoding_dict(self, data):
        """
        编码转换 for dict
        :param data: 需要转换的 dict 数据
        :return: 转换好的 dict
        """
        if not isinstance(data, dict):
            raise ValueError('Parameter data must be dict object.')

        result = {}
        for k, v in data.items():
            k = self._transcoding(k)
            if isinstance(v, dict):
                v = self._transcoding_dict(v)
            elif isinstance(v, list):
                v = self._transcoding_list(v)
            else:
                v = self._transcoding(v)
            result.update({k: v})
        return result
