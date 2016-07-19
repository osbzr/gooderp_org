# -*- coding: utf-8 -*-
{
    'name': "auth_oauth_extended",

    'summary': """
        for qq/weixin/weibo authorization and login into Odoo """,

    'description': """
Allow users to login through OAuth2 Provider those in china.
=============================================================
QQ
Weixin
Weibo
etc.

    """,

    'author': 'Odoo CN, Jeffery <jeffery9@gmail.com>',
    'category': 'Tools',
    'version': '0.1',

    'depends': ['auth_oauth'],

    'data': [
        'security/ir.model.access.csv',
        'auth_oauth_view.xml',
        'auth_oauth_data.xml',
    ],

    'installable': True,

}