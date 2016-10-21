class HTMLEncoding(object):
    def __init__(self):
        pass
    def XSSEncode(self, maliciouscode):
        htmlCodes = (
            ('"', '&quot;'),('%22', '&quot;'),
            ("'", '&#x27;'),('%27', '&#x27;'), 
            ('/', '&#x2F;'),('%2f', '&#x2F;'),('%2F', '&#x2F;'),
            ('<', '&lt;'),('%3C', '&lt;'),('%3c', '&lt;'),
            ('>', '&gt;'),('%3E', '&gt;'),('%3e', '&gt;'),
            (';', '&end;'),('%3B', '&end;'),('%3b', '&end;'),
            ('=', '&eql;'),('%3D', '&eql;'),('%3d', '&eql;'),
            ('&', '&amp;'),('%26', '&amp;'),
            ('(', '&sbkt;'),('%28', '&sbkt;'),
            (')', '&ebkt;'),('%29', '&ebkt;'),  
            ('document.', 'dom'),
        )
        for code in htmlCodes:
            maliciouscode = maliciouscode.replace(code[0], code[1])

        return maliciouscode


    def UrlEncode(self, url):
        htmlCodes = (
            (':', '-'),
            ('//', '--'),
            ('/', '-'),
            ('.', '-'),
        )
        for code in htmlCodes:
            url = url.replace(code[0], code[1])

        return url
        
