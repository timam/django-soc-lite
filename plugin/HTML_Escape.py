def XSSEncode(maliciouscode):
    htmlCodes = (
        ('"', '&quot;'),('%22', '&quot;'),
        ("'", '&#x27;'),('%27', '&#x27;'), 
        ('/', '&#x2F;'),('%2f', '&#x2F;'),('%2F', '&#x2F;'),
        ('<', '&lt;'),('%3C', '&lt;'),('%3c', '&lt;'),
        ('>', '&gt;'),('%3E', '&gt;'),('%3e', '&gt;'),
        (';', '&end;'),('%3B', '&end;'),('%3b', '&end;'),
        ('&', '&amp;'),('%26', '&amp;'),
    )
    for code in htmlCodes:
        maliciouscode = maliciouscode.replace(code[0], code[1])
    import re
    maliciouscode = re.sub(' +',' ',maliciouscode)

    return maliciouscode

def CommandEscape(maliciouscode):
    htmlCodes = (
        ('"', '&quot;'),('%22', '&quot;'),
        ("'", '&#x27;'),('%27', '&#x27;'), 
        ('/', '&#x2F;'),('%2f', '&#x2F;'),('%2F', '&#x2F;'),
        ('<', '&lt;'),('%3C', '&lt;'),('%3c', '&lt;'),
        ('>', '&gt;'),('%3E', '&gt;'),('%3e', '&gt;'),
        (';', '&end;'),('%3B', '&end;'),('%3b', '&end;'),
        ('&', '&amp;'),('%26', '&amp;'),
    )
    for code in htmlCodes:
        maliciouscode = maliciouscode.replace(code[0], code[1])
    import re
    maliciouscode = re.sub(' +',' ',maliciouscode)
    return maliciouscode

def UrlEncode(url):
    htmlCodes = (
        (':', '-'),
        ('//', '--'),
        ('/', '-'),
        ('.', '-'),
    )
    for code in htmlCodes:
        url = url.replace(code[0], code[1])

    return url
        
