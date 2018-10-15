def decoder(url):
    import urllib
    try:
        decoded_url = urllib.unquote(url)
        decoded_url = urllib.unquote(decoded_url)
    except AttributeError:
        import urllib.parse 
        decoded_url = urllib.parse.unquote(url)
        decoded_url = urllib.parse.unquote(decoded_url)
    return decoded_url  
    
