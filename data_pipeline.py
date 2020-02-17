import requests
from bs4 import BeautifulSoup
import io
import gzip
import random
import os.path
import os
import json
import threading

BASE_URL = None
DOWNLOAD_PROBABILITY = None
SIZE_LIMIT = None
DOWNLOAD_AMOUNT = None
with open('config.json', 'r') as config_file:
    config = json.load(config_file)
    BASE_URL = config['base_url']
    DOWNLOAD_PROBABILITY = config['download_probability']
    SIZE_LIMIT = config['size_limit']
    DOWNLOAD_AMOUNT = config['download_amount']

FLOAT_SET = frozenset([str(i) for i in range(10)] + ['.'])

def get_all_sitemap_links(url):
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'xml')
    return (x.find('loc').text for x in soup.find_all('sitemap'))
def download_gzip_link(url):
    r = requests.get(url)
    with gzip.GzipFile(fileobj=io.BytesIO(r.content)) as f:
        result = f.read()
        soup = BeautifulSoup(result, 'xml')
        return (x.get('href') for x in soup.find_all("xhtml:link", {
            "hreflang": "en"
        })[5:] if x.get('media') is None and len(x.get('href').split('/')) == 5)
def download_from_app_page(url):
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    url = soup.find('a', text='Download APK')
    if url is not None:
        r = requests.get(BASE_URL + url.get('href'))
        soup = BeautifulSoup(r.text, 'html.parser')
        link = soup.find('a', {
            'id': 'download_link'
        })
        fsize_tag = soup.find('span', {
            'class': 'fsize'
        })
        fsize = float(''.join([x for x in fsize_tag.text if x in FLOAT_SET]))
        if link and fsize < SIZE_LIMIT:
            r = requests.get(link.get('href'))
            app_name = url.get('href').split('/')
            if not os.path.isdir('data/' + app_name[1]):
                with open(app_name[1] + '.apk', 'wb+') as f:
                    f.write(r.content)
                return app_name[1]
            else:
                print('ignoring %s because exists' % app_name[1])
        else:
            if link:
                print('ignoring because size is %f' % fsize)
def download_and_process_apks(amount, download_probability=.5, size_limit=50, base_url='https://apkpure.com'):
    threads = []
    for x in get_all_sitemap_links(BASE_URL + '/sitemap.xml'):
        for link in download_gzip_link(x):
            if random.random() < DOWNLOAD_PROBABILITY:
                download = download_from_app_page(link)
                if download is not None:
                    print(download + " downloaded")
                    amount -= 1
                    thread = threading.Thread(target=os.system, args=('./process-app.sh %s' % download,))
                    threads.append(thread)
                    thread.start()
                if amount is 0:
                    for thread in threads:
                        thread.join()
                    print('done')
                    return

# download_and_process_apks(DOWNLOAD_AMOUNT)