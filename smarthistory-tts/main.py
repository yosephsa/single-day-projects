from pyquery import PyQuery
import requests
from gtts import gTTS
import os

################
## Text Fetcher
################

def getHtml(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
    response = requests.get(url, headers=headers) 
    html = response.content.decode()
    return html

def parseText(html):
    pq = PyQuery(html)
    tag = pq('.entry-content')
    return tag.text()


def getAudioAndSave(text, urlName):
    # define variables
    s = text
    file = urlName + ".mp3"

    # initialize tts, create mp3 and play
    tts = gTTS(s, 'com')
    tts.save(file)
    os.system("mpg123 " + file)


##################
## Init Stuff
################

def init():
    url = input("Enter Smarthostory.com Article Link: ")
    #url = "https://smarthistory.org/common-questions-about-dates/"
    urlName = url.split('/')[-2]
    html = getHtml(url)
    text = parseText(html)
    getAudioAndSave(text, urlName)

init()