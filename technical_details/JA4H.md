# JA4H: HTTP Client Fingerprint

![JA4H](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.png)

JA4H fingerprints the HTTP Client. Each client will have multiple fingerprints depending on what it’s doing. Clients will have different fingerprints when doing different HTTP Methods as well as different HTTP versions and will sometimes need to add fields depending on what the server tells it. However, the fingerprint will generally be the same per client per HTTP method and version save for cookie details. 

Each session is likely to have multiple JA4H’s, so each will be logged.

(2 character http method)  
(2 character http version)  
(“c” if cookie exists, “n” if no cookie or new connection)  
(“r” if referer exists, “n” if no referer or new connection)  
(2 character number of headers)  
(4 character first accept-language code)  
_  
(12 character truncated sha256 hash of the http header fields, in the order they are seen)  
_  
(12 character truncated sha256 hash of the cookie fields, sorted)  
_  
(12 character truncated sha256 hash of the cookie fields+values, sorted)  
```
Example JA4H: ge20cr13enus_a82fbf14bc42_457935509480_e97928733c74
```
2 Character HTTP Method:  
These are the HTTP methods available and their 2 character code to start the fingerprint:  
```
ge = GET  
he = HEAD  
op = OPTIONS  
tr = TRACE  
de = DELETE  
pu = PUT  
po = POST  
pa = PATCH  
co = CONNECT
```

2 Character HTTP Version:  
HTTP versions:  
```
10 = HTTP/1.0  
11 = HTTP/1.1  
20 = HTTP/2  
30 = HTTP/3  
```
If there is a Cookie in the HTTP header, the value is “c” for cookie.  
If there is not a Cookie in the HTTP header, the value is “n” for “n”o cookie or “n”ew connection

If there is a Referer in the HTTP header, the value is “r” for referer.  
If there is not a Referer in the HTTP header, the value is “n” for “n”o referer or “n”ew connection

2 character number of header fields. See below on capturing header fields. This ignores the cookie and referer header as that is captured above.  
06 = 6 headers  
99 = anything > than 100 headers

First 4 characters of the primary Accept-Language (ignore “-”):  
See https://www.iana.org/assignments/language-subtag-registry/language-subtag-registry  
This field can look like:  
```
Accept-Language: da, en-GB;q=0.8, en;q=0.7  
Accept-Language: en-US,en;q=0.9
```
The first value prior to the comma is the primary language of the client. JA4H captures this while ignoring the “-” character. Use 0s if less than 4 characters are used or if no accept-language field exists.

Example:  
```
da = da00  
en-US = enus  
en-UK = enuk  
ru-RU = ruru  
None = 0000
```

“_”

12 character truncated sha256 hash of the http headers:  
The http headers come after the http version code and start on new lines ending at a “:” JA4H captures all HTTP header fields, case-sensitive, except for “Cookie” and “Referer” as those are captured above. JA4H does not capture the values. The fields are then concatenated with a “,” delimiter and sha256 hashed using the first 12 characters of the hash. JA4H is not capturing “Cookie” here because it is already captured in the fingerprint above.

So for:   
```
POST /plugins/unassigned.devices/UnassignedDevices.php HTTP/1.1
Host: 192.168.1.1
Content-Length: 664
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.110 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.1.1
Referer: http://192.168.1.1/Main
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: example=d7df2dd0937ec27; ud_reload=UD_reload
Connection: close
```
The headers captured are:
```
Host,Content-Length,Accept,X-Requested-With,User-Agent,Content-Type,Origin,Accept-Encoding,Accept-Language,Connection
```
(notice “Cookie” and “Referer” is omitted)
Sha256 hash:
```
47d05ed57293244a9b505865f749705e4e7fcbfee3780254b075f46433e51251
```
Truncated hash:
```
47d05ed57293
```

“_”

12 character truncated sha256 hash of the cookie fields, sorted:  
The cookie fields are the values before “=” and are delimited by “;”. JA4H captures these fields and concatenates them using a “,” delimiter and then performs a truncated sha256 hash of the string.

Example Cookie:
```
Cookie: 1P_JAR=2023-06-07-17; AEC=AUEFqZdaLLwaXJHyxA8-Cu0i0N4klp_vV3XOuyEYeiWlp4QaeIvSv6t4XKM; OGPC=19027681-1:; NID=511=rRELE2o91XNLo6eayqEN7Lf2ue7EcSHVkew3oxf4jzyF8vix2BzxTRvda8MYBFEkLyC1xjTcqSIjbC-wV2r120jr2HFau_dHvMxUm9fk6W2J2mddtlMpGMA8qGuAZWt1DSpCFFwHZSKBryGnvRJUeXkc-jw4sXdWhgCKxeu3f01Na4YsBYGf; DV=A84BtBIPqhgmIDlq9acmfs7ik-duiZjdmUPDG3eW3QIAAAA
```
Fields captured:
```
1P_JAR,AEC,OGPC,NID,DV
```
Sorted in alphabetical order:
```
1P_JAR,AEC,DV,NID,OGPC = 21864220ae3d
```

12 character truncated sha256 hash of the cookie fields+values, sorted:  
The cookie fields+values are now captured and sorted like above, using a “,” delimiter and then performing a truncated hash. This part of the fingerprint will be unique to each user but can allow for tracking of individual users through the application without the need to log SPII like username or session tokens.

Using the example above, we sort the cookie to:  
```
1P_JAR=2023-06-07-17,AEC=AUEFqZdaLLwaXJHyxA8-Cu0i0N4klp_vV3XOuyEYeiWlp4QaeIvSv6t4XKM,DV=A84BtBIPqhgmIDlq9acmfs7ik-duiZjdmUPDG3eW3QIAAAA,NID=511=rRELE2o91XNLo6eayqEN7Lf2ue7EcSHVkew3oxf4jzyF8vix2BzxTRvda8MYBFEkLyC1xjTcqSIjbC-wV2r120jr2HFau_dHvMxUm9fk6W2J2mddtlMpGMA8qGuAZWt1DSpCFFwHZSKBryGnvRJUeXkc-jw4sXdWhgCKxeu3f01Na4YsBYGf,OGPC=19027681-1:

Sha256: e97928733c7408285e0878640b946867e0a8fd0ac02765ad48a375220296a5e3
Truncated: e97928733c74
```

## JA4H Example:

So for:
```
GET /public/api/alerts HTTP/2
Host: www.cnn.com
Cookie: FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929; sato=1; countryCode=US; stateCode=VA; geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511; usprivacy=1---; umto=1; _dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726
Sec-Ch-Ua: 
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.110 Safari/537.36
Sec-Ch-Ua-Platform: ""
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://www.cnn.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
```
Headers:
```
Host,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,User-Agent,Sec-Ch-Ua-Platform,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-Dest,Accept-Encoding,Accept-Language
```
Cookie:
```
Unsorted: FastAB,sato,countryCode,stateCode,geoData,usprivacy,umto,_dd_s
Sorted: FastAB,_dd_s,countryCode,geoData,sato,stateCode,umto,usprivacy
```
ge (HTTP Method)
20 (HTTP Version)
c (There’s a cookie)
r (There’s a referer)
11 (13 header fields minus Cookie and Referer as those are accounted for above)
enus (Accept-Language)
_
974ebe531c03 (hash of http header fields)
_
b66fa821d02c (hash of sorted cookie fields)
_
e97928733c74 (hash of the sorted cookie fields+values)
```
JA4H=ge20cr13enus_974ebe531c03_b66fa821d02c_e97928733c74
```

## Raw Output
The program should allow for raw outputs either sorted or unsorted.  
-r (raw fingerprint) -o (original ordering)

The raw fingerprint for JA4H would look like this:
```
JA4H_r = ge20cr13enus_Host,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,User-Agent,Sec-Ch-Ua-Platform,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-Dest,Accept-Encoding,Accept-Language_FastAB,_dd_s,countryCode,geoData,sato,stateCode,umto,usprivacy_FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929,_dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726,countryCode=US,geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511,sato=1,stateCode=VA,umto=1,usprivacy=1---
```
The raw fingerprint with the original ordering (-o) would look like this:
```
JA4H_ro = ge20cr13enus_Host,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,User-Agent,Sec-Ch-Ua-Platform,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-Dest,Accept-Encoding,Accept-Language_FastAB,sato,countryCode,stateCode,geoData,usprivacy,umto,_dd_s_FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929,sato=1,countryCode=US,stateCode=VA,geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511,usprivacy=1—,umto=1,_dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726
```
