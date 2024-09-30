# JA4H: HTTP Client Fingerprint

![JA4H](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.png)

JA4H fingerprints the HTTP client based on each HTTP request.

### Number of Headers:
2 digit number of headers, not counting Cookie and Referer. For 3 headers the value is "03".
If there are more than 99, the output is 99.
