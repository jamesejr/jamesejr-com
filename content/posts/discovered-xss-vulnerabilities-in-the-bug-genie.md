+++
title = 'Discovered XSS vulnerabilities in The Bug Genie'
author = ['James Espinosa']
description = 'Vulnerability research into multiple XSS issues in The Bug Genie.'
date = 2013-05-14T21:00:00-08:00
draft = false
tags = ['Vulnerability Research']
+++

Earlier this year, I discovered multiple cross-site scripting (XSS) vulnerabilities in [The Bug Genie](http://thebuggenie.com), an open source issue tracking and project management application.

## The Vulnerabilities

For reference, the vulnerabilities were assigned [CVE-2013-1760](http://xforce.iss.net/xforce/xfdb/89360). Proper and timely disclosure practices were coordinated through the Trustwave SpiderLabs' security advisory team.

The Bug Genie version 3.2.4 and earlier, suffer from multiple persistent, and reflected XSS vulnerabilities in different areas of the application. I will not dive into details for each finding, as they are mentioned in the references below.

One of the unfixed issues was related to not properly sanitizing output that was rendered during error messages:

### Examples:

```
Could not validate against the OpenID provider: $message
Could not connect to $url
```

Modifying the `openid_identifier` parameter's value to arbitrary JavaScript caused the application to throw the error exception:

```
Could not connect to http://<script>prompt(1)</script>
```

Resulting in reflected cross-site scripting. The remaining findings included:

- Wiki `description` parameter XSS
- Issues `description` parameter XSS
- Issues `uploader_file` parameter persistent XSS
- Dashboard `HTTP Referer Header` reflected XSS
- Account `HTTP Referer Header` reflected XSS
- Login `openid_identifier` parameter XSS
- File Attachments persistent XSS

## The Patches

After disclosing the security issues to The Bug Genie team, version 3.2.5 of the application was released to address them. Unfortunately, I found out that not all of the findings were properly addressed. As a result, I hunted down the remaining two unfixed issues, and submitted a pull request to merge my fixes to their codebase.

The following are the two patches that I submitted to address the `openid_identifier` and `timeline` XSS vulnerabilities:

**Filename:** core/classes/LightOpenID.classes.php

```diff
<pre><code>protected function request_streams($url, $method='GET', $params=array())
{
	if(!$this->hostExists($url)) {
-    	throw new ErrorException("Could not connect to $url.", 404);
+		throw new ErrorException("Could not connect to ".htmlentities($url), 404);
}
</code></pre>
```

**Filename:** modules/main/templates/_logitem.inc.php

```diff
<pre><code>if (isset($include_details) && include_details)
{
-	echo < div class="timeline_inline_details">'.n12br($issue->getDescription()).'< /div>';
+   echo < div class="timeline_inline_details">'.n12br(htmlentities($issue->getDescription())).'< /div>';
}
</code></pre>
```

## Additional References

- [Security Notice: TBGSN-002-1](http://www.thebuggenie.com/security/TBGSN-002-1)
- [Security Notice: TBGSN-002-2](http://www.thebuggenie.com/security/TBGSN-002-2)
- [Open Sourced Vulnerability Database (OSVDB)](http://osvdb.org/creditees/11651-james-espinosa)
- [Trustwave SpiderLabs Security Advisory: TWSL2013-002](http://blog.spiderlabs.com/2013/05/twsl2013-002-multiple-xss-vulnerabilities-in-the-bug-genie.html)
