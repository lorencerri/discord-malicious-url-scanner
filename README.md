> **Note:** This is only a proof of concept, no optimizations to the code have been made, this is only to show how the feature might look as an end product.

# discord-malicious-url-scanner

Scans Discord messages for links and parses them through VirusTotal to check if they're malicious.

> <b>Note:</b> VirusTotal's API ratelimits are very low (4 URLs/minute & 500 URLs/day). Keep this in mind when running on high-traffic servers. Alternatively, you could use a higher limit API such as [Google's Web Risk API](https://cloud.google.com/web-risk), although the results would most likely be much less accurate.

**Preview** <br>
![Preview](https://i.imgur.com/BW8iBNJ.png)

