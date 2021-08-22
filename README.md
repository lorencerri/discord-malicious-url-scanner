# discord-malicious-url-scanner

Scans Discord messages for links and parses them through VirusTotal to check if they're malicious.

This is only a proof of concept and will eventually be added to [discord-guardian](https://github.com/lorencerri/discord-guardian).

> <b>Note:</b> VirusTotal's API ratelimits are very low (4 URLs/minute & 500 URLs/day). Keep this in mind when running on high-traffic servers. Alternatively, you could use a higher limit API such as [Google's Web Risk API](https://cloud.google.com/web-risk), although the results would most likely be much less accurate.
