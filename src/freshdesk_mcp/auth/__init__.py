"""OAuth support for running the Freshdesk MCP server on a public HTTPS URL.

Each user authorises their own MCP client (e.g. Claude) by entering their personal
Freshdesk API key on a consent page. The key is stored encrypted on disk and can only
be decrypted with the OAuth tokens issued for that grant, or with the API key itself.
"""
