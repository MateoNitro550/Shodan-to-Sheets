# Shodan to Google Sheets

This project was created for my Internet and Web Technologies final project. It lets users search Shodan or look up an IP address, then save formatted results to a Google Sheet.

## Project walkthrough

The project walkthrough is available [in this video](https://youtu.be/peJIvAJI2Ek).

## How it works

- A web form accepts a Shodan search query or IP address and an optional Google Spreadsheet ID.
- The server uses Shodan's Search API for queries and its Host API for IP lookups, then normalizes the results into spreadsheet rows. Search results are limited to the first 10 matches.
- Google OAuth authorizes access to Google Sheets. The app creates a new spreadsheet when no ID is provided, or appends rows to the specified spreadsheet.
- A random OAuth state value connects the Google callback to the original search request.
- The spreadsheet includes normalized Shodan fields and summaries for services such as FTP, HTTP, SMB, SSH, and reported vulnerabilities.

## API credentials

Set `SHODAN_API_KEY`, `GOOGLE_CLIENT_ID`, and `GOOGLE_CLIENT_SECRET` as environment variables, or enter the values in `auth/credentials.json` for local use.