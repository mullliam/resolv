# resolv

resolv is a command-line hostname and IP investigation tool.

For a hostname, it resolves any CNAME chain, gathers A records, performs PTR lookups for each IP, runs WHOIS against each IP, and prints grouped output in a readable ASCII table.

For a direct IP input, it performs PTR and WHOIS lookups only.

The script is designed to quickly identify infrastructure ownership and network metadata behind a hostname, including common registry-specific WHOIS fields.

## What The Script Does

For a supplied hostname, resolv:

1. Follows the full CNAME chain (if present)
2. Retrieves all A records from the final hostname
3. Looks up PTR records for each returned IP
4. Runs WHOIS for each IP and extracts common ownership/network fields
5. Groups IPs by complete WHOIS identity
6. Shows only WHOIS columns that contain at least one non-empty value

For a supplied IP address, resolv:

1. Performs a PTR lookup for the IP
2. Runs WHOIS for the IP
3. Shows only WHOIS columns that contain at least one non-empty value

## WHOIS Fields Parsed

The parser is adaptive and supports commonly used keys across ARIN, RIPE, APNIC, LACNIC, and AFRINIC output styles.

Fields currently collected:

- OrgName
- Organization
- owner
- org-name
- org
- descr
- netname
- route
- origin
- OriginAS
- CIDR
- country

## Requirements

- Python 3
- dig command available in PATH
- whois command available in PATH

On macOS, if needed:

	brew install bind whois

## Usage

From the repo directory:

	./resolv.py example.com
	./resolv.py 8.8.8.8

Or with Python explicitly:

	python3 resolv.py example.com
	python3 resolv.py 8.8.8.8

## Quick Start (Copy/Paste)

Use this block to clone/update the repo in `~/tools`, add a `resolv` alias in `~/.zshrc`, and load it immediately:

	mkdir -p ~/tools
	git clone https://github.com/mullliam/resolv.git ~/tools/resolv 2>/dev/null || git -C ~/tools/resolv pull --ff-only
	touch ~/.zshrc
	grep -q "^alias resolv=" ~/.zshrc || echo "alias resolv='python3 \$HOME/tools/resolv/resolv.py'" >> ~/.zshrc
	source ~/.zshrc

## Add A Global resolv Alias (macOS zsh)

If you want to run resolv from any directory using the command resolv, add an alias to your shell config.

1. Make the script executable:

	chmod +x /Users/liam.mulligan/github/resolv/resolv.py

2. Add this line to ~/.zshrc:

	alias resolv='/Users/liam.mulligan/github/resolv/resolv.py'

3. Reload your shell config:

	source ~/.zshrc

4. Run from anywhere:

	resolv example.com
	resolv 8.8.8.8

## Alternative: Create A Symlink (Optional)

If you prefer not to use an alias, place a symlink in a directory already in PATH (for example, /usr/local/bin):

	ln -sf /Users/liam.mulligan/github/resolv/resolv.py /usr/local/bin/resolv

Then use:

	resolv example.com
	resolv 8.8.8.8
