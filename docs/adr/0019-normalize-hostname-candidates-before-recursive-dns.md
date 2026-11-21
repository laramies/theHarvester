# Normalize hostname candidates before recursive DNS

Normalize and scope-check each constructed hostname before it enters recursive DNS validation. The wordlist reader accepts tokens that can still form invalid hostnames, including underscore-prefixed labels. Filtering on the final hostname keeps those tokens out of the candidate set and leaves the validation budget for usable names.
