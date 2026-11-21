# Use a conservative email extraction pattern

The email parser extracts candidate addresses from unstructured provider text. Its local-part pattern excludes delimiters such as asterisks and parentheses to reduce false positives in marked-up text. Broader character support would require evidence that it improves extraction without increasing false positives.
