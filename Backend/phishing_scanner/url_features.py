#url_features.py
def extract_features(url):
    features = {
        "url_length": len(url),
        "n_dots": url.count("."),
        "n_hypens": url.count("-"),
        "n_underline": url.count("_"),
        "n_slash": url.count("/"),
        "n_questionmark": url.count("?"),
        "n_equal": url.count("="),
        "n_at": url.count("@"),
        "n_and": url.count("&"),
        "n_exclamation": url.count("!"),
        "n_space": url.count(" "),
        "n_tilde": url.count("~"),
        "n_comma": url.count(","),
        "n_plus": url.count("+"),
        "n_asterisk": url.count("*"),
        "n_hastag": url.count("#"),
        "n_dollar": url.count("$"),
        "n_percent": url.count("%"),
        "n_redirection": url.count(">>") + url.count("%3E%3E")
    }
    return list(features.values())
