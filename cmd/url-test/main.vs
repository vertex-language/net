package main

import "net/url"

var failures = 0

func check(_ ok: bool, _ what: string) {
    if ok {
        print("ok    \(what)")
    } else {
        print("FAIL  \(what)")
        failures += 1
    }
}

func parses(_ text: string, _ want: string) {
    do {
        let got = try url.Parse(text).String()
        check(got == want, "\(text) parses as \(want)" + (got == want ? "" : " (got \(got))"))
    } catch {
        check(false, "\(text) parses (threw \(error))")
    }
}

func resolves(_ ref: string, _ base: string, _ want: string) {
    do {
        let got = try url.Parse(base).Resolve(ref).String()
        check(got == want, "\(ref) against \(base) is \(want)" + (got == want ? "" : " (got \(got))"))
    } catch {
        check(false, "\(ref) against \(base) (threw \(error))")
    }
}

func testParse() {
    print("Parsing")
    do {
        let u = try url.Parse("HTTPS://User:Pw@GitHub.com:8443/a/b?q=1&r=%2F#frag")
        check(u.Scheme == "https" && u.Host == "github.com", "scheme and a special URL's host are lowercase")
        check(u.User == "User:Pw" && u.Port == "8443" && u.EffectivePort == 8443, "userinfo and port")
        check(u.Path == "/a/b" && u.Query == "q=1&r=%2F" && u.Fragment == "frag", "path, query and fragment, as written")
        check(u.RequestURI == "/a/b?q=1&r=%2F", "the request URI is path and query")
        check(u.Origin == "https://github.com:8443", "the origin keeps a port that isn't the default")
        check(u.QueryValues.Get("r") == "/", "query values are decoded")

        let bare = try url.Parse("https://github.com")
        check(bare.Path == "/" && bare.EffectivePort == 443 && bare.Origin == "https://github.com", "an http(s) URL's empty path is /, and its port is the default")

        let v6 = try url.Parse("http://[2001:DB8::1]:8080/x")
        check(v6.Host == "2001:db8::1" && v6.Port == "8080" && v6.HostPort == "[2001:db8::1]:8080", "an IPv6 host loses its brackets, and gets them back in HostPort")

        let rel = try url.Parse("../x.css?v=2")
        check(!rel.IsAbsolute && rel.Path == "../x.css" && rel.Query == "v=2", "a relative reference")

        let file = try url.Parse("file:///Users/me/site/index.html")
        check(file.HasAuthority && file.Host.isEmpty && file.Path == "/Users/me/site/index.html", "a file URL has an empty authority")

        let drive = try url.Parse("C:/Users/me")
        check(drive.Scheme.isEmpty && drive.Path == "C:/Users/me", "a drive letter is a path, not a scheme")

        let mail = try url.Parse("mailto:Someone@Example.com")
        check(mail.Scheme == "mailto" && mail.Path == "Someone@Example.com" && !mail.HasAuthority, "a URL without an authority keeps its path as written")
    } catch {
        check(false, "parsing threw \(error)")
    }
    parses("  https://github.com/\tlogin\n ", "https://github.com/login")
    parses("https://github.com\\login\\x?a\\b", "https://github.com/login/x?a\\b")
    parses("https://a/b/../c/./d", "https://a/c/d")
    parses("http://example.com:80/", "http://example.com:80/")
    parses("data:text/plain,hi", "data:text/plain,hi")
    parses("?", "?")
    parses("#top", "#top")

    let bad: [(string, string)] = [("http://x:99999/", "a port over 65535"), ("http://x:8a/", "a port with letters"),
                                   ("http://[::1/", "an unclosed ["), ("https:///path", "an https URL with no host"),
                                   ("http://a b/", "a space in the host")]
    for (text, what) in bad {
        do {
            _ = try url.Parse(text)
            check(false, "\(what) is refused")
        } catch {
            check(true, "\(what) is refused")
        }
    }
}

func testResolve() {
    print("RFC 3986 section 5.4")
    let base = "http://a/b/c/d;p?q"
    let cases: [(string, string)] = [
        ("g:h", "g:h"), ("g", "http://a/b/c/g"), ("./g", "http://a/b/c/g"), ("g/", "http://a/b/c/g/"),
        ("/g", "http://a/g"), ("//g", "http://g/"), ("?y", "http://a/b/c/d;p?y"), ("g?y", "http://a/b/c/g?y"),
        ("#s", "http://a/b/c/d;p?q#s"), ("g#s", "http://a/b/c/g#s"), ("g?y#s", "http://a/b/c/g?y#s"),
        (";x", "http://a/b/c/;x"), ("g;x", "http://a/b/c/g;x"), ("", "http://a/b/c/d;p?q"),
        (".", "http://a/b/c/"), ("./", "http://a/b/c/"), ("..", "http://a/b/"), ("../", "http://a/b/"),
        ("../g", "http://a/b/g"), ("../..", "http://a/"), ("../../", "http://a/"), ("../../g", "http://a/g"),
        ("../../../g", "http://a/g"), ("../../../../g", "http://a/g"), ("/./g", "http://a/g"),
        ("/../g", "http://a/g"), ("g.", "http://a/b/c/g."), (".g", "http://a/b/c/.g"), ("g..", "http://a/b/c/g.."),
        ("..g", "http://a/b/c/..g"), ("./../g", "http://a/b/g"), ("./g/.", "http://a/b/c/g/"),
        ("g/./h", "http://a/b/c/g/h"), ("g/../h", "http://a/b/c/h"), ("g;x=1/./y", "http://a/b/c/g;x=1/y"),
        ("g;x=1/../y", "http://a/b/c/y"),
    ]
    for (ref, want) in cases { resolves(ref, base, want) }

    print("Sites and files")
    resolves("/login", "https://github.com/", "https://github.com/login")
    resolves("//github.githubassets.com/a.css", "https://github.com/", "https://github.githubassets.com/a.css")
    resolves("images/x.png", "https://www.google.com/webhp?hl=en", "https://www.google.com/images/x.png")
    resolves("https://other.org", "https://github.com/x", "https://other.org/")
    resolves("page2.html", "testdata/pages/", "testdata/pages/page2.html")
    resolves("../style.css", "testdata/pages/", "testdata/style.css")
    resolves("../../x.css", "pages/", "../x.css")
    resolves("x.png", "file:///Users/me/site/index.html", "file:///Users/me/site/x.png")
    resolves("x.png", "/Users/me/site/", "/Users/me/site/x.png")
}

func testEscaping() {
    print("Escaping and queries")
    check(url.PathEscape("a b/c?d") == "a%20b%2Fc%3Fd", "PathEscape escapes spaces, / and ?")
    check(url.QueryEscape("two words&x=é") == "two+words%26x%3D%C3%A9", "QueryEscape: + for spaces, UTF-8 as bytes")
    check(url.PathUnescape("a%20b%2fc%zz") == "a b/c%zz", "PathUnescape keeps a % without hex digits")
    check(url.QueryUnescape("two+words%26") == "two words&", "QueryUnescape reads + as a space")
    var v = url.ParseQuery("a=1&b=two+words&a=3&&flag")
    check(v.All("a") == ["1", "3"] && v.Get("b") == "two words" && v.Get("flag") == "", "ParseQuery: repeated keys, a key alone, empty pairs skipped")
    v.Set("a", "x y")
    v.Delete("flag")
    check(v.Encode() == "b=two+words&a=x+y", "Set replaces, Delete removes, Encode keeps order")
}

func main() -> int32 {
    testParse()
    testResolve()
    testEscaping()
    if failures == 0 {
        print("ALL URL CHECKS PASSED")
        return 0
    }
    print("\(failures) FAILED")
    return 1
}
