# Github Security Advisory Parser
This is a very simple go project that parses the Github security advisory database.

It isn't anything earthshaking. It was a good exercise for beginning Go programming with a real purpose in mind.

# Getting the database to parse
Clone [the database](https://github.com/github/advisory-database) and look into the `advisories` subdirectory.

# Running the code
Once you compile `scanner`, you just need to run it on some sub-tree of the advisories:
```
./scanner -in advisories/github-reviewed/ -out foo.csv
```
This extracts a few fields and produces data that looks like this:
```
Id,Aliases,Summary,Ecosystem,Name
GHSA-229r-pqp6-8w6g,"[CVE-2013-6421]","sprout Code Injection vulnerability","RubyGems","sprout"
GHSA-24fg-p96v-hxh8,"[CVE-2011-0447]","actionpack Cross-Site Request Forgery vulnerability","RubyGems","actionpack"
GHSA-29gr-w57f-rpfw,"[CVE-2014-7818]","actionpack vulnerable to Path Traversal","RubyGems","actionpack"
GHSA-2fqv-h3r5-m4vf,"[CVE-2017-1000006]","Cross Site Scripting (XSS) in plotly.js","npm","plotly.js"
GHSA-2xjj-5x6h-8vmf,"[CVE-2012-1099]","Cross-site Scripting in actionpack","RubyGems","actionpack"
GHSA-333x-9vgq-v2j4,"[CVE-2015-5688]","Directory Traversal in geddy","npm","geddy"
GHSA-33pp-3763-mrfp,"[CVE-2014-7819]","sprockets vulnerable to Path Traversal","RubyGems","sprockets"
```
Unfortunately, this isn't quite parseable by `duckdb` because of the use of C-style backslashes for escaping characters like tabs and quotes. If you tell duckdb to handle the quoted quotes, then it is surprised by the other uses of `\`.
