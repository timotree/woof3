# woof3
Python 3.8+ port of WOOF (Web Offer One File) by Simon Budig

I found the WOOF utility and loved the utility of it, but it appears to have
been abandoned in 2012. I'm still a relatively new Python developer, so this was
a fun, quick project to learn about porting Python 2 code to 3. I would also
love to use this project to learn more about testing. Any tips would be greatly
appreciated!

I started with Ubuntu 18.04's WOOF package, ran it through Pylint and YAPF with
the Facebook style, which made a ton of formatting changes. The version in
Ubuntu's packages was updated to use ThreadedHTTPServer, which isn't in the
latest version available (2012-05-31) on Simon Budig's WOOF webpage.

Not everything has been tested in Python 3 yet. I've successully retrieved
and uploaded a single file.
