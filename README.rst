#########
apocrypha
#########

   works, usually written, of unknown authorship or of doubtful origin

Usage
=====

``example_client.py`` is the current reference implementation of the "native"
client protocol. It takes local filesystem paths as arguments, and uploads each
to ptpb.io (a public deployment of apocrypha).

.. code::

   $ sha256sum test.png test.webm
   d2f1543b82d8219b0c2086224339bf503211a221a2ec55a9a39f23bf8a1e2481  test.png
   ba0f0e2ba50ccea0a80f114d0e0a40595cb2922bdf01f00ce7134405b23a2302  test.webm
   $ python test/example_client.py test.png test.webm
   test.png https://ptpb.io:667/d2f1
   test.webm https://ptpb.io:667/ba0f

Verify that apocrypha is able to regurgitate these:

.. code::

   $ curl -s -D/dev/stderr https://ptpb.io:667/d2f1.png | sha256sum
   HTTP/1.1 200
   transfer-encoding: chunked
   content-type: image/png

   d2f1543b82d8219b0c2086224339bf503211a221a2ec55a9a39f23bf8a1e2481  -
   $ curl -s -D/dev/stderr https://ptpb.io:667/ba0f.webm | sha256sum
   HTTP/1.1 200
   transfer-encoding: chunked
   content-type: video/webm

   ba0f0e2ba50ccea0a80f114d0e0a40595cb2922bdf01f00ce7134405b23a2302  -

The ``content-type`` feature makes apocrypha suitable for presenting common
media types (plaintext, html, video, etc..) in web browsers.

Prefix length
=============

apocrypha has a concept of a "prefix_length", specified by the client. An
uploaded file is addressable by **both** the full 64 character sha256 hex digest
and a prefix of that hex digest of length exactly equal to the "prefix_length"
specified at upload time.
